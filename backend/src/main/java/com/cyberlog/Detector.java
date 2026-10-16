package com.cyberlog;

import com.cyberlog.LogParser.Event;
import java.util.*;
import java.util.regex.Pattern;

/** Rule-based detection, feature extraction and the transparent "Calculated Risk Score". */
public class Detector {
    public record Threat(String ip, String type, long ts, double confidence, String reason, int count, int threshold) {}
    public record Risk(int score, String severity, Map<String, Integer> factors) {}

    private static final Pattern RESTRICTED = Pattern.compile("(?i)/(admin|private|etc/passwd|\\.env|wp-admin|phpmyadmin|\\.git)");
    private final int bfMax, bfWin, scanMin, scanWin;

    public Detector(int bfMax, int bfWin, int scanMin, int scanWin) {
        this.bfMax = bfMax; this.bfWin = bfWin; this.scanMin = scanMin; this.scanWin = scanWin;
    }

    public Map<String, List<Event>> group(List<Event> events) {
        Map<String, List<Event>> g = new TreeMap<>();
        for (Event e : events) g.computeIfAbsent(e.ip(), k -> new ArrayList<>()).add(e);
        g.values().forEach(l -> l.sort(Comparator.comparingLong(Event::ts)));
        return g;
    }

    /** Numeric features per IP (these are also the inputs of the Isolation Forest). */
    public Map<String, Object> features(List<Event> l) {
        int n = l.size(), fails = 0, ok = 0, errors = 0;
        Set<Integer> ports = new HashSet<>(); Set<String> urls = new HashSet<>();
        for (Event e : l) {
            if ("FAIL".equals(e.result())) fails++;
            if ("SUCCESS".equals(e.result())) ok++;
            if (e.status() >= 400) errors++;
            if (e.port() > 0) ports.add(e.port());
            if (!e.url().isEmpty()) urls.add(e.url());
        }
        double minutes = Math.max(1.0, (l.get(n - 1).ts() - l.get(0).ts()) / 60.0);
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("requests", n); f.put("failed_logins", fails); f.put("successful_logins", ok);
        f.put("unique_ports", ports.size()); f.put("unique_urls", urls.size());
        f.put("requests_per_minute", Math.round(n / minutes * 100) / 100.0);
        f.put("error_rate", Math.round(100.0 * errors / n) / 100.0);
        f.put("fail_rate", fails + ok == 0 ? 0.0 : Math.round(100.0 * fails / (fails + ok)) / 100.0);
        return f;
    }

    public List<Threat> detect(Map<String, List<Event>> groups) {
        List<Threat> out = new ArrayList<>();
        // average requests per IP per minute (baseline for the spike rule)
        long buckets = 0, total = 0;
        Map<String, Map<Long, Integer>> perMin = new HashMap<>();
        for (var en : groups.entrySet()) {
            Map<Long, Integer> m = new HashMap<>();
            for (Event e : en.getValue()) m.merge(e.ts() / 60, 1, Integer::sum);
            perMin.put(en.getKey(), m); buckets += m.size(); total += en.getValue().size();
        }
        double avg = buckets == 0 ? 1 : (double) total / buckets;
        int spikeThr = (int) Math.max(30, Math.ceil(5 * avg));

        for (var en : groups.entrySet()) {
            String ip = en.getKey(); List<Event> l = en.getValue();
            List<Long> failTs = new ArrayList<>(), portTs = new ArrayList<>(); List<String> ports = new ArrayList<>();
            int restricted = 0, restrictedErr = 0; long firstRestricted = -1;
            for (Event e : l) {
                if ("FAIL".equals(e.result())) failTs.add(e.ts());
                if (e.port() > 0) { portTs.add(e.ts()); ports.add(String.valueOf(e.port())); }
                if (RESTRICTED.matcher(e.url()).find()) {
                    restricted++; if (firstRestricted < 0) firstRestricted = e.ts();
                    if (e.status() == 401 || e.status() == 403 || e.status() == 404) restrictedErr++;
                }
            }
            // 1) Brute force: >= bfMax failed logins inside bfWin seconds
            long[] bf = densest(failTs, null, bfWin);
            if (bf[0] >= bfMax) out.add(new Threat(ip, "Brute Force", bf[1], conf(bf[0], bfMax),
                String.format("This IP generated %d failed login attempts within %d seconds (threshold: %d in %d seconds). Repeated authentication failures indicate suspicious login behavior and may represent a brute-force attempt.", bf[0], bfWin, bfMax, bfWin),
                (int) bf[0], bfMax));
            // 2) Port scan: >= scanMin distinct ports inside scanWin seconds
            long[] sc = densest(portTs, ports, scanWin);
            if (sc[0] >= scanMin) out.add(new Threat(ip, "Port Scan", sc[1], conf(sc[0], scanMin),
                String.format("This IP connected to %d different ports within %d seconds (threshold: %d). Touching many ports quickly is a common sign of port scanning (reconnaissance).", sc[0], scanWin, scanMin),
                (int) sc[0], scanMin));
            // 3) Request spike: one minute far above the average per-IP-per-minute rate
            var peak = Collections.max(perMin.get(ip).entrySet(), Map.Entry.comparingByValue());
            if (peak.getValue() >= spikeThr) out.add(new Threat(ip, "Request Spike", peak.getKey() * 60, conf(peak.getValue(), spikeThr),
                String.format("This IP sent %d requests in a single minute, while the average in this log is %.1f requests per IP per minute (alert threshold: %d). Sudden bursts may indicate automated abuse or a denial-of-service attempt.", peak.getValue(), avg, spikeThr),
                peak.getValue(), spikeThr));
            // 4) Unauthorized access: repeated hits on restricted paths
            if (restricted >= 5) out.add(new Threat(ip, "Unauthorized Access", firstRestricted, conf(restricted, 5),
                String.format("This IP made %d requests to restricted paths such as /admin, /private or /etc/passwd (%d were answered with 401/403/404). Repeated attempts may indicate probing for unauthorized access.", restricted, restrictedErr),
                restricted, 5));
            // 5) Suspicious login: success right after many failures (10 minute look-back)
            for (Event e : l) {
                if (!"SUCCESS".equals(e.result())) continue;
                long recent = failTs.stream().filter(t -> t <= e.ts() && t >= e.ts() - 600).count();
                if (recent >= bfMax) {
                    out.add(new Threat(ip, "Suspicious Login", e.ts(), conf(recent, bfMax),
                        String.format("This IP had %d failed logins in the 10 minutes before a successful login (user '%s'). A success after many failures can mean guessed or stolen credentials; verify this account.", recent, e.username()),
                        (int) recent, bfMax));
                    break;
                }
            }
        }
        out.sort(Comparator.comparingLong(Threat::ts));
        return out;
    }

    /** Sliding window: returns {best count (or distinct keys), window start time}. */
    static long[] densest(List<Long> ts, List<String> keys, int win) {
        long best = 0, start = ts.isEmpty() ? 0 : ts.get(0);
        Map<String, Integer> cnt = new HashMap<>();
        int l = 0;
        for (int r = 0; r < ts.size(); r++) {
            cnt.merge(keys == null ? "#" + r : keys.get(r), 1, Integer::sum);
            while (ts.get(r) - ts.get(l) > win) {
                String k = keys == null ? "#" + l : keys.get(l);
                if (cnt.merge(k, -1, Integer::sum) == 0) cnt.remove(k);
                l++;
            }
            if (cnt.size() > best) { best = cnt.size(); start = ts.get(l); }
        }
        return new long[]{best, start};
    }

    private static double conf(long v, int thr) { return Math.round(Math.min(0.99, 0.6 + 0.39 * Math.min(1.0, v / (3.0 * thr))) * 100) / 100.0; }

    /** Calculated Risk Score = rule base + frequency (how far above threshold) + AI anomaly bonus. Not scientifically validated. */
    public static Risk risk(String type, int count, int thr, boolean anomaly, double aiScore) {
        int base = switch (type) {
            case "Brute Force" -> 40; case "Port Scan" -> 35; case "Request Spike" -> 25;
            case "Unauthorized Access" -> 30; case "Suspicious Login" -> 55; default -> 25; };
        double over = Math.min(1.0, Math.max(0.0, count / (double) Math.max(1, thr) - 1) / 2);
        int freq = (int) Math.round(25 * over);
        int ai = anomaly ? (int) Math.round(20 * aiScore) : 0;
        int score = Math.min(100, base + freq + ai);
        String sev = score <= 25 ? "LOW" : score <= 50 ? "MEDIUM" : score <= 75 ? "HIGH" : "CRITICAL";
        Map<String, Integer> f = new LinkedHashMap<>();
        f.put("rule_base", base); f.put("frequency", freq); f.put("ai_anomaly", ai);
        return new Risk(score, sev, f);
    }
}
