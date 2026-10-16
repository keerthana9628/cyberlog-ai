package com.cyberlog;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.*;

/** Turns raw log text into normalized Events. Logs are treated strictly as DATA (never executed). */
public class LogParser {
    public record Event(long ts, String ip, String username, String method, String url,
                        int status, int port, String result, String raw) {}
    public record Parsed(List<Event> events, String format, int skipped) {}

    private static final Pattern APACHE = Pattern.compile("^(\\S+) \\S+ (\\S+) \\[([^\\]]+)\\] \"(\\S+) (\\S+)[^\"]*\" (\\d{3})");
    private static final Pattern SSH = Pattern.compile("^([A-Z][a-z]{2}\\s+\\d+ \\d\\d:\\d\\d:\\d\\d) \\S+ sshd\\[\\d+\\]: (Failed|Accepted) \\w+ for (?:invalid user )?(\\S+) from (\\S+)");
    private static final Pattern FIREWALL = Pattern.compile("^(\\S+)\\s.*SRC=(\\S+).*?DPT=(\\d+)");
    private static final DateTimeFormatter APACHE_TS = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);
    private static final DateTimeFormatter SSH_TS = DateTimeFormatter.ofPattern("yyyy MMM d HH:mm:ss", Locale.ENGLISH);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static Parsed parse(String fileName, String text) {
        String t = text.strip();
        if (t.isEmpty()) throw new IllegalArgumentException("The uploaded file is empty.");
        List<Event> out = new ArrayList<>();
        Set<String> formats = new LinkedHashSet<>();
        int skipped = 0;
        String[] lines = t.split("\\r?\\n");

        if (fileName.toLowerCase().endsWith(".json")) {
            List<Map<String, Object>> rows = new ArrayList<>();
            try {
                if (t.startsWith("[")) rows = MAPPER.readValue(t, new TypeReference<List<Map<String, Object>>>() {});
                else for (String l : lines) { try { rows.add(MAPPER.readValue(l, new TypeReference<Map<String, Object>>() {})); } catch (Exception e) { skipped++; } }
            } catch (Exception e) { throw new IllegalArgumentException("Unable to read this JSON file. Please upload valid JSON."); }
            for (var row : rows) {
                Map<String, String> m = new HashMap<>();
                row.forEach((k, v) -> m.put(k.toLowerCase(), String.valueOf(v)));
                Event e = fromMap(m, row.toString());
                if (e == null) skipped++; else { out.add(e); formats.add("JSON Events"); }
            }
        } else if (isCsvHeader(lines[0])) {
            String[] head = lines[0].toLowerCase().split(",", -1);
            for (int i = 1; i < lines.length; i++) {
                String[] c = lines[i].split(",", -1);
                if (c.length != head.length) { skipped++; continue; }   // corrupted row
                Map<String, String> m = new HashMap<>();
                for (int j = 0; j < head.length; j++) m.put(head[j].trim(), c[j].trim().replace("\"", ""));
                Event e = fromMap(m, lines[i]);
                if (e == null) skipped++; else { out.add(e); formats.add("CSV Events (Windows/Generic)"); }
            }
        } else {
            for (String line : lines) {
                Event e = null;
                try { e = parseLine(line, formats); } catch (Exception ex) { /* malformed line -> skipped */ }
                if (e == null) skipped++; else out.add(e);
            }
        }
        if (out.isEmpty()) throw new IllegalArgumentException("Unable to recognize this log format. Please upload a supported security log.");
        return new Parsed(out, String.join(" + ", formats), skipped);
    }

    private static boolean isCsvHeader(String h) {
        h = h.toLowerCase();
        return h.contains(",") && h.contains("ip") && (h.contains("time") || h.contains("date"));
    }

    private static Event parseLine(String line, Set<String> formats) {
        String raw = line.length() > 500 ? line.substring(0, 500) : line;
        Matcher m = APACHE.matcher(line);
        if (m.find()) {
            long ts = OffsetDateTime.parse(m.group(3), APACHE_TS).toEpochSecond();
            String method = m.group(4), url = m.group(5); int st = Integer.parseInt(m.group(6));
            String res = "";
            if (method.equals("POST") && url.startsWith("/login")) res = (st == 401 || st == 403) ? "FAIL" : (st == 200 || st == 302) ? "SUCCESS" : "";
            formats.add("Apache/Nginx Access Log");
            return new Event(ts, m.group(1), m.group(2).equals("-") ? "" : m.group(2), method, url, st, 0, res, raw);
        }
        m = SSH.matcher(line);
        if (m.find()) {
            long ts = LocalDateTime.parse(Year.now().getValue() + " " + m.group(1).replaceAll("\\s+", " "), SSH_TS).toEpochSecond(ZoneOffset.UTC);
            formats.add("SSH auth.log");
            return new Event(ts, m.group(4), m.group(3), "", "", 0, 22, m.group(2).equals("Failed") ? "FAIL" : "SUCCESS", raw);
        }
        m = FIREWALL.matcher(line);
        if (m.find()) {
            long ts = parseTs(m.group(1));
            if (ts < 0) return null;
            formats.add("Firewall Log");
            return new Event(ts, m.group(2), "", "", "", 0, Integer.parseInt(m.group(3)), "", raw);
        }
        return null;
    }

    private static Event fromMap(Map<String, String> m, String raw) {
        String ip = first(m, "ip", "src_ip", "source_ip", "src", "client_ip");
        long ts = parseTs(first(m, "timestamp", "time", "datetime", "date"));
        if (ip == null || ip.isBlank() || ts < 0) return null;
        String act = (nz(first(m, "action", "result", "outcome", "event")) + " " + nz(first(m, "event_id", "eventid"))).toLowerCase();
        String res = "";
        if (act.contains("fail") || act.contains("denied") || act.contains("4625")) res = "FAIL";
        else if (act.contains("success") || act.contains("accept") || act.contains("4624")) res = "SUCCESS";
        String r = raw.length() > 500 ? raw.substring(0, 500) : raw;
        return new Event(ts, ip, nz(first(m, "user", "username", "account")), nz(first(m, "method", "http_method")),
                nz(first(m, "url", "path", "request", "uri")), toInt(first(m, "status", "status_code", "code")),
                toInt(first(m, "port", "dst_port", "dport")), res, r);
    }

    static long parseTs(String s) {
        if (s == null) return -1;
        s = s.trim();
        try {
            if (s.matches("\\d{9,13}")) { long v = Long.parseLong(s); return s.length() >= 12 ? v / 1000 : v; }
            String x = s.replace(' ', 'T');
            try { return LocalDateTime.parse(x).toEpochSecond(ZoneOffset.UTC); }
            catch (Exception e) { return OffsetDateTime.parse(x).toEpochSecond(); }
        } catch (Exception e) { return -1; }
    }

    private static String first(Map<String, String> m, String... keys) { for (String k : keys) if (m.containsKey(k)) return m.get(k); return null; }
    private static String nz(String s) { return s == null || s.equals("null") ? "" : s; }
    private static int toInt(String s) { try { return Integer.parseInt(s.trim()); } catch (Exception e) { return 0; } }
}
