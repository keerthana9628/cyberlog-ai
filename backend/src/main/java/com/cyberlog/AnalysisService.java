package com.cyberlog;

import com.cyberlog.LogParser.Event;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/** Upload -> Analyze pipeline: parse, rules, AI, risk scoring, save to SQLite. All SQL uses ? placeholders. */
@Service
public class AnalysisService {
    private static final ObjectMapper M = new ObjectMapper();
    private final JdbcTemplate db;
    private final Detector detector;
    private final AiClient ai;
    private final Map<Long, List<Event>> pending = new ConcurrentHashMap<>();

    public AnalysisService(JdbcTemplate db, @Value("${cyberlog.ai.url}") String aiUrl,
                           @Value("${cyberlog.bf.max-fails}") int bfMax, @Value("${cyberlog.bf.window-sec}") int bfWin,
                           @Value("${cyberlog.scan.min-ports}") int scanMin, @Value("${cyberlog.scan.window-sec}") int scanWin) {
        this.db = db; this.ai = new AiClient(aiUrl); this.detector = new Detector(bfMax, bfWin, scanMin, scanWin);
    }

    public Map<String, Object> upload(String fileName, long size, String text) {
        LogParser.Parsed p = LogParser.parse(fileName, text);
        db.update("INSERT INTO sessions(file_name,size,format,records,status,created_at) VALUES(?,?,?,?,?,?)",
            fileName, size, p.format(), p.events().size(), "UPLOADED", Instant.now().getEpochSecond());
        long id = db.queryForObject("SELECT last_insert_rowid()", Long.class);
        pending.put(id, p.events());
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("sessionId", id); r.put("fileName", fileName); r.put("size", size);
        r.put("records", p.events().size()); r.put("format", p.format()); r.put("skippedLines", p.skipped());
        return r;
    }

    public Map<String, Object> analyze(long id) {
        List<Event> ev = pending.get(id);
        if (ev == null) throw new NoSuchElementException("Upload session not found. Please upload the log file again.");
        for (String t : List.of("logs", "threats", "ip_statistics")) db.update("DELETE FROM " + t + " WHERE session_id=?", id);
        db.batchUpdate("INSERT INTO logs(session_id,ts,ip,username,method,url,status,port,result,raw) VALUES(?,?,?,?,?,?,?,?,?,?)", ev, 500,
            (ps, e) -> { ps.setLong(1, id); ps.setLong(2, e.ts()); ps.setString(3, e.ip()); ps.setString(4, e.username()); ps.setString(5, e.method());
                ps.setString(6, e.url()); ps.setInt(7, e.status()); ps.setInt(8, e.port()); ps.setString(9, e.result()); ps.setString(10, e.raw()); });

        var groups = detector.group(ev);
        Map<String, Map<String, Object>> feats = new LinkedHashMap<>();
        groups.forEach((ip, l) -> feats.put(ip, detector.features(l)));
        var aiRes = ai.analyze(feats);                       // null if AI service is down
        boolean aiOk = aiRes != null;

        List<Detector.Threat> threats = new ArrayList<>(detector.detect(groups));
        Set<String> ruleIps = threats.stream().map(Detector.Threat::ip).collect(Collectors.toSet());
        if (aiOk) for (var en : aiRes.entrySet()) {          // IPs flagged only by the AI model
            var r = en.getValue(); String ip = en.getKey();
            if (Boolean.TRUE.equals(r.get("anomaly")) && !ruleIps.contains(ip) && groups.containsKey(ip))
                threats.add(new Detector.Threat(ip, "Anomaly", groups.get(ip).get(0).ts(), Math.round(num(r.get("score")) * 100) / 100.0,
                    "The AI model flagged unusual behaviour: " + r.get("reason"), 1, 1));
        }
        Map<String, Integer> ipMax = new HashMap<>(); List<Integer> scores = new ArrayList<>();
        for (Detector.Threat t : threats) {
            var r = aiOk ? aiRes.get(t.ip()) : null;
            boolean an = r != null && Boolean.TRUE.equals(r.get("anomaly"));
            Detector.Risk risk = Detector.risk(t.type(), t.count(), t.threshold(), an, r == null ? 0 : num(r.get("score")));
            db.update("INSERT INTO threats(session_id,ts,ip,type,severity,confidence,score,reason,status,factors) VALUES(?,?,?,?,?,?,?,?,?,?)",
                id, t.ts(), t.ip(), t.type(), risk.severity(), t.confidence(), risk.score(), t.reason(), "Open", json(risk.factors()));
            ipMax.merge(t.ip(), risk.score(), Math::max); scores.add(risk.score());
        }
        int anomalies = 0;
        for (var en : feats.entrySet()) {
            String ip = en.getKey(); var f = en.getValue(); var r = aiOk ? aiRes.get(ip) : null;
            boolean an = r != null && Boolean.TRUE.equals(r.get("anomaly")); if (an) anomalies++;
            int risk = ipMax.getOrDefault(ip, 0);
            long tc = threats.stream().filter(t -> t.ip().equals(ip)).count();
            db.update("INSERT INTO ip_statistics(session_id,ip,requests,failed_logins,successful_logins,unique_ports,unique_urls,threat_count,risk_score,anomaly,anomaly_score,ai_reason,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                id, ip, f.get("requests"), f.get("failed_logins"), f.get("successful_logins"), f.get("unique_ports"), f.get("unique_urls"),
                tc, risk, an ? 1 : 0, r == null ? 0 : num(r.get("score")), r == null ? "AI service unavailable" : r.get("reason"),
                risk >= 51 ? "High Risk" : risk > 0 ? "Suspicious" : "Normal");
        }
        int secScore = 100;
        if (!scores.isEmpty()) secScore = Math.max(0, 100 - (int) Math.round(0.6 * Collections.max(scores) + 0.4 * scores.stream().mapToInt(i -> i).average().orElse(0)));
        db.update("UPDATE sessions SET status='ANALYZED', analyzed_at=?, security_score=?, ai_available=?, anomalies=? WHERE id=?",
            Instant.now().getEpochSecond(), secScore, aiOk ? 1 : 0, anomalies, id);
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("sessionId", id); res.put("threats", threats.size()); res.put("anomalies", anomalies);
        res.put("securityScore", secScore); res.put("aiAvailable", aiOk);
        return res;
    }

    private static double num(Object o) { return o instanceof Number n ? n.doubleValue() : 0; }
    private static String json(Object o) { try { return M.writeValueAsString(o); } catch (Exception e) { return "{}"; } }
}
