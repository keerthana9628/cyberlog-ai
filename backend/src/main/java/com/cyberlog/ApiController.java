package com.cyberlog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.*;
import org.springframework.dao.DataAccessException;
import org.springframework.http.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api")
public class ApiController {
    private final AnalysisService svc;
    private final JdbcTemplate db;
    public ApiController(AnalysisService svc, JdbcTemplate db) { this.svc = svc; this.db = db; }

    @GetMapping("/health")
    public Map<String, Object> health() { return Map.of("status", "UP", "time", Instant.now().toString()); }

    @PostMapping("/logs/upload")
    public Map<String, Object> upload(@RequestParam("file") MultipartFile f) throws IOException {
        if (f.isEmpty()) throw new IllegalArgumentException("The uploaded file is empty.");
        // sanitize the name; the file is never written to disk or executed - only parsed as text
        String name = Paths.get(String.valueOf(f.getOriginalFilename())).getFileName().toString().replaceAll("[^A-Za-z0-9._-]", "_");
        String lower = name.toLowerCase();
        if (!(lower.endsWith(".log") || lower.endsWith(".txt") || lower.endsWith(".csv") || lower.endsWith(".json")))
            throw new IllegalArgumentException("Unsupported file type. Please upload a .log, .txt, .csv or .json file.");
        return svc.upload(name, f.getSize(), new String(f.getBytes(), StandardCharsets.UTF_8));
    }

    @PostMapping("/logs/analyze")
    public Map<String, Object> analyze(@RequestBody Map<String, Object> body) {
        Object id = body.get("sessionId");
        if (!(id instanceof Number n)) throw new IllegalArgumentException("sessionId is required.");
        return svc.analyze(n.longValue());
    }

    private Long latest() { return db.queryForObject("SELECT MAX(id) FROM sessions WHERE status='ANALYZED'", Long.class); }
    private long need() { Long s = latest(); if (s == null) throw new NoSuchElementException("No analysis yet. Upload a log and click Analyze."); return s; }

    @GetMapping("/dashboard")
    public Map<String, Object> dashboard() {
        Long s = latest();
        if (s == null) return Map.of("hasData", false);
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("hasData", true);
        d.put("session", db.queryForMap("SELECT * FROM sessions WHERE id=?", s));
        int total = db.queryForObject("SELECT COUNT(*) FROM logs WHERE session_id=?", Integer.class, s);
        int susp = db.queryForObject("SELECT COUNT(*) FROM logs WHERE session_id=? AND ip IN (SELECT ip FROM threats WHERE session_id=?)", Integer.class, s, s);
        d.put("totalEvents", total); d.put("suspiciousEvents", susp); d.put("normalEvents", total - susp);
        d.put("threats", db.queryForObject("SELECT COUNT(*) FROM threats WHERE session_id=?", Integer.class, s));
        d.put("criticalThreats", db.queryForObject("SELECT COUNT(*) FROM threats WHERE session_id=? AND severity='CRITICAL'", Integer.class, s));
        d.put("highRiskIps", db.queryForObject("SELECT COUNT(*) FROM ip_statistics WHERE session_id=? AND risk_score>=51", Integer.class, s));
        d.put("securityScore", db.queryForObject("SELECT security_score FROM sessions WHERE id=?", Integer.class, s));
        d.put("bySeverity", db.queryForList("SELECT severity k, COUNT(*) v FROM threats WHERE session_id=? GROUP BY severity", s));
        d.put("byType", db.queryForList("SELECT type k, COUNT(*) v FROM threats WHERE session_id=? GROUP BY type", s));
        d.put("timeline", db.queryForList("SELECT (ts/60)*60 t, COUNT(*) c FROM logs WHERE session_id=? GROUP BY t ORDER BY t LIMIT 300", s));
        d.put("topIps", db.queryForList("SELECT ip, risk_score FROM ip_statistics WHERE session_id=? ORDER BY risk_score DESC LIMIT 5", s));
        d.put("statusDist", db.queryForList("SELECT status k, COUNT(*) v FROM logs WHERE session_id=? AND status>0 GROUP BY status ORDER BY v DESC LIMIT 10", s));
        d.put("normalVsAnomalous", db.queryForMap("SELECT COALESCE(SUM(CASE WHEN anomaly=1 THEN requests ELSE 0 END),0) anomalous, COALESCE(SUM(CASE WHEN anomaly=0 THEN requests ELSE 0 END),0) normal FROM ip_statistics WHERE session_id=?", s));
        int ips = db.queryForObject("SELECT COUNT(*) FROM ip_statistics WHERE session_id=?", Integer.class, s);
        int an = db.queryForObject("SELECT COUNT(*) FROM ip_statistics WHERE session_id=? AND anomaly=1", Integer.class, s);
        Double avg = db.queryForObject("SELECT AVG(anomaly_score) FROM ip_statistics WHERE session_id=? AND anomaly=1", Double.class, s);
        Map<String, Object> ai = new LinkedHashMap<>();
        ai.put("anomalies", an); ai.put("totalIps", ips); ai.put("anomalyPercent", ips == 0 ? 0 : Math.round(1000.0 * an / ips) / 10.0);
        ai.put("aiRiskScore", avg == null ? 0 : Math.round(avg * 100));
        ai.put("topAnomalies", db.queryForList("SELECT ip, requests, anomaly_score, ai_reason FROM ip_statistics WHERE session_id=? AND anomaly=1 ORDER BY anomaly_score DESC LIMIT 10", s));
        d.put("ai", ai);
        return d;
    }

    @GetMapping("/threats")
    public List<Map<String, Object>> threats(@RequestParam(required = false) String severity, @RequestParam(required = false) String type,
            @RequestParam(required = false) String ip, @RequestParam(required = false) String q,
            @RequestParam(required = false) Long from, @RequestParam(required = false) Long to) {
        Long s = latest(); if (s == null) return List.of();
        StringBuilder sql = new StringBuilder("SELECT * FROM threats WHERE session_id=?"); List<Object> p = new ArrayList<>(List.of(s));
        if (has(severity)) { sql.append(" AND severity=?"); p.add(severity.toUpperCase()); }
        if (has(type)) { sql.append(" AND type=?"); p.add(type); }
        if (has(ip)) { sql.append(" AND ip LIKE ?"); p.add("%" + ip.trim() + "%"); }
        if (has(q)) { sql.append(" AND (reason LIKE ? OR ip LIKE ? OR type LIKE ?)"); p.add("%" + q + "%"); p.add("%" + q + "%"); p.add("%" + q + "%"); }
        if (from != null) { sql.append(" AND ts>=?"); p.add(from); }
        if (to != null) { sql.append(" AND ts<=?"); p.add(to); }
        sql.append(" ORDER BY score DESC, ts LIMIT 1000");
        return db.queryForList(sql.toString(), p.toArray());
    }

    @GetMapping("/threats/{id}")
    public Map<String, Object> threat(@PathVariable long id) {
        var l = db.queryForList("SELECT * FROM threats WHERE id=?", id);
        if (l.isEmpty()) throw new NoSuchElementException("Threat not found.");
        return l.get(0);
    }

    @GetMapping("/ip-analysis")
    public List<Map<String, Object>> ips() {
        Long s = latest(); if (s == null) return List.of();
        return db.queryForList("SELECT * FROM ip_statistics WHERE session_id=? ORDER BY risk_score DESC, requests DESC", s);
    }

    @GetMapping("/logs")
    public List<Map<String, Object>> logs(@RequestParam(required = false) String q, @RequestParam(required = false) String ip,
            @RequestParam(required = false) String severity, @RequestParam(required = false) String type,
            @RequestParam(required = false) Long from, @RequestParam(required = false) Long to) {
        Long s = latest(); if (s == null) return List.of();
        StringBuilder sql = new StringBuilder("SELECT * FROM logs WHERE session_id=?"); List<Object> p = new ArrayList<>(List.of(s));
        if (has(q)) { sql.append(" AND raw LIKE ?"); p.add("%" + q + "%"); }
        if (has(ip)) { sql.append(" AND ip LIKE ?"); p.add("%" + ip.trim() + "%"); }
        if (has(severity)) { sql.append(" AND ip IN (SELECT ip FROM threats WHERE session_id=? AND severity=?)"); p.add(s); p.add(severity.toUpperCase()); }
        if (has(type)) { sql.append(" AND ip IN (SELECT ip FROM threats WHERE session_id=? AND type=?)"); p.add(s); p.add(type); }
        if (from != null) { sql.append(" AND ts>=?"); p.add(from); }
        if (to != null) { sql.append(" AND ts<=?"); p.add(to); }
        sql.append(" ORDER BY ts LIMIT 500");
        return db.queryForList(sql.toString(), p.toArray());
    }

    @GetMapping("/reports")
    public Map<String, Object> report() {
        long s = need();
        var sess = db.queryForMap("SELECT * FROM sessions WHERE id=?", s);
        var threats = db.queryForList("SELECT * FROM threats WHERE session_id=? ORDER BY score DESC", s);
        var top = db.queryForList("SELECT * FROM ip_statistics WHERE session_id=? ORDER BY risk_score DESC LIMIT 5", s);
        var ai = db.queryForList("SELECT * FROM ip_statistics WHERE session_id=? AND anomaly=1 ORDER BY anomaly_score DESC LIMIT 5", s);
        StringBuilder md = new StringBuilder("# CYBERLOG AI - Security Analysis Report\n\n");
        md.append("*Educational tool. Scores are calculated heuristics, not certified security assessments.*\n\n");
        md.append("## Summary\n- File: ").append(sess.get("file_name")).append("\n- Format: ").append(sess.get("format"))
          .append("\n- Records: ").append(sess.get("records")).append("\n- Threats detected: ").append(threats.size())
          .append("\n- Calculated Security Score: ").append(sess.get("security_score")).append("/100\n\n## Top Suspicious IPs\n");
        for (var r : top) md.append("- ").append(r.get("ip")).append(" - Calculated Risk Score ").append(r.get("risk_score")).append(" (").append(r.get("status")).append(")\n");
        md.append("\n## Detected Threats\n");
        for (var t : threats) md.append("- [").append(t.get("severity")).append("] ").append(t.get("type")).append(" from ").append(t.get("ip")).append(": ").append(t.get("reason")).append("\n");
        md.append("\n## AI Findings (Isolation Forest, educational model)\n");
        if (ai.isEmpty()) md.append("- No anomalous IPs found (or the AI service was unavailable).\n");
        for (var r : ai) md.append("- ").append(r.get("ip")).append(": ").append(r.get("ai_reason")).append("\n");
        md.append("\n## Recommendations\n");
        Set<Object> types = new HashSet<>(); threats.forEach(t -> types.add(t.get("type")));
        if (types.contains("Brute Force") || types.contains("Suspicious Login")) md.append("- Enforce account lockout/rate limiting and multi-factor authentication; review accounts that logged in after failures.\n");
        if (types.contains("Port Scan")) md.append("- Review firewall rules and consider blocking or rate-limiting the scanning IPs.\n");
        if (types.contains("Request Spike")) md.append("- Add rate limiting or a WAF; check whether the traffic is a legitimate event.\n");
        if (types.contains("Unauthorized Access")) md.append("- Restrict /admin and similar paths by IP or VPN and confirm none returned 200 to outsiders.\n");
        if (types.isEmpty()) md.append("- No threats detected. Keep monitoring and keep logs for review.\n");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("fileName", sess.get("file_name")); out.put("markdown", md.toString());
        return out;
    }

    private static boolean has(String s) { return s != null && !s.isBlank(); }
}

/** Friendly JSON errors instead of stack traces (never exposes server paths). */
@RestControllerAdvice
class ErrorHandler {
    private ResponseEntity<Map<String, String>> err(HttpStatus s, String m) { return ResponseEntity.status(s).body(Map.of("error", m)); }
    @ExceptionHandler(IllegalArgumentException.class) ResponseEntity<Map<String, String>> bad(IllegalArgumentException e) { return err(HttpStatus.BAD_REQUEST, e.getMessage()); }
    @ExceptionHandler(NoSuchElementException.class) ResponseEntity<Map<String, String>> nf(NoSuchElementException e) { return err(HttpStatus.NOT_FOUND, e.getMessage()); }
    @ExceptionHandler(MaxUploadSizeExceededException.class) ResponseEntity<Map<String, String>> big(Exception e) { return err(HttpStatus.PAYLOAD_TOO_LARGE, "File too large. The limit is 10 MB."); }
    @ExceptionHandler(DataAccessException.class) ResponseEntity<Map<String, String>> dbErr(Exception e) { return err(HttpStatus.INTERNAL_SERVER_ERROR, "Database error. Please try again."); }
    @ExceptionHandler(Exception.class) ResponseEntity<Map<String, String>> other(Exception e) { return err(HttpStatus.INTERNAL_SERVER_ERROR, "Something went wrong while processing the request."); }
}
