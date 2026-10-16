package com.cyberlog;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.Map;

/** Calls the Python AI service. Returns null if the service is unavailable (the app keeps working). */
public class AiClient {
    private static final ObjectMapper M = new ObjectMapper();
    private final String url;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

    public AiClient(String url) { this.url = url; }

    @SuppressWarnings("unchecked")
    public Map<String, Map<String, Object>> analyze(Map<String, Map<String, Object>> features) {
        try {
            HttpRequest rq = HttpRequest.newBuilder(URI.create(url + "/analyze")).timeout(Duration.ofSeconds(60))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(M.writeValueAsString(Map.of("ips", features)))).build();
            HttpResponse<String> r = http.send(rq, HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) return null;
            return (Map<String, Map<String, Object>>) M.readValue(r.body(), Map.class).get("results");
        } catch (Exception e) { return null; }
    }
}
