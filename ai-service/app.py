"""CYBERLOG AI - educational anomaly detection service (Isolation Forest).
NOT a certified security product. It only scores numbers sent to it; it never touches real systems."""
import numpy as np
from flask import Flask, jsonify, request
from sklearn.ensemble import IsolationForest

app = Flask(__name__)
FEATURES = ["requests", "failed_logins", "successful_logins", "unique_ports",
            "unique_urls", "requests_per_minute", "error_rate", "fail_rate"]


def baseline(n=300):
    """Synthetic 'normal' behaviour so the model works even for logs with only a few IPs."""
    r = np.random.default_rng(42)
    return np.column_stack([r.integers(3, 80, n), r.integers(0, 3, n), r.integers(0, 9, n), r.integers(0, 3, n),
                            r.integers(1, 16, n), r.uniform(0.2, 8, n), r.uniform(0, 0.2, n), r.uniform(0, 0.3, n)])


BASE = baseline()
MEAN, STD = BASE.mean(axis=0), BASE.std(axis=0) + 1e-9


def explain(vec, anomaly):
    if not anomaly:
        return "Behaviour is within the normal profile."
    z = (vec - MEAN) / STD
    top = [i for i in np.argsort(-z)[:3] if z[i] > 2]
    if not top:
        return "The combination of features is unusual compared with the normal profile."
    parts = [f"{FEATURES[i].replace('_', ' ')} ({vec[i]:g}) is {z[i]:.1f} standard deviations above normal" for i in top]
    return "; ".join(parts) + "."


@app.get("/health")
def health():
    return jsonify(status="UP", model="IsolationForest")


@app.post("/analyze")
def analyze():
    data = request.get_json(silent=True) or {}
    ips = data.get("ips")
    if not isinstance(ips, dict) or not ips:
        return jsonify(error="Body must be {'ips': {ip: {features}}}"), 400
    names = list(ips.keys())
    try:
        X = np.array([[float(ips[ip].get(f, 0)) for f in FEATURES] for ip in names])
    except (TypeError, ValueError, AttributeError):
        return jsonify(error="Invalid feature values"), 400
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    model.fit(np.vstack([BASE, X]))
    d = model.decision_function(X)           # negative = anomalous
    MARGIN = -0.06                           # only clearly unusual IPs (score >= ~0.65) are flagged
    score = 1 / (1 + np.exp(10 * d))         # 0..1 (0.5 = boundary)
    res = {ip: {"anomaly": bool(d[i] < MARGIN), "score": round(float(score[i]), 3),
                "reason": explain(X[i], bool(d[i] < MARGIN))} for i, ip in enumerate(names)}
    return jsonify(results=res, model="IsolationForest (educational)")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
