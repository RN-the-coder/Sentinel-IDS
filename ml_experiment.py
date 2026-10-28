"""Laboratorio interactivo con muestras sintéticas, separado del motor real."""

import numpy as np
from sklearn.ensemble import IsolationForest


def run_experiment(contamination=0.1, size=500, rate=12):
    rng = np.random.default_rng(42)

    def generate_normal(n):
        packet_sizes = np.clip(rng.normal(500, 40, n), 200, 800)
        packet_rates = np.clip(rng.normal(12, 2, n), 1, 25)
        return np.column_stack((packet_sizes, packet_rates, packet_sizes * packet_rates))

    training = generate_normal(200)
    normal = generate_normal(30)
    anomalies = np.array([
        [60, 180, 10800],
        [1300, 250, 325000],
        [80, 110, 8800],
        [1100, 90, 99000],
        [50, 300, 15000],
    ], dtype=float)

    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(training)
    normal_preds = model.predict(normal)
    anomalous_preds = model.predict(anomalies)
    sample = np.array([[size, rate, size * rate]], dtype=float)
    score = float(model.score_samples(sample)[0])

    return {
        "normal_correct": int((normal_preds == 1).sum()),
        "anomalies_correct": int((anomalous_preds == -1).sum()),
        "false_positives": int((normal_preds == -1).sum()),
        "prediction": int(model.predict(sample)[0]),
        "sample_score": score,
        "tutorial_rule_fires": bool(score < -0.5),
        "threshold": float(model.offset_),
        "normal_scores": model.score_samples(normal),
        "anomaly_scores": model.score_samples(anomalies),
    }
