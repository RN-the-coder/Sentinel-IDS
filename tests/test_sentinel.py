from pathlib import Path
import json
import time

from sentinel_data import mask_ip, read_alerts, read_telemetry
from ml_experiment import run_experiment


def test_mask_ip():
    assert mask_ip("172.64.155.209") == "172.64.x.x"
    assert mask_ip("bad") == "Oculta"


def test_duplicate_critical_warning_collapsed(tmp_path):
    payload = {
        "timestamp": "2026-10-28T15:00:29.000001",
        "threat_type": "signature",
        "source_ip": "172.64.155.209",
        "destination_ip": "192.168.1.100",
        "confidence": 1.0,
        "details": {"type": "signature", "rule": "port_scan", "confidence": 1.0},
    }
    body = json.dumps(payload)
    logfile = tmp_path / "ids_alerts.log"
    logfile.write_text(
        "2026-10-28 15:00:29,001 - WARNING - " + body + "\n" +
        "2026-10-28 15:00:29,002 - CRITICAL - High confidence threat detected: " + body + "\n",
        encoding="utf-8",
    )
    df = read_alerts(logfile)
    assert len(df) == 1
    assert df.iloc[0]["severity"] == "CRITICAL"
    assert df.iloc[0]["rule"] == "port_scan"


def test_telemetry_not_inferred_from_log(tmp_path):
    assert read_telemetry(tmp_path / "missing.json")[0] == "desconocido"
    f = tmp_path / "status.json"
    f.write_text(json.dumps({"schema_version": 1, "state": "running", "sniffer_running": True}))
    assert read_telemetry(f)[0] == "activo"
    old = time.time() - 60
    import os
    os.utime(f, (old, old))
    assert read_telemetry(f)[0] == "atrasado"
    f.write_text(json.dumps({"schema_version": 1, "state": "stopped", "sniffer_running": False}))
    assert read_telemetry(f)[0] == "detenido"


def test_ml_experiment():
    result = run_experiment(0.1, 1300, 250)
    assert result["anomalies_correct"] == 5
    assert result["prediction"] == -1
    assert result["sample_score"] < -0.5
