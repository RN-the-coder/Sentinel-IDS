"""Utilidades de datos para Sentinel IDS v2 (sin dependencias de Streamlit)."""

from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
import json
import random
import time

import pandas as pd

FIELDS = [
    "timestamp", "severity", "rule", "method", "source_ip",
    "destination_ip", "confidence", "score"
]


def mask_ip(ip):
    """Enmascara IPv4; para otros identificadores oculta el valor entero."""
    text = str(ip)
    parts = text.split(".")
    if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
        return ".".join(parts[:2] + ["x", "x"])
    return "Oculta"


def read_alerts(log_path, max_lines=16000):
    """Carga las últimas líneas y combina WARNING/CRITICAL de una detección."""
    path = Path(log_path)
    if not path.is_file():
        return pd.DataFrame(columns=FIELDS)

    records = {}
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        lines = deque(handle, maxlen=max_lines)

    for line in lines:
        parts = line.rstrip("\r\n").split(" - ", 2)
        if len(parts) != 3:
            continue
        level, message = parts[1], parts[2]
        if level not in ("WARNING", "CRITICAL"):
            continue
        start = message.find("{")
        if start < 0:
            continue
        try:
            payload = json.loads(message[start:])
        except (ValueError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue

        details = payload.get("details")
        if not isinstance(details, dict):
            details = {}
        timestamp = pd.to_datetime(payload.get("timestamp"), errors="coerce")
        if pd.isna(timestamp):
            continue
        try:
            timestamp = timestamp.tz_localize(None) if timestamp.tzinfo else timestamp
        except (TypeError, AttributeError):
            continue

        method = str(payload.get("threat_type") or "desconocido")
        rule = str(details.get("rule") or method)
        source = str(payload.get("source_ip") or "Desconocida")
        destination = str(payload.get("destination_ip") or "Desconocida")
        try:
            confidence = float(payload.get("confidence", 0.0))
        except (ValueError, TypeError):
            confidence = 0.0
        try:
            score = float(details["score"]) if details.get("score") is not None else None
        except (ValueError, TypeError):
            score = None

        # El CRITICAL del tutorial duplica un WARNING con el mismo JSON de evento.
        key = (timestamp.isoformat(), method, rule, source, destination, confidence, score)
        if key not in records:
            records[key] = {
                "timestamp": timestamp,
                "severity": "CRITICAL" if level == "CRITICAL" else "WARNING",
                "rule": rule,
                "method": method,
                "source_ip": source,
                "destination_ip": destination,
                "confidence": confidence,
                "score": score,
            }
        elif level == "CRITICAL":
            records[key]["severity"] = "CRITICAL"

    return pd.DataFrame(list(records.values()), columns=FIELDS)


def read_telemetry(path, max_age_seconds=6):
    """Retorna (estado, datos): activo, detenido, atrasado o desconocido.

    El tiempo de actualización se comprueba contra la modificación del archivo,
    no contra un texto o una inferencia a partir de ids_alerts.log.
    """
    path = Path(path)
    try:
        stat = path.stat()
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            return "desconocido", None
        if data.get("state") == "stopped":
            return "detenido", data
        if time.time() - stat.st_mtime > max_age_seconds:
            return "atrasado", data
        if data.get("state") == "running" and data.get("sniffer_running") is True:
            return "activo", data
        if data.get("state") == "error":
            return "error", data
        return "desconocido", data
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return "desconocido", None


def demo_alerts():
    """Datos 100% sintéticos e IP reservadas para documentación."""
    rng = random.Random(42)
    now = datetime.now().replace(second=0, microsecond=0)
    sources = ["198.51.100.12", "198.51.100.25", "203.0.113.8", "203.0.113.42", "192.0.2.71"]
    targets = ["192.0.2.10", "192.0.2.20", "192.0.2.30"]
    rules = ["port_scan", "syn_flood", "anomaly"]
    rows = []
    for i in range(170):
        rule = rng.choices(rules, weights=[6, 3, 2], k=1)[0]
        severity = rng.choices(["WARNING", "CRITICAL"], weights=[4, 3], k=1)[0]
        rows.append({
            "timestamp": now - timedelta(minutes=rng.randrange(0, 360), seconds=rng.randrange(60)),
            "severity": severity,
            "rule": rule,
            "method": "anomaly" if rule == "anomaly" else "signature",
            "source_ip": rng.choice(sources),
            "destination_ip": rng.choice(targets),
            "confidence": round(rng.uniform(0.5, 1.0), 3),
            "score": round(rng.uniform(-0.8, -0.5), 3) if rule == "anomaly" else None,
        })
    return pd.DataFrame(rows, columns=FIELDS)


def demo_telemetry():
    rng = random.Random(38)
    now = datetime.now()
    history = []
    total = 0
    bytes_total = 0
    for i in range(60):
        n = max(0, int(rng.gauss(18 + 11 * (i % 14 < 5), 7)))
        total += n
        bytes_total += n * 430
        history.append({
            "timestamp": (now - timedelta(seconds=59 - i)).isoformat(timespec="seconds"),
            "packets_per_second": n,
            "bytes_per_second": n * 430,
        })
    return {
        "schema_version": 1,
        "state": "demo",
        "sniffer_running": False,
        "packets_total": total,
        "processed_total": total,
        "bytes_total": bytes_total,
        "alerts_total": 170,
        "seconds_running": 60,
        "last_packet_at": now.isoformat(timespec="seconds"),
        "history": history,
    }
