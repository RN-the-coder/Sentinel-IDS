"""Ejecutor instrumentado del IDS existente. No modifica ids.py.

Uso en Windows (PowerShell administrador):
  .\\venv\\Scripts\\python.exe sentinel_live.py --interface-index 18
"""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import queue
import threading
import time

from scapy.all import AsyncSniffer, IP, TCP, conf, show_interfaces
from ids import TrafficAnalyzer, DetectionEngine, AlertSystem

ROOT = Path(__file__).resolve().parent
STATUS_PATH = ROOT / "sentinel_status.json"
LOG_PATH = ROOT / "ids_alerts.log"


def local_now():
    return datetime.now().isoformat(timespec="seconds")


class Telemetry:
    """Mantiene solo contadores de tráfico, sin guardar contenido de paquetes."""

    def __init__(self, interface):
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.interface = str(interface)
        self.packets_total = 0
        self.bytes_total = 0
        self.processed_total = 0
        self.alerts_total = 0
        self.last_packet_at = None
        self.interval_packets = 0
        self.interval_bytes = 0
        self.history = []
        self.last_sample = time.monotonic()

    def captured(self, packet):
        with self.lock:
            self.packets_total += 1
            self.bytes_total += len(packet)
            self.interval_packets += 1
            self.interval_bytes += len(packet)
            self.last_packet_at = local_now()

    def processed(self):
        with self.lock:
            self.processed_total += 1

    def alert(self):
        with self.lock:
            self.alerts_total += 1

    def snapshot(self, state, sniffer_running=False, error=None):
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_sample
            if elapsed >= 1:
                self.history.append({
                    "timestamp": local_now(),
                    "packets_per_second": round(self.interval_packets / elapsed, 2),
                    "bytes_per_second": round(self.interval_bytes / elapsed, 2),
                })
                self.history = self.history[-90:]
                self.interval_packets = 0
                self.interval_bytes = 0
                self.last_sample = now

            return {
                "schema_version": 1,
                "state": state,
                "sniffer_running": bool(sniffer_running),
                "interface": self.interface,
                "updated_at": local_now(),
                "seconds_running": round(now - self.started),
                "packets_total": self.packets_total,
                "processed_total": self.processed_total,
                "bytes_total": self.bytes_total,
                "alerts_total": self.alerts_total,
                "last_packet_at": self.last_packet_at,
                "history": list(self.history),
                "error": error,
            }


def save_snapshot(telemetry, state, sniffer_running=False, error=None):
    snapshot = telemetry.snapshot(state, sniffer_running, error)
    temporary = STATUS_PATH.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, ensure_ascii=False)
    os.replace(temporary, STATUS_PATH)


def main():
    parser = argparse.ArgumentParser(description="Sentinel IDS — captura y telemetría local")
    parser.add_argument("--interface-index", type=int, default=None,
                        help="Índice del adaptador en show_interfaces() (p. ej., 18)")
    parser.add_argument("--list-interfaces", action="store_true", help="Mostrar adaptadores y salir")
    args = parser.parse_args()
    if args.list_interfaces:
        show_interfaces()
        return

    interface = conf.ifaces.dev_from_index(args.interface_index) if args.interface_index is not None else conf.iface
    if STATUS_PATH.exists() and time.time() - STATUS_PATH.stat().st_mtime < 5:
        try:
            previous = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            previous = {}
        if previous.get("state") == "running":
            raise SystemExit("Ya parece haber un monitor Sentinel activo. Detén ese proceso antes de iniciar otro.")

    telemetry = Telemetry(interface)
    packet_queue = queue.Queue(maxsize=4000)
    analyzer = TrafficAnalyzer()
    engine = DetectionEngine()
    alerts = AlertSystem(log_file=str(LOG_PATH))

    def callback(packet):
        if IP in packet and TCP in packet:
            telemetry.captured(packet)
            try:
                packet_queue.put_nowait(packet)
            except queue.Full:
                # No bloquear la captura; la diferencia capturados/procesados es observable.
                pass

    sniffer = None
    last_write = 0.0
    final_state = "stopped"
    error = None
    try:
        sniffer = AsyncSniffer(iface=interface, prn=callback, store=False)
        sniffer.start()
        print(f"Sentinel IDS v2: capturando TCP/IP en {interface}")
        print("Telemetría: sentinel_status.json | Alertas: ids_alerts.log")
        print("Abre otro terminal para ejecutar: python -m streamlit run dashboard.py")
        print("Para detener: Ctrl+C")

        while True:
            if not sniffer.running:
                raise RuntimeError("El capturador dejó de estar activo. Revisa Npcap y la interfaz.")
            try:
                packet = packet_queue.get(timeout=0.25)
            except queue.Empty:
                packet = None
            if packet is not None:
                features = analyzer.analyze_packet(packet)
                telemetry.processed()
                if features:
                    for threat in engine.detect_threats(features):
                        alerts.generate_alert(threat, {
                            "source_ip": packet[IP].src,
                            "destination_ip": packet[IP].dst,
                            "source_port": packet[TCP].sport,
                            "destination_port": packet[TCP].dport,
                        })
                        telemetry.alert()
            if time.monotonic() - last_write >= 1:
                save_snapshot(telemetry, "running", sniffer.running)
                last_write = time.monotonic()

    except KeyboardInterrupt:
        print("Deteniendo Sentinel IDS...")
    except Exception as exc:
        final_state = "error"
        error = f"{type(exc).__name__}: {exc}"
        print(f"Error: {error}")
    finally:
        if sniffer is not None and sniffer.running:
            try:
                sniffer.stop(join=True)
            except Exception as exc:
                final_state = "error"
                error = f"No se pudo detener captura: {exc}"
        save_snapshot(telemetry, final_state, False, error)
        print("Estado final guardado.")


if __name__ == "__main__":
    main()
