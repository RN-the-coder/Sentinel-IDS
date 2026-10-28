# Known limitations and security notes

This is an **educational IDS prototype**, not a calibrated intrusion detector.

## Capture and telemetry

- Scapy/Npcap captures **IPv4 TCP** packets visible to the chosen interface; it cannot see all traffic across a network automatically.
- Administrator rights may be needed for packet capture on Windows.
- `sentinel_live.py` captures packets and hands them to a bounded in-memory queue. Under load, packets may be dropped from processing; compare captured/processed counters.
- A recent telemetry heartbeat indicates that the monitor reported itself running; it does not guarantee continuous visibility into all traffic.
- `ids.py` keeps the author's local Windows interface index `18` in its example entry point; others should verify interface indices and use `sentinel_live.py` with an explicit index.

## Detection

- The signature rules were adapted from a simplified educational tutorial. The `port_scan` rule does **not** count distinct probed destination ports, so traffic volume can be mistaken for scanning.
- A fixed confidence of `1.0` for a rule is a software convention, **not a measured probability** of an intrusion.
- WARNING and CRITICAL pairs may describe the same event, so the dashboard collapses duplicated log records when possible.
- The live engine creates an `IsolationForest`, but the app does not automatically supply real training samples, and the ML detector remains inactive unless explicitly trained.
- The ML lab is a **separate** simulation using artificially generated examples. The sample accuracy is not generalizable to real cyberattacks.
- The ML lab compares a model-learned classification threshold with the original tutorial's **hard-coded score threshold**, which may disagree.

## Data safety

- `ids_alerts.log` contains network IP addresses and should remain local.
- `sentinel_status.json` stores local interface and telemetry metadata and should remain local.
- Screenshot images in this repository were captured with IP masking enabled. For future public screenshots, prefer the **Demostración** mode with reserved fictional IPs.
- Exported CSVs could still disclose network metadata if masking was disabled; never publish without checking the contents.
- Avoid committing tokens, passwords, `.env` files, raw packet captures or logs. If sensitive data was committed previously, `.gitignore` alone does **not** remove it from Git history.

## Appropriate use

Run only on networks and devices you control or are authorized to monitor. Do not treat alerts as confirmed incidents without additional investigation.
