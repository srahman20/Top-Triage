# Top‑Triage — End‑to‑End Alert Triage Pipeline (Wireshark → Python → Splunk → SOAR)

A practical, mid‑level security engineering project that tackles **alert fatigue** by collecting raw telemetry (PCAP + system logs), normalizing events with Python, applying correlation + enrichment, scoring and prioritizing alerts, and visualizing them in Splunk. A small set of **SOAR‑style actions** (Slack/webhook, blocklist suggestion, email) demonstrates automated handoff.

> **Note:** Screenshots in this repo are from Splunk Dashboard Studio; packet capture/log generation steps are documented so you can reproduce them in a lab.

---

## Goals & Scope
- Reduce noise by correlating common behaviors: **brute force**, **port scans**, **suspicious egress**.
- Add context (reputation, asset criticality) and produce a **risk score** per entity/event.
- Present a focused triage view: **Top Alerts**, **Top Offenders**, **Timeline**, **Recent High‑Signal Events**.
- Emulate SOAR handoff with a few safe actions.

Out of scope: building a production SIEM/SOAR; the project is a **repeatable lab** with clear code + docs.

---

## Architecture
```mermaid
flowchart LR
  A[Telemetry Sources] -->|PCAP (Wireshark/tcpdump)| B(Collector)
  A -->|Syslog / Windows Events| B
  B --> C[Normalizer (Python)]
  C --> D[Correlation Engine (YAML rules)]
  D --> E[Enrichment (Reputation/Assets)]
  E --> F[Risk Scoring & Prioritization]
  F --> G[Outputs]
  G -->|HTTP Event Collector| H[(Splunk Index)]
  G -->|CSV/JSON Artifacts| I[Artifacts]
  H --> J[Dashboard Studio Panels]
  F --> K[SOAR Actions (webhook/email/blocklist)]
```

---

## Repo Structure
```
top-triage/
├─ collector/
│  ├─ pcap_to_csv.py
│  ├─ syslog_sample/
│  │  └─ sample.log
│  └─ win_events_sample/
│     └─ sample.csv
├─ engine/
│  ├─ schema.py
│  ├─ normalize.py
│  ├─ correlate.py
│  ├─ enrich.py
│  └─ score.py
├─ rules/
│  ├─ rules.yaml
│  └─ allowlists.yaml
├─ outputs/
│  ├─ .gitkeep
│  ├─ out_events.jsonl        # generated
│  ├─ out_alerts.jsonl        # generated
│  └─ out_alerts.csv          # generated
├─ splunk/
│  ├─ hec_config.md
│  ├─ panels.spl
│  └─ dashboard_notes.md
├─ soar/
│  ├─ actions.py
│  └─ actions.yaml
├─ configs/
│  ├─ assets.csv
│  ├─ rep_local.csv
│  └─ .env.example
├─ docs/
│  ├─ screenshots/
│  │  └─ .gitkeep
│  └─ diagrams/
│     └─ architecture.mmd
├─ tests/
│  ├─ fixtures/
│  │  └─ tiny_events.jsonl
│  └─ test_rules.py
├─ requirements.txt
├─ Makefile
└─ README.md
```

---

## Quick Start
**Prereqs:** Python 3.11+, `tshark` (Wireshark CLI), Splunk Enterprise (local), `jq` for the HEC make target

```bash
# 1) Setup venv
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2) Convert PCAP → CSV (example capture)
# (Skip if using only sample logs in collector/syslog_sample)
python collector/pcap_to_csv.py data/sample.pcap -o data/pcap.csv

# 3) Normalize + correlate + enrich + score
python -m engine.normalize --pcap data/pcap.csv --syslog collector/syslog_sample/*.log --win collector/win_events_sample/*.csv -o outputs/out_events.jsonl
python -m engine.correlate --rules rules/rules.yaml --allow rules/allowlists.yaml --events outputs/out_events.jsonl -o outputs/correlated.jsonl
python -m engine.enrich --events outputs/correlated.jsonl --assets configs/assets.csv --rep configs/rep_local.csv -o outputs/enriched.jsonl
python -m engine.score --events outputs/enriched.jsonl -o outputs/out_alerts.jsonl --csv outputs/out_alerts.csv

# 4) (Option A) Send to Splunk via HEC
export $(grep -v '^#' configs/.env.example | xargs)   # or create your own .env
make hec-send

# 4) (Option B) Splunk file ingest
# Configure a file monitor for outputs/out_alerts.csv → index=toptriage sourcetype=toptriage:alerts
```

---

## PCAP & Log Generation (Lab Recipes)
> **Run only in your own lab.**

**Port Scan (nmap)**
```bash
nmap -sS -p 1-1000 10.0.0.5
```

**SSH Brute Force (hydra)**
```bash
hydra -l student -P rockyou.txt ssh://10.0.0.5
```

**Wireshark/tcpdump capture**
```bash
sudo tcpdump -i eth0 -w data/sample.pcap host 10.0.0.5
```

---

## Dashboard (Security‑Focused SPL)
See `splunk/panels.spl` for queries such as **Brute Force Timeline**, **Top Offenders**, **Recent High‑Signal Alerts**, and **Scan Heat**.



