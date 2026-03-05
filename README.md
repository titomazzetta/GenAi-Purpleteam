# PurpleLab: Automated Purple Team Simulation with Generative AI

PurpleLab is a Python CLI tool that automates a complete red team / blue team exercise on a single Debian VM. It simulates a phishing attack, collects telemetry using Wazuh, Suricata, Zeek, and auditd, and leverages a local LLM (Mistral 7B via Ollama) to analyze the incident and generate a professional report.

## Features

- **AI-generated phishing email and attack plan** (MITRE ATT&CK mapped)
- **Safe local emulation** of post-click behaviors (discovery, credential access, C2)
- **Comprehensive log collection** from Suricata, Zeek, auditd, and Wazuh
- **Correlation and timeline building**
- **AI-powered defensive analysis** (IOCs, detection rules, hardening recommendations)
- **Automatic Markdown report generation** with all artifacts
- **Single VM deployment** – easy to demo and share

## Requirements

- Debian 12 (or 11) VM
- **Minimum 8GB RAM** (for 4-bit quantized Mistral)
- 20GB free disk space
- Root access (for installing sensors)

## Installation

```bash
git clone git clone https://github.com/titomazzetta/GenAi-Purpleteam.git
cd purplelab
pip install -r requirements.txt
sudo python3 purplelab.py setup   # Installs all sensors and Ollama
```

## Quick Start

After setup, run a full exercise:

```bash
python3 purplelab.py run full
```

Or run individual steps:

```bash
python3 purplelab.py run generate              # Generate phishing email + attack plan
python3 purplelab.py run emulate --run-id XXX  # Emulate the attack
python3 purplelab.py run collect XXX           # Collect logs
python3 purplelab.py run analyze XXX           # Run AI analysis
python3 purplelab.py run report XXX            # Generate report
```

## Output

All artifacts are stored in `runs/{run_id}/`:
- `scenario/` – Generated phishing email and attack plan
- `raw/` – Raw logs from all sensors
- `processed/` – Timeline and enriched bundle
- `iocs/` – STIX IOC data
- `rules/` – Sigma and Suricata detection rules
- `report.md` – Final Markdown report

## License

MIT
