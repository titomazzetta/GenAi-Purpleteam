# PurpleLab — Automated Purple Team Simulation (Ollama-only)

PurpleLab is a **lab-only** purple-team automation project that demonstrates an end-to-end workflow:

1. **Red Team (safe emulation):** generate an AI-driven scenario + ATT&CK-mapped plan, then run **non-destructive** commands to create telemetry
2. **Blue Team (telemetry):** collect logs from common sensors (Suricata/Zeek/auditd/Wazuh where available)
3. **SOC triage (GenAI via Ollama):** extract IOCs, map ATT&CK, identify detection gaps, and recommend mitigations
4. **Reporting:** output a **portfolio-ready** `report.md` with **detection coverage scoring** and recommended defensive actions

> This repository is intentionally **Ollama-only** (no OpenAI dependencies).

---

## Safety / Scope

- **Educational lab simulation only.**
- No malware, persistence, or real exploitation.
- Emulation uses standard Linux utilities (curl/wget/uname/id/ip/cat/nslookup/dig/nmap) to generate detection signals.

---

## What you get at the end of a run

A run creates a folder:

`runs/<run_id>/`

Key outputs:

- `report.md` — final GitHub-friendly report (coverage score + gaps + mitigations)
- `processed/timeline.json` — normalized telemetry timeline
- `processed/ai_insights.json` — raw AI JSON (Ollama)
- `iocs/iocs.stix.json` — IOC bundle (STIX 2.1 where applicable)
- `rules/` — drafted Sigma rules + Suricata rules

---

## Quickstart (Kali / Debian)

### 0) Clone + create a venv (recommended on Kali)

```bash
<<<<<<< HEAD
git clone git clone https://github.com/titomazzetta/GenAi-Purpleteam.git
=======
git clone <YOUR_REPO_URL>
>>>>>>> 2d06cee (Finalize PurpleLab AI-driven purple team simulation with Ollama analysis, detection coverage scoring, and SOC mitigation reporting)
cd purplelab

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 1) Guided installer (recommended)

This will:
- install sensors (Suricata + auditd, optional Zeek/Wazuh)
- install Ollama (optional)
- detect your capture interface
- let you select an installed Ollama model

```bash
sudo -H -E .venv/bin/python3 purplelab.py setup --guided
```

### 2) Run a fast demo (optional)

Great for validating your environment quickly:

```bash
python3 purplelab.py run demo
```

### 3) Run the full exercise

```bash
python3 purplelab.py run full
```

At the end, PurpleLab prints a **terminal summary panel** (coverage %, top IOCs, top mitigations) and writes:

`runs/<run_id>/report.md`

---

## CLI Commands

### Setup / checks
- `python3 purplelab.py init` — interactive config writer (no installs)
- `python3 purplelab.py setup --guided` — guided installer
- `python3 purplelab.py doctor` — basic health checks (Ollama reachable, sensors present)

### Run modes
- `python3 purplelab.py run demo` — fast run (short emulation)
- `python3 purplelab.py run full` — generate + emulate + collect + analyze + report
- `python3 purplelab.py run generate` — scenario generation only
- `python3 purplelab.py run emulate --run-id <id>` — emulation only
- `python3 purplelab.py run collect <id>` — collect logs only
- `python3 purplelab.py run analyze <id>` — AI analysis only
- `python3 purplelab.py run report <id>` — report generation only

### Show artifacts in terminal
- `python3 purplelab.py show summary --run-id <id>`
- `python3 purplelab.py show report --run-id <id>`
- `python3 purplelab.py show insights --run-id <id>`

---

## How this satisfies “Project 9” style requirements

This project demonstrates:

- **GenAI attack simulation** (scenario + plan generation via Ollama)
- **Attacker behavior emulation** (safe, non-destructive command execution)
- **Blue Team analysis** (collect + normalize sensor logs)
- **SOC L2 response** (IOCs + ATT&CK mapping + detection gaps + mitigations)
- **Final reporting** (coverage scoring + evidence + recommended defenses)

---

## Notes for GitHub

- Do **not** commit `runs/`, `logs/`, or `__pycache__/` — these are ignored via `.gitignore`.
- If you want screenshots in the report, add them under `runs/<run_id>/evidence/` and link them in `report.md`.

---

## Troubleshooting

### Ollama not reachable
- Ensure Ollama is running:
  - `ollama serve`
- Check:
  - `curl http://localhost:11434/api/tags`

### Suricata not producing alerts
- Confirm interface and permissions
- Run:
  - `sudo suricata -T -c /etc/suricata/suricata.yaml`

---

## License
Educational use.
