# GenAI Purple Team Lab

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

An automated **AI-assisted Purple Team simulation lab** for single-VM security testing that
simulates adversary behavior, collects multi-sensor telemetry, and performs
LLM-assisted defensive analysis with MITRE ATT&CK mapping and reporting.

This project was created for a **Cybersecurity Capstone (Project 9)**
focusing on using Generative AI to assist both **Red Team attack
simulation** and **Blue Team defensive analysis**.

📖 Detailed system design: [Lab Architecture](LAB_ARCHITECTURE.md)

### Suggested GitHub "About" text

`Automated purple team simulation on a single Debian/Kali VM — AI-generated attack scenarios, safe local emulation, multi-sensor log collection, and Ollama-powered defensive analysis with MITRE ATT&CK mapping.`

## Portfolio Highlights

- Built an end-to-end purple-team workflow in Python (scenario generation → emulation → collection → AI analysis → reporting)
- Integrated multi-source telemetry (Suricata, auditd, optional Zeek/Wazuh) into a normalized timeline
- Added MITRE ATT&CK technique mapping with detection coverage scoring to expose visibility gaps
- Implemented local-LLM analysis via Ollama with deterministic fallback handling for demo resilience
- Produced repeatable Markdown reports suitable for SOC-style incident review and capstone presentation

------------------------------------------------------------------------

# Project Overview

Purple Teaming combines:

### Red Team

Simulates realistic attack scenarios.

### Blue Team

Detects, analyzes, and responds to those attacks.

This project automates both sides using:

-   Python automation
-   Security log collection
-   MITRE ATT&CK mapping
-   AI analysis using **Ollama (local LLM)**
-   Automated reporting and defensive recommendations


## Why Ollama (Local AI) for this project

We chose **Ollama** because it is free to use locally, modular, and practical for capstone/lab workflows:

-   **No per-call API cost** for repeated demos and testing runs
-   **Offline-capable** operation inside a lab VM/network
-   **Data stays local** (logs and telemetry do not need to leave your environment)
-   **Model flexibility** (switch between models such as `mistral`, `llama3`, or `phi3`)
-   **Reproducibility** for grading/demo: same host, same model, same pipeline

### Advantages of running AI locally for Purple Team labs

-   Better control over sensitive log data
-   Lower latency from local inference calls
-   Fewer external dependency failures during demonstrations
-   Easier customization and tuning for defensive analysis prompts


------------------------------------------------------------------------

# Architecture Workflow

    Attack Simulation (Red Team)
            ↓
    System & Network Log Collection
            ↓
    AI Log Analysis (Ollama)
            ↓
    IOC Extraction + MITRE ATT&CK Mapping
            ↓
    Detection Coverage Scoring
            ↓
    AI-Generated Mitigation Recommendations
            ↓
    Automated Security Report

------------------------------------------------------------------------

# Key Features

## AI Attack Simulation

Generates realistic attack scenarios using Generative AI.

Examples:

-   Spearphishing simulation
-   Command execution
-   Reverse shell activity
-   Credential access simulation

------------------------------------------------------------------------

## Blue Team Log Analysis

The system collects logs such as:

-   system logs
-   network events
-   security alerts
-   command execution traces

AI then analyzes these logs to identify suspicious activity.

------------------------------------------------------------------------

## MITRE ATT&CK Mapping

Detected activity is mapped to MITRE ATT&CK techniques such as:

-   **T1566.001 -- Spearphishing Attachment**
-   **T1059.003 -- Command Shell**
-   **T1003 -- Credential Dumping**

------------------------------------------------------------------------

## Detection Coverage Scoring

Example:

  Technique   Emulated   Detected
  ----------- ---------- ----------
  T1566.001   Yes        Yes
  T1059.003   Yes        No

Detection Coverage:

    2 / 3 techniques detected
    Coverage: 66%

This demonstrates **security visibility gaps**.

## Sample Run Outcome (what reviewers should look for)

After a successful run (`python3 purplelab.py run demo` or `run full`), reviewers can verify:

- Timeline events captured in `runs/<timestamp>/processed/timeline.json`
- AI insights in `runs/<timestamp>/processed/ai_insights.json`
- Final report in `runs/<timestamp>/report.md`
- Coverage summary in terminal output (Detected vs Missed techniques)

Example checks:

``` bash
python3 purplelab.py show summary
python3 purplelab.py show report
```

------------------------------------------------------------------------

# AI Security Analysis

Using **Ollama**, the AI model analyzes logs and produces:

-   Indicators of Compromise (IOCs)
-   Detection gaps
-   Threat analysis
-   Defensive recommendations

Example:

    Indicators of Compromise

    • suspicious-domain.xyz
    • reverse shell to 10.10.10.5
    • encoded PowerShell command

------------------------------------------------------------------------

# Project Structure

    GenAi-Purpleteam
    │
    ├── purplelab.py
    │
    ├── modules
    │   ├── ai_analyzer.py
    │   ├── collector.py
    │   ├── emulation.py
    │   ├── reporter.py
    │   └── setup.py
    │
    ├── config
    │   └── purplelab.yaml
    │
    ├── requirements.txt
    ├── README.md
    └── LICENSE

------------------------------------------------------------------------

# Installation (Linux / Kali / Ubuntu)

Recommended environment:

-   Kali Linux
-   Ubuntu
-   Debian

Minimum Requirements:

-   Python 3.9+
-   8GB RAM recommended
-   Internet connection
-   sudo privileges

### ARM64 Kali on VMware Fusion (Mac Studio) checklist

If you are running Kali ARM64 in VMware Fusion on Apple Silicon, this project is compatible with that setup.
Use this quick checklist before running the lab:

-   Confirm architecture is ARM64:

``` bash
uname -m
```

Expected: `aarch64` or `arm64`

-   Ensure VMware guest tools are installed (improves VM networking and clock sync):

``` bash
sudo apt update
sudo apt install -y open-vm-tools open-vm-tools-desktop
```

-   Verify your VM NIC appears (often `ens33`, `eth0`, or similar):

``` bash
ip -br a
ip route
```

PurpleLab defaults to `interface: auto`, which is recommended for VMware environments.

------------------------------------------------------------------------

# Step 1 --- Install Ollama

PurpleLab requires **Ollama** for AI analysis.

Install:

``` bash
curl -fsSL https://ollama.com/install.sh | sh
```

Verify:

``` bash
ollama --version
```

Start the service:

``` bash
sudo systemctl start ollama
```

If systemctl is unavailable:

``` bash
ollama serve
```

------------------------------------------------------------------------

# Step 2 --- Download an AI Model

Recommended model:

``` bash
ollama pull llama3
```

Lightweight model:

``` bash
ollama pull phi3
```

Verify models:

``` bash
ollama list
```

------------------------------------------------------------------------

# Step 3 --- Clone the Repository

``` bash
git clone https://github.com/titomazzetta/GenAi-Purpleteam.git
cd GenAi-Purpleteam
```

------------------------------------------------------------------------

# Step 4 --- Create Python Virtual Environment

``` bash
python3 -m venv .venv
source .venv/bin/activate
```

Your prompt should now display:

    (.venv)

------------------------------------------------------------------------

# Step 5 --- Install Python Dependencies

``` bash
pip install --upgrade pip
pip install -r requirements.txt
```

------------------------------------------------------------------------

# Step 6 --- Verify Environment

``` bash
python3 purplelab.py doctor
```

Expected output:

    [Doctor] Basic health checks

    runs directory created
    Ollama reachable at localhost:11434

------------------------------------------------------------------------

# Running the Purple Team Lab

## Quick Demo

``` bash
python3 purplelab.py run demo
```

Notes for reliable demo detections:

- Run setup once first (`python3 purplelab.py setup`) so auditd/Suricata rules are in place.
- Demo mode uses deterministic safe steps that are easier to detect across ARM64 and x86_64.
- If coverage is still low, verify sensor services are running and that your user can read/export logs.
- Collection is non-blocking: if `sudo` needs a password, audit export is skipped instead of hanging.
- If Ollama is offline, PurpleLab now generates deterministic fallback insights + candidate IOCs from telemetry so results are still useful.
- For capstone/demo reliability, keep `ai.auto_pull_model: true` and set `ai.retries: 1` (or higher) in `config/purplelab.yaml`.

------------------------------------------------------------------------

## Full Purple Team Simulation

``` bash
python3 purplelab.py run full
```

The system will:

1.  Generate an AI attack scenario
2.  Execute simulated attack behavior
3.  Collect system logs
4.  Analyze logs using AI
5.  Extract IOCs
6.  Map activity to MITRE ATT&CK
7.  Calculate detection coverage
8.  Generate mitigation recommendations
9.  Produce a final report

------------------------------------------------------------------------

# Viewing Results

Reports are stored in:

    runs/<timestamp>/report.md

Example:

    runs/2026-03-05/report.md

Display results in terminal:

``` bash
python3 purplelab.py show summary
```

View full report:

``` bash
python3 purplelab.py show report
```

------------------------------------------------------------------------

# Technologies Used

-   Python
-   Ollama (Local LLM)
-   MITRE ATT&CK Framework
-   Security Log Analysis
-   Generative AI

------------------------------------------------------------------------

# Skills Demonstrated

- Python automation and CLI workflow design
- Detection engineering (Suricata/auditd/Zeek/Wazuh log handling)
- MITRE ATT&CK mapping and coverage analysis
- SOC-style incident triage and reporting
- Local LLM integration (Ollama), prompt engineering, and reliability safeguards
- Linux/VM lab setup and troubleshooting (including ARM64 VMware workflows)

------------------------------------------------------------------------

# Known Limitations and Roadmap

Current limitations:

- Single-host demo mode can underrepresent real multi-host enterprise traffic
- Detection fidelity depends on local sensor/service readiness and log permissions
- Local model quality/performance varies by available hardware and selected model

Planned improvements:

- Add baseline-vs-attack differential filtering for cleaner signal isolation
- Expand ATT&CK coverage with additional deterministic emulation steps
- Add optional SIEM export adapters and richer detection-rule validation
- Add benchmarked run artifacts (coverage trends and timing metrics)

------------------------------------------------------------------------

# Educational Purpose

This project demonstrates how Generative AI can assist in:

-   automated red team simulation
-   blue team log analysis
-   detection coverage evaluation
-   incident response recommendations

------------------------------------------------------------------------

# License

MIT License
