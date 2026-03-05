# GenAI Purple Team Lab

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

An automated **AI-assisted Purple Team simulation lab** that
demonstrates how Generative AI can simulate attacks, analyze logs,
extract Indicators of Compromise (IOCs), evaluate detection coverage,
and generate mitigation recommendations.

This project was created for a **Cybersecurity Capstone (Project 9)**
focusing on using Generative AI to assist both **Red Team attack
simulation** and **Blue Team defensive analysis**.

📖 Detailed system design: [Lab Architecture](LAB_ARCHITECTURE.md)

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

# Educational Purpose

This project demonstrates how Generative AI can assist in:

-   automated red team simulation
-   blue team log analysis
-   detection coverage evaluation
-   incident response recommendations

------------------------------------------------------------------------

# License

MIT License
