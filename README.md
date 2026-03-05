# GenAI Purple Team Lab

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

An automated **AI-assisted Purple Team simulation lab** that demonstrates how Generative AI can be used to simulate attacks, analyze logs, extract Indicators of Compromise (IOCs), evaluate detection coverage, and generate mitigation recommendations.

This project was created for a **Cybersecurity Capstone (Project 9)** focusing on using Generative AI to assist both **Red Team attack simulation** and **Blue Team defensive analysis**.

📖 Detailed system design: [Lab Architecture](LAB_ARCHITECTURE.md)

---

# Project Overview

Purple Teaming combines:

**Red Team**
Simulate realistic attack scenarios.

**Blue Team**
Detect, analyze, and respond to those attacks.

This project automates both sides using:

• Python automation
• Security log collection
• MITRE ATT&CK mapping
• AI analysis using **Ollama (local LLM)**
• Automated reporting and defensive recommendations

---

# Architecture Workflow

```
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
```

---

# Key Features

## AI Attack Simulation

Generates realistic attack scenarios using Generative AI.

Examples:

• Spearphishing simulation
• Command execution
• Reverse shell activity
• Credential access simulation

---

## Blue Team Log Analysis

The system collects logs such as:

• system logs
• network events
• security alerts
• command execution traces

AI then analyzes these logs to identify suspicious activity.

---

## MITRE ATT&CK Mapping

Detected activity is mapped to MITRE ATT&CK techniques such as:

• **T1566.001 – Spearphishing Attachment**
• **T1059.003 – Command Shell**
• **T1003 – Credential Dumping**

---

## Detection Coverage Scoring

The lab measures how well the simulated environment detects attacks.

Example:

| Technique | Emulated | Detected |
| --------- | -------- | -------- |
| T1566.001 | Yes      | Yes      |
| T1059.003 | Yes      | No       |

Detection Coverage:

```
2 / 3 techniques detected
Coverage: 66%
```

This helps demonstrate **security gaps**.

---

## AI Security Analysis

Using **Ollama**, the AI model analyzes logs and produces:

• Indicators of Compromise (IOCs)
• Detection gaps
• Threat analysis
• Defensive recommendations

Example output:

```
Indicators of Compromise
• suspicious-domain.xyz
• reverse shell to 10.10.10.5
• encoded PowerShell command
```

---

## AI Mitigation Recommendations

The AI also suggests defensive improvements such as:

• Implement DMARC and phishing filtering
• Add SIEM detection rules
• Monitor outbound traffic to unknown IPs
• Deploy endpoint monitoring

This demonstrates **SOC Level-2 response capabilities**.

---

# Project Structure

The repository is structured to separate orchestration logic, attack simulation, log collection, and AI analysis modules.

```
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
```

---

# Installation

## Lab Requirements

Recommended environment:

• Linux (Debian / Ubuntu / Kali)
• Python 3.9+
• Internet access for tool installation
• 8GB RAM recommended for local AI model

PurpleLab installs required tools automatically during setup.

---

## Clone the Repository

```bash
git clone https://github.com/titomazzetta/GenAi-Purpleteam.git
cd GenAi-Purpleteam
```

---

## Create Python Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Environment Setup

PurpleLab can automatically install required security tools and AI components.

Run the automated setup:

```bash
sudo python3 purplelab.py setup
```

This installs and configures:

• Suricata IDS
• Zeek Network Monitor
• Wazuh SIEM agent
• auditd host monitoring
• Ollama local AI engine
• Default AI model

---

# AI Model Selection

PurpleLab automatically selects the best available Ollama model:

1. llama3.1:8b-instruct (recommended)
2. mistral:7b-instruct (fallback)
3. phi3:mini (lightweight)

If the default model is unavailable, PurpleLab automatically falls back to the next model.

---

# Running the Purple Team Lab

## Verify Environment

```bash
python3 purplelab.py doctor
```

---

## Run Demo Simulation

```bash
python3 purplelab.py run demo
```

---

## Run Full Purple Team Simulation

```bash
python3 purplelab.py run full
```

The system will:

1. Generate an attack scenario
2. Execute the simulated attack
3. Collect system logs
4. Analyze logs using AI
5. Extract IOCs
6. Calculate detection coverage
7. Generate mitigation recommendations
8. Produce a final report

---

# Output Reports

Results are stored in:

```
runs/<timestamp>/report.md
```

Example report sections:

• Attack plan
• Attack timeline
• Indicators of compromise
• MITRE ATT&CK mapping
• Detection coverage score
• Recommended mitigations
• SOC analyst playbook

---

# Example Output

After a simulation completes, PurpleLab generates an incident analysis report.

Example location:

```
runs/2026-03-05/report.md
```

Example report contents:

• Attack timeline
• MITRE ATT&CK technique mapping
• Indicators of Compromise
• Detection coverage score
• Defensive recommendations

---

# Technologies Used

Python
Ollama (Local LLM)
MITRE ATT&CK Framework
Security Log Analysis
Generative AI

---

# Educational Purpose

This project demonstrates how Generative AI can assist in:

• automated red team simulation
• blue team log analysis
• security detection evaluation
• incident response recommendations

---

# License

MIT License
