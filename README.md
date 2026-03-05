
# GenAI Purple Team Lab

An automated **AI‑assisted Purple Team simulation lab** that demonstrates how Generative AI can be used to simulate attacks, analyze logs, extract Indicators of Compromise (IOCs), evaluate detection coverage, and generate mitigation recommendations.

This project was created for a **Cybersecurity Capstone (Project 9)** focusing on using Generative AI to assist both **Red Team attack simulation** and **Blue Team defensive analysis**.

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
AI‑Generated Mitigation Recommendations
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

• **T1566.001** – Spearphishing Attachment  
• **T1059.003** – Command Shell  
• **T1003** – Credential Dumping  

---

## Detection Coverage Scoring

The lab measures how well the simulated environment detects attacks.

Example:

| Technique | Emulated | Detected |
|----------|----------|----------|
| T1566.001 | Yes | Yes |
| T1059.003 | Yes | No |

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

This demonstrates **SOC Level‑2 response capabilities**.

---

# Project Structure

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

## Clone the Repository

```
git clone https://github.com/titomazzetta/GenAi-Purpleteam.git
cd GenAi-Purpleteam
```

---

## Create Python Virtual Environment

```
python3 -m venv .venv
source .venv/bin/activate
```

---

## Install Dependencies

```
pip install -r requirements.txt
```

---

# Install Ollama

This project uses **Ollama** for local AI analysis.

Install Ollama:

https://ollama.ai

Pull a model:

```
ollama pull llama3
```

---

# Running the Purple Team Lab

## Verify Environment

```
python3 purplelab.py doctor
```

This checks:

• Python environment  
• AI connectivity  
• configuration settings

---

## Run Demo Simulation

```
python3 purplelab.py run demo
```

This runs a quick attack simulation and analysis.

---

## Run Full Purple Team Simulation

```
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

# Example Terminal Output

```
============================================
PURPLE LAB — AI DEFENSIVE ANALYSIS
============================================

Detection Coverage: 75%

Indicators of Compromise
• suspicious-domain.xyz
• reverse shell connection

Missed Detection
• T1059.003 Command Shell

Recommended Mitigations
• Implement email filtering
• Add SIEM rule for encoded PowerShell
• Monitor outbound reverse shell traffic

Report generated:
runs/2026-03-05/report.md
```

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
