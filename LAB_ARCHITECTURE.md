
# PurpleLab Architecture

This document explains the architecture of the **GenAI Purple Team Lab** and how the different components interact to simulate attacks and analyze security telemetry.

---

# Lab Overview

The lab simulates both sides of a cybersecurity engagement:

• **Red Team** – Simulates attacker behavior  
• **Blue Team** – Detects and analyzes attack activity  
• **AI Engine** – Assists with threat analysis and reporting

The system is designed to run in a **controlled lab environment** using virtual machines.

---

# Lab Topology

Recommended setup:

RED TEAM VM (Kali Linux)  
Simulated attacker environment

BLUE TEAM VM (Debian / Ubuntu)  
Detection + AI analysis environment

Both machines communicate over a **private lab network**.

Example network:

10.10.10.0/24

---

# System Architecture

             RED TEAM VM
        (Attack Simulation Host)
                   │
                   │ simulated attacks
                   ▼

             BLUE TEAM VM
        (Detection & AI Analysis)

    ┌───────────────────────────────┐
    │ Suricata  – Network IDS       │
    │ Zeek      – Network telemetry │
    │ Wazuh     – SIEM alerts       │
    │ auditd    – Host monitoring   │
    │ Ollama    – AI analysis       │
    └───────────────────────────────┘
                   │
                   ▼
            PurpleLab Engine

         IOC Extraction
         MITRE ATT&CK Mapping
         Detection Coverage
         Mitigation Advice

                   ▼
            Security Report

---

# PurpleLab Modules

purplelab.py  
Main CLI entry point controlling the simulation.

modules/emulation.py  
Runs adversary emulation techniques.

modules/collector.py  
Collects system and network telemetry.

modules/ai_analyzer.py  
Uses a local LLM to analyze events and extract security insights.

modules/reporter.py  
Generates the final incident analysis report.

modules/setup.py  
Automates installation of required lab tools.

---

# Detection Stack

The Blue Team VM includes the following detection tools:

Suricata  
Network Intrusion Detection System.

Zeek  
Deep network telemetry and protocol analysis.

Wazuh  
Security Information and Event Management (SIEM).

auditd  
Linux host monitoring and command execution logging.

These tools produce the logs analyzed by the AI engine.

---

# AI Analysis Engine

The project uses **Ollama** to run a local large language model.

Models supported:

• llama3.1:8b-instruct (recommended)  
• mistral:7b-instruct  
• phi3:mini

The AI engine performs:

• IOC extraction  
• threat analysis  
• MITRE ATT&CK technique mapping  
• detection gap analysis  
• mitigation recommendations

---

# Security Reporting

At the end of the simulation PurpleLab generates a report containing:

• attack scenario  
• attack timeline  
• extracted indicators of compromise  
• MITRE ATT&CK mappings  
• detection coverage score  
• defensive recommendations

Reports are saved in:

runs/<timestamp>/report.md

---

# Design Goals

This project was designed to demonstrate:

• purple team automation  
• AI‑assisted security analysis  
• detection engineering concepts  
• SOC Level‑2 investigation workflows  
• reproducible cybersecurity labs

---

# Educational Use

PurpleLab is intended for:

• cybersecurity education  
• lab demonstrations  
• detection engineering practice  
• red/blue team training

All attack simulations are **safe and controlled** and should only be run in a **lab environment**.
