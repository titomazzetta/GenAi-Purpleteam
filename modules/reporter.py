"""
Reporter module.
Generates a Markdown report from all collected artifacts.
"""
import json
import os
from datetime import datetime

def generate(config, run_id, verbose=False):
    if verbose: print("[VERBOSE] Generating final Markdown report...")
    run_dir = f"{config['paths']['runs_base']}/{run_id}"
    report_file = f"{run_dir}/report.md"

    try:
        with open(f"{run_dir}/scenario/email_template.txt") as f:
            email = f.read()
    except:
        email = "Not available"

    try:
        with open(f"{run_dir}/scenario/attack_plan.json") as f:
            attack_plan = json.load(f)
    except:
        attack_plan = []

    try:
        with open(f"{run_dir}/processed/timeline.json") as f:
            timeline = json.load(f)
    except:
        timeline = []

    try:
        with open(f"{run_dir}/processed/ai_insights.json") as f:
            insights = json.load(f)
    except:
        insights = {}

    try:
        with open(f"{run_dir}/iocs/iocs.stix.json") as f:
            stix = json.load(f)
    except:
        stix = {}

    report = f"""# Purple Team Exercise Report – {run_id}

## Executive Summary
{insights.get('executive_summary', 'N/A')}

## Environment
- **Blue VM (Debian)**: Sensors: Wazuh, Suricata, Zeek, auditd
- **Red Emulation**: Local execution on same VM
- **Network**: Isolated lab network ({config['lab']['subnet']})

## Attack Simulation (Red Team)
The following steps were executed locally, simulating a phishing attack:

| Step | MITRE ATT&CK | Description | Command |
|------|--------------|-------------|---------|
"""
    for step in attack_plan:
        report += f"| {step.get('name','')} | {step.get('technique','')} | {step.get('description','')} | `{step.get('command','')}` |\n"

    report += f"""
## Detection Timeline (Blue Team)
Total events collected: {len(timeline)}

| Timestamp | Source | Event Type | Details | MITRE |
|-----------|--------|------------|---------|-------|
"""
    for event in timeline[:30]:
        ts = event.get('timestamp', '')[:19]
        src = event.get('source', '')
        etype = event.get('event_type', '')
        details = ""
        if etype == 'alert' and 'rule_description' in event:
            details = event['rule_description']
        elif etype == 'dns' and 'query' in event:
            details = f"DNS query: {event['query']}"
        elif etype == 'http':
            details = "HTTP request"
        tech = event.get('technique', '')
        report += f"| {ts} | {src} | {etype} | {details} | {tech} |\n"

    report += f"""
## Indicators of Compromise (IOCs)
| Type | Value | Confidence |
|------|-------|------------|
"""
    for ioc in insights.get('iocs', []):
        report += f"| {ioc.get('type','')} | {ioc.get('value','')} | {ioc.get('confidence','')} |\n"

    report += f"""
## MITRE ATT&CK Techniques Observed
| Technique ID | Name | Explanation |
|--------------|------|-------------|
"""
    for tech in insights.get('mitre_techniques', []):
        report += f"| {tech.get('id','')} | {tech.get('name','')} | {tech.get('explanation','')} |\n"

    report += f"""
## Defensive Recommendations

### Hardening Measures
"""
    for measure in insights.get('hardening_measures', []):
        report += f"- {measure}\n"

    report += f"""
### Awareness Training Points
"""
    for point in insights.get('awareness_points', []):
        report += f"- {point}\n"

    report += f"""
### Detection Rules

#### Sigma Rules
"""
    for rule in insights.get('sigma_rules', []):
        report += f"```yaml\n{rule}\n```\n\n"

    report += f"""
#### Suricata Rules
"""
    for rule in insights.get('suricata_rules', []):
        report += f"```\n{rule}\n```\n\n"

    report += f"""
## Appendix
- **Raw logs**: `runs/{run_id}/raw/`
- **STIX IOC bundle**: `runs/{run_id}/iocs/iocs.stix.json`
- **AI insights JSON**: `runs/{run_id}/processed/ai_insights.json`

---
*Report generated automatically by PurpleLab on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""

    with open(report_file, "w") as f:
        f.write(report)

    if verbose: print(f"[VERBOSE] Report saved to {report_file}")
    print(f"[+] Report generated: {report_file}")
