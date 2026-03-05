"""Emulation Module (PurpleLab)

Purpose
- Generates a safe phishing scenario + ATT&CK-mapped attack plan using Ollama.
- Executes a *non-destructive* adversary emulation locally to generate realistic telemetry.

Safety / Guardrails
- No exploitation, malware, or persistence is performed.
- Commands are standard userland utilities intended to produce detection signals
  (e.g., HTTP requests, discovery commands, attempted /etc/shadow read).
- Designed to run in an isolated lab environment only.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime
from typing import Any, Dict, List

from . import ai_analyzer

# Default ATT&CK-mapped steps used if AI scenario generation fails.
# Each step is intentionally non-destructive and designed to generate telemetry.
DEFAULT_STEPS: List[Dict[str, str]] = [
    {
        "name": "Phishing Link Click",
        "technique": "T1566.001",
        "command": "curl -s http://{target}/phish.html || wget -q -O /dev/null http://{target}/phish.html",
        "description": "Simulate user clicking a malicious link in phishing email.",
    },
    {
        "name": "System Discovery",
        "technique": "T1082",
        "command": "uname -a; whoami; ip a; hostname",
        "description": "Gather system information.",
    },
    {
        "name": "User Discovery",
        "technique": "T1033",
        "command": "cat /etc/passwd; id; lastlog",
        "description": "Enumerate users.",
    },
    {
        "name": "Credential Access - /etc/shadow Attempt",
        "technique": "T1003.008",
        "command": "cat /etc/shadow",
        "description": "Attempt to read password hashes.",
    },
    {
        "name": "Network Scanning",
        "technique": "T1046",
        "command": "nmap -sT -p 22,80,443 {target} --open",
        "description": "Scan for open ports.",
    },
    {
        "name": "C2 DNS Beacon",
        "technique": "T1071.004",
        "command": "nslookup malicious.example.com; ping -c 1 malicious.example.com",
        "description": "Simulate DNS beacon to C2 server.",
    },
    {
        "name": "Reverse Shell Simulation",
        "technique": "T1071.001",
        "command": "nc -zv {target} 4444 || curl -s http://{target}:4444 || echo 'Simulated reverse shell'",
        "description": "Attempt connection to reverse shell listener.",
    },
]


def ping_target(ip: str, verbose: bool = False) -> bool:
    """Ping the target IP once to check reachability (best-effort)."""
    if verbose:
        print(f"[VERBOSE] Pinging {ip}...")
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, timeout=5)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def generate_scenario(config: Dict[str, Any], verbose: bool = False, demo_mode: bool = False) -> str:
    if verbose:
        print("[VERBOSE] Generating AI scenario (phishing email + attack plan) via Ollama...")

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = f"{config['paths']['runs_base']}/{run_id}"
    os.makedirs(f"{run_dir}/scenario", exist_ok=True)

    prompt = (
        "Generate a realistic phishing email targeting healthcare employees. "
        "Pretext: urgent patient record update. "
        "Also create a SAFE, lab-only post-click attack plan mapped to MITRE ATT&CK. "
        "Include these techniques somewhere in the plan: T1566.001, T1082, T1003.008, T1071.004.\n\n"
        "Return JSON with keys: email_subject, email_body, attack_steps. "
        f"attack_steps must be a list of {3 if demo_mode else 5} objects with: name, technique, description, command. "
        "Commands must be non-destructive and use standard Linux utilities only "
        "(curl/wget, uname/id/ip, cat, ls, nslookup/dig, nmap). "
        "Do NOT include reverse shells, persistence, or malware. "
        "Use {target} as the target placeholder in commands."
    )

    try:

        scenario = ai_analyzer.call_llm(config, prompt, json_mode=True)
        if not isinstance(scenario, dict) or "email_subject" not in scenario:
            raise ValueError("Unexpected scenario shape")
        if verbose:
            print("[VERBOSE] AI scenario generated successfully.")
    except Exception as e:
        print(f"[!] AI generation failed: {e}. Using default scenario.")
        scenario = {
            "email_subject": "URGENT: Patient Record Update Required",
            "email_body": "Dear employee,\n\nWe detected an issue with your patient records. Please verify your information immediately.\n\n[Link]\n\nIT Department",
            "attack_steps": DEFAULT_STEPS,
        }

    with open(f"{run_dir}/scenario/email_template.txt", "w", encoding="utf-8") as f:
        f.write(f"Subject: {scenario['email_subject']}\n\n{scenario['email_body']}")

    with open(f"{run_dir}/scenario/attack_plan.json", "w", encoding="utf-8") as f:
        json.dump(scenario.get("attack_steps", DEFAULT_STEPS), f, indent=2)

    if verbose:
        print(f"[VERBOSE] Scenario saved to {run_dir}/scenario/")
    return run_id


def run_local(config: Dict[str, Any], run_id: str, verbose: bool = False, max_steps: int | None = None) -> None:
    if not run_id:
        print("[!] No run_id provided. Generate a scenario first.")
        return

    if verbose:
        print("[VERBOSE] Starting local emulation...")

    run_dir = f"{config['paths']['runs_base']}/{run_id}"
    steps_file = f"{run_dir}/scenario/attack_plan.json"

    if not os.path.exists(steps_file):
        print("[!] Attack plan not found. Using default steps.")
        steps = DEFAULT_STEPS
    else:
        with open(steps_file, "r", encoding="utf-8") as f:
            steps = json.load(f)

    if isinstance(max_steps, int) and max_steps > 0:
        steps = (steps or [])[:max_steps]

    target = config.get('lab', {}).get('target_ip', '127.0.0.1')
    print(f"[*] Target configured as: {target}")

    # ICMP might be blocked; warn but continue.
    if not ping_target(target, verbose=verbose):
        print(f"[!] Ping to {target} failed (ICMP may be blocked). Continuing anyway...")

    os.makedirs(f"{run_dir}/emulation", exist_ok=True)
    log_file = f"{run_dir}/red_runlog.jsonl"
    text_log = f"{run_dir}/emulation/emulation.log"
    with open(log_file, "w", encoding="utf-8") as log, open(text_log, "w", encoding="utf-8") as tlog:
        for step in steps:
            cmd = (step.get('command') or '').format(target=target)
            name = step.get('name', 'Step')
            tech = step.get('technique', '')

            if verbose:
                print(f"[VERBOSE] Executing: {cmd}")
            print(f"[*] Executing: {name} ({tech})")
            tlog.write(f"[*] {name} ({tech})\n")

            start = datetime.utcnow().isoformat()
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                output = (result.stdout or '') + (result.stderr or '')
                exit_code = result.returncode
            except subprocess.TimeoutExpired as e:
                output = str(e)
                exit_code = -1
            except Exception as e:
                output = str(e)
                exit_code = -2
            end = datetime.utcnow().isoformat()

            # write a small excerpt to the text log for report readability
            excerpt = (output or "").strip().splitlines()
            excerpt = "\n".join(excerpt[:25])
            if excerpt:
                tlog.write(excerpt + "\n")
            tlog.write("\n")

            record = {
                "timestamp": start,
                "end_time": end,
                "name": name,
                "technique": tech,
                "command": cmd,
                "exit_code": exit_code,
                "output": output[:800],
            }
            log.write(json.dumps(record) + "\n")
            log.flush()
            time.sleep(1)

    if verbose:
        print(f"[VERBOSE] Emulation log saved to {log_file}")
    print(f"[+] Emulation complete. Log saved to {log_file}")


def get_last_run_id(config: Dict[str, Any]) -> str | None:
    runs_base = config['paths']['runs_base']
    if not os.path.exists(runs_base):
        return None
    runs = [d for d in os.listdir(runs_base) if os.path.isdir(os.path.join(runs_base, d))]
    if not runs:
        return None
    runs.sort(reverse=True)
    return runs[0]
