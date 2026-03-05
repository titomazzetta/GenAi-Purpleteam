"""Setup Module (PurpleLab) — Kali/Debian friendly

Purpose
- Installs and configures the sensor stack used for the Blue-Team detection view:
  Suricata (NIDS), Zeek (optional), and auditd (host audit).
- Optionally installs Wazuh (heavy) and Ollama (local LLM runtime).

Kali / Debian Compatibility
- Kali enforces PEP 668 for the system Python. Always use a virtualenv.
- Python deps are installed into the *currently running interpreter* via:
    sys.executable -m pip install -r requirements.txt

Safety
- Intended for an isolated lab VM only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any, Dict

import yaml


def _run(cmd, check=True, shell=False, verbose=False):
    if verbose:
        print(f"[*] {cmd if isinstance(cmd, str) else ' '.join(cmd)}")
    return subprocess.run(cmd, check=check, shell=shell)


def _detect_interface() -> str:
    """Best-effort: pick the default-route interface."""
    try:
        out = subprocess.check_output(["bash", "-lc", "ip route show default 2>/dev/null | awk '{print $5}' | head -n1"])  # noqa
        iface = out.decode().strip()
        return iface or "eth0"
    except Exception:
        return "eth0"


def _prompt_bool(prompt: str, default: bool) -> bool:
    d = "Y/n" if default else "y/N"
    while True:
        ans = input(f"{prompt} [{d}]: ").strip().lower()
        if not ans:
            return default
        if ans in {"y", "yes"}:
            return True
        if ans in {"n", "no"}:
            return False
        print("  Please enter y or n.")


def _prompt_choice(prompt: str, options: list[str], default_idx: int = 0) -> str:
    for i, opt in enumerate(options, start=1):
        mark = " (default)" if (i - 1) == default_idx else ""
        print(f"  {i}) {opt}{mark}")
    while True:
        ans = input(f"{prompt} [1-{len(options)}]: ").strip()
        if not ans:
            return options[default_idx]
        if ans.isdigit() and 1 <= int(ans) <= len(options):
            return options[int(ans) - 1]
        print("  Invalid selection.")


def _ollama_models(base_url: str, timeout_s: int = 3) -> list[str]:
    """Return local Ollama model tags if reachable; otherwise empty."""
    try:
        import requests

        r = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=timeout_s)
        if r.status_code != 200:
            return []
        data = r.json() or {}
        models = [m.get("name") for m in data.get("models", []) if m.get("name")]
        return sorted(set(models))
    except Exception:
        return []


def guided_configure(config: Dict[str, Any], verbose: bool = False, write_config: bool = True) -> Dict[str, Any]:
    """Interactive guided configuration.

    - Prompts for optional components
    - Selects interface (auto / explicit)
    - Selects Ollama model (from local tags if reachable, else common defaults)
    - Optionally writes config/purplelab.yaml
    """

    print("\n[Guided Installer] PurpleLab configuration\n")
    cfg = dict(config)
    cfg.setdefault("features", {})
    cfg.setdefault("lab", {})
    cfg.setdefault("ai", {})

    # Interface
    print("Interface for Suricata/Zeek capture:")
    iface_choice = _prompt_choice(
        "Select interface mode",
        options=["auto (recommended)", "eth0", "wlan0", "custom"],
        default_idx=0,
    )
    if iface_choice.startswith("auto"):
        cfg["lab"]["interface"] = "auto"
    elif iface_choice == "custom":
        cfg["lab"]["interface"] = input("Enter interface name (e.g., eth0): ").strip() or "eth0"
    else:
        cfg["lab"]["interface"] = iface_choice

    # Features
    print("\nOptional components:")
    cfg["features"]["install_ollama"] = _prompt_bool("Install/enable Ollama (local LLM runtime)?", True)
    cfg["features"]["install_zeek"] = _prompt_bool("Install Zeek (network telemetry, optional)?", True)
    cfg["features"]["install_wazuh"] = _prompt_bool("Install Wazuh (heavy SIEM/EDR stack, optional)?", False)

    # Ollama base URL
    cfg["ai"].setdefault("base_url", "http://localhost:11434")
    cfg["ai"].setdefault("timeout_s", 180)
    base_url = input(f"\nOllama base URL [{cfg['ai']['base_url']}]: ").strip() or cfg["ai"]["base_url"]
    cfg["ai"]["base_url"] = base_url

    # Model selection
    print("\nOllama model selection:")
    local_models = _ollama_models(base_url)
    common = ["mistral", "llama3", "phi3", "qwen2", "gemma2"]
    options = local_models if local_models else common
    if local_models:
        print("Detected locally available models from Ollama:")
        default_idx = 0
    else:
        print("Could not query local Ollama tags yet (or none installed). Choose a common model to pull:")
        default_idx = 0
    selected = _prompt_choice("Choose model", options=options, default_idx=default_idx)
    # Allow manual override
    manual = input(f"Use '{selected}'. Press Enter to accept, or type a different model tag: ").strip()
    cfg["ai"]["model"] = manual or selected

    # Write config
    if write_config:
        os.makedirs("config", exist_ok=True)
        path = os.path.join("config", "purplelab.yaml")
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, sort_keys=False)
        print(f"\n[+] Saved: {path}")

    if verbose:
        print("\n[VERBOSE] Final guided config:")
        print(yaml.safe_dump(cfg, sort_keys=False))

    return cfg


def run(config: Dict[str, Any], force: bool = False, verbose: bool = False) -> None:
    if verbose:
        print("[*] Starting PurpleLab setup (Kali/Debian)...")

    # System deps (run with sudo)
    _run(["sudo", "apt", "update"], verbose=verbose)
    deps = ["curl", "wget", "git", "jq", "nmap", "netcat-traditional", "python3-venv"]
    _run(["sudo", "apt", "install", "-y"] + deps, verbose=verbose)

    # Python deps into current interpreter (venv)
    if verbose:
        print("[*] Installing Python packages into current interpreter...")
    _run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], check=False, verbose=verbose)
    _run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], verbose=verbose)

    features = config.get("features", {})
    install_wazuh_enabled = bool(features.get("install_wazuh", False))
    install_zeek_enabled = bool(features.get("install_zeek", True))
    install_ollama_enabled = bool(features.get("install_ollama", True))

    if install_wazuh_enabled:
        install_wazuh(config, force, verbose)

    install_suricata(config, force, verbose)

    if install_zeek_enabled:
        install_zeek(config, force, verbose)

    install_auditd(config, force, verbose)
    add_custom_rules(config, verbose)

    if install_ollama_enabled:
        install_ollama(config, verbose)

    restart_services(install_wazuh_enabled, install_zeek_enabled, install_ollama_enabled, verbose)

    print("[+] Setup complete. Reboot recommended.")


def install_wazuh(config: Dict[str, Any], force: bool, verbose: bool) -> None:
    if force or not os.path.exists("/var/ossec"):
        print("[*] Installing Wazuh (this is heavy and can take a while)...")
        _run(["curl", "-sO", "https://packages.wazuh.com/4.9/wazuh-install.sh"], verbose=verbose)
        _run(["sudo", "bash", "wazuh-install.sh", "-a", "-i"], verbose=verbose)
        _run(["sudo", "tar", "-O", "-xf", "wazuh-install-files.tar"], check=False, verbose=verbose)
        print("[*] Wazuh installed. Save the printed credentials.")
    else:
        if verbose:
            print("[*] Wazuh already installed, skipping.")


def install_suricata(config: Dict[str, Any], force: bool, verbose: bool) -> None:
    if verbose:
        print("[*] Installing Suricata...")
    _run(["sudo", "apt", "install", "-y", "suricata"], verbose=verbose)

    iface = config.get("lab", {}).get("interface", "eth0")
    if iface == "auto":
        iface = _detect_interface()
        if verbose:
            print(f"[*] Auto-detected interface: {iface}")

    # Update suricata.yaml interface and enable community-id.
    # Note: This sed assumes the default packaged yaml includes 'interface: eth0'.
    _run(["sudo", "sed", "-i", f"s/interface: eth0/interface: {iface}/", "/etc/suricata/suricata.yaml"], check=False, verbose=verbose)
    _run(["sudo", "sed", "-i", "s/community-id: false/community-id: true/", "/etc/suricata/suricata.yaml"], check=False, verbose=verbose)

    if verbose:
        print("[*] Updating Suricata rules...")
    _run(["sudo", "suricata-update"], check=False, verbose=verbose)


def install_zeek(config: Dict[str, Any], force: bool, verbose: bool) -> None:
    if verbose:
        print("[*] Installing Zeek...")
    _run(["sudo", "apt", "install", "-y", "zeek"], check=False, verbose=verbose)

    iface = config.get("lab", {}).get("interface", "eth0")
    if iface == "auto":
        iface = _detect_interface()

    node_cfg = f"""[zeek]
type=standalone
host=localhost
interface={iface}
"""

    with open("/tmp/node.cfg", "w", encoding="utf-8") as f:
        f.write(node_cfg)
    _run(["sudo", "cp", "/tmp/node.cfg", "/etc/zeek/node.cfg"], check=False, verbose=verbose)

    if shutil.which("zeekctl"):
        if verbose:
            print("[*] Deploying Zeek...")
        _run(["sudo", "zeekctl", "deploy"], check=False, verbose=verbose)
    else:
        if verbose:
            print("[*] zeekctl not found; Zeek deploy skipped.")


def install_auditd(config: Dict[str, Any], force: bool, verbose: bool) -> None:
    if verbose:
        print("[*] Installing auditd...")
    _run(["sudo", "apt", "install", "-y", "auditd"], verbose=verbose)

    rules = """
-w /etc/shadow -p wa -k shadow_access
-w /etc/passwd -p wa -k passwd_access
-w /etc/sudoers -p wa -k sudoers_changes
-a always,exit -S execve -k process_execution
""".strip() + "\n"

    with open("/tmp/audit.rules", "w", encoding="utf-8") as f:
        f.write(rules)

    _run(["sudo", "cp", "/tmp/audit.rules", "/etc/audit/rules.d/purplelab.rules"], verbose=verbose)
    _run(["sudo", "augenrules", "--load"], check=False, verbose=verbose)


def add_custom_rules(config: Dict[str, Any], verbose: bool) -> None:
    if verbose:
        print("[*] Adding custom Suricata rule to generate a deterministic detection signal...")

    c2_rule = """
alert dns $HOME_NET any -> any any (msg:"PurpleLab: Simulated Malicious Domain Lookup"; content:"malicious.example.com"; nocase; classtype:trojan-activity; sid:1000001; rev:1;)
""".strip() + "\n"

    with open("/tmp/purplelab.rules", "w", encoding="utf-8") as f:
        f.write(c2_rule)

    _run(["sudo", "cp", "/tmp/purplelab.rules", "/etc/suricata/rules/purplelab.rules"], check=False, verbose=verbose)

    # Ensure it's included in suricata.yaml (best-effort).
    _run(
        [
            "sudo",
            "bash",
            "-lc",
            "grep -q 'purplelab.rules' /etc/suricata/suricata.yaml || sed -i '/rule-files:/a\\  - purplelab.rules' /etc/suricata/suricata.yaml",
        ],
        check=False,
        verbose=verbose,
    )


def install_ollama(config: Dict[str, Any], verbose: bool) -> None:
    if verbose:
        print("[*] Installing Ollama...")

    if not shutil.which("ollama"):
        # Correct way to run pipe via shell
        _run("curl -fsSL https://ollama.com/install.sh | sh", shell=True, verbose=verbose)

    model = config.get("ai", {}).get("model", "mistral")
    if verbose:
        print(f"[*] Pulling Ollama model: {model}")
    _run(["ollama", "pull", model], check=False, verbose=verbose)

    # Enable/start service if systemd is present
    if shutil.which("systemctl"):
        _run(["sudo", "systemctl", "enable", "ollama"], check=False, verbose=verbose)
        _run(["sudo", "systemctl", "start", "ollama"], check=False, verbose=verbose)

    if verbose:
        print("[+] Ollama is ready.")


def restart_services(wazuh: bool, zeek: bool, ollama: bool, verbose: bool) -> None:
    if verbose:
        print("[*] Restarting services...")

    services = ["suricata", "auditd"]
    if wazuh:
        services += ["wazuh-manager", "wazuh-agent"]
    if zeek:
        services += ["zeek"]
    if ollama:
        services += ["ollama"]

    for svc in services:
        _run(["sudo", "systemctl", "restart", svc], check=False, verbose=verbose)
