"""
Setup module for PurpleLab.
Handles installation and configuration of all sensors and Ollama.
"""
import subprocess
import os

def run(config, force=False, verbose=False):
    if verbose: print("[*] Starting PurpleLab setup on Debian...")
    subprocess.run(["sudo", "apt", "update"], check=True)
    deps = ["curl", "wget", "git", "python3-pip", "jq", "nmap", "netcat-traditional"]
    if verbose: print("[*] Installing system dependencies...")
    subprocess.run(["sudo", "apt", "install", "-y"] + deps, check=True)
    if verbose: print("[*] Installing Python packages...")
    subprocess.run(["pip3", "install", "-r", "requirements.txt"], check=True)
    install_wazuh(config, force, verbose)
    install_suricata(config, force, verbose)
    install_zeek(config, force, verbose)
    install_auditd(config, force, verbose)
    add_custom_rules(config, verbose)
    install_ollama(verbose)
    restart_services(verbose)
    print("[+] Setup complete. Reboot recommended.")

def install_wazuh(config, force, verbose):
    if force or not os.path.exists("/var/ossec"):
        if verbose: print("[*] Installing Wazuh 4.9...")
        subprocess.run(["curl", "-sO", "https://packages.wazuh.com/4.9/wazuh-install.sh"], check=True)
        subprocess.run(["sudo", "bash", "wazuh-install.sh", "-a", "-i"], check=True)
        subprocess.run(["sudo", "tar", "-O", "-xf", "wazuh-install-files.tar"], check=False)
        print("[*] Wazuh installed. Save the printed credentials.")
    else:
        if verbose: print("[*] Wazuh already installed, skipping.")

def install_suricata(config, force, verbose):
    if verbose: print("[*] Installing Suricata...")
    subprocess.run(["sudo", "apt", "install", "-y", "suricata"], check=True)
    iface = config['lab']['interface']
    subprocess.run(["sudo", "sed", "-i", f's/interface: eth0/interface: {iface}/', "/etc/suricata/suricata.yaml"], check=True)
    subprocess.run(["sudo", "sed", "-i", 's/community-id: false/community-id: true/', "/etc/suricata/suricata.yaml"], check=True)
    if verbose: print("[*] Updating Suricata rules...")
    subprocess.run(["sudo", "suricata-update"], check=True)

def install_zeek(config, force, verbose):
    if verbose: print("[*] Installing Zeek...")
    subprocess.run(["sudo", "apt", "install", "-y", "zeek"], check=True)
    iface = config['lab']['interface']
    node_cfg = f"""[zeek]
type=standalone
host=localhost
interface={iface}
"""
    with open("/tmp/node.cfg", "w") as f:
        f.write(node_cfg)
    subprocess.run(["sudo", "cp", "/tmp/node.cfg", "/etc/zeek/node.cfg"], check=True)
    if verbose: print("[*] Deploying Zeek...")
    subprocess.run(["sudo", "zeekctl", "deploy"], check=True)

def install_auditd(config, force, verbose):
    if verbose: print("[*] Installing auditd...")
    subprocess.run(["sudo", "apt", "install", "-y", "auditd"], check=True)
    rules = """
-w /etc/shadow -p wa -k shadow_access
-w /etc/passwd -p wa -k passwd_access
-w /etc/sudoers -p wa -k sudoers_changes
-a always,exit -S execve -k process_execution
"""
    with open("/tmp/audit.rules", "w") as f:
        f.write(rules)
    subprocess.run(["sudo", "cp", "/tmp/audit.rules", "/etc/audit/rules.d/custom.rules"], check=True)
    subprocess.run(["sudo", "augenrules", "--load"], check=True)

def add_custom_rules(config, verbose):
    if verbose: print("[*] Adding custom Suricata and Wazuh rules...")
    c2_rule = """
alert dns $HOME_NET any -> any any (msg:"Simulated Malicious Domain Lookup"; content:"malicious.example.com"; nocase; classtype:trojan-activity; sid:1000001; rev:1;)
"""
    with open("/tmp/custom.rules", "w") as f:
        f.write(c2_rule)
    subprocess.run(["sudo", "cp", "/tmp/custom.rules", "/etc/suricata/rules/custom.rules"], check=True)
    subprocess.run(["sudo", "sed", "-i", "/rule-files:/a   - custom.rules", "/etc/suricata/suricata.yaml"], check=True)

    wazuh_rule = """
<group name="credential_access,">
  <rule id="100050" level="10">
    <if_sid>510</if_sid>
    <field name="audit.file.name">shadow</field>
    <field name="audit.success">no</field>
    <description>Attempted access to /etc/shadow detected (possible credential dumping)</description>
    <mitre>
      <id>T1003.008</id>
    </mitre>
  </rule>
</group>
"""
    with open("/tmp/local_rules.xml", "w") as f:
        f.write(wazuh_rule)
    subprocess.run(["sudo", "cp", "/tmp/local_rules.xml", "/var/ossec/etc/rules/local_rules.xml"], check=True)
    subprocess.run(["sudo", "chown", "wazuh:wazuh", "/var/ossec/etc/rules/local_rules.xml"], check=True)

def install_ollama(verbose):
    if verbose: print("[*] Installing Ollama...")
    subprocess.run(["curl", "-fsSL", "https://ollama.com/install.sh", "|", "sh"], shell=True, check=True)
    if verbose: print("[*] Pulling Mistral 7B (4-bit quantized)... This may take a few minutes.")
    subprocess.run(["ollama", "pull", "mistral:7b"], check=True)
    subprocess.run(["sudo", "systemctl", "enable", "ollama"], check=True)
    subprocess.run(["sudo", "systemctl", "start", "ollama"], check=True)
    if verbose: print("[+] Ollama is ready. Mistral model loaded.")

def restart_services(verbose):
    if verbose: print("[*] Restarting services...")
    services = ["wazuh-manager", "wazuh-agent", "suricata", "zeek", "auditd", "ollama"]
    for svc in services:
        subprocess.run(["sudo", "systemctl", "restart", svc], check=False)
    if verbose: print("[*] All services restarted.")
