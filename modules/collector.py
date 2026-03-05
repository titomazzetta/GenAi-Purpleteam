"""
Collector module.
Copies raw logs from sensors, parses them, and builds a normalized timeline.
"""
import json
import os
import subprocess

def collect(config, run_id, verbose=False):
    if verbose: print("[VERBOSE] Collecting logs from sensors...")
    run_dir = f"{config['paths']['runs_base']}/{run_id}"
    raw_dir = f"{run_dir}/raw"
    processed_dir = f"{run_dir}/processed"
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(processed_dir, exist_ok=True)

    suricata_file = config['suricata']['eve_file']
    if os.path.exists(suricata_file):
        if verbose: print(f"[VERBOSE] Copying Suricata logs from {suricata_file}")
        subprocess.run(f"cp {suricata_file} {raw_dir}/suricata_eve.json", shell=True, check=False)

    zeek_dir = config['zeek']['log_dir']
    if os.path.exists(zeek_dir):
        if verbose: print(f"[VERBOSE] Copying Zeek logs from {zeek_dir}")
        subprocess.run(f"cp -r {zeek_dir} {raw_dir}/zeek", shell=True, check=False)

    audit_file = config['auditd']['log_file']
    if os.path.exists(audit_file):
        if verbose: print(f"[VERBOSE] Extracting audit logs (today) from {audit_file}")
        subprocess.run(f"sudo ausearch -ts today -r -f {audit_file} > {raw_dir}/audit.log 2>/dev/null", shell=True, check=False)

    wazuh_alerts = config['wazuh']['alerts_file']
    if os.path.exists(wazuh_alerts):
        if verbose: print(f"[VERBOSE] Copying Wazuh alerts from {wazuh_alerts}")
        subprocess.run(f"cp {wazuh_alerts} {raw_dir}/wazuh_alerts.json", shell=True, check=False)

    if verbose: print("[VERBOSE] Parsing logs and building timeline...")
    timeline = []
    parse_suricata(f"{raw_dir}/suricata_eve.json", timeline)
    parse_zeek(raw_dir, timeline)
    parse_audit(f"{raw_dir}/audit.log", timeline)
    parse_wazuh(f"{raw_dir}/wazuh_alerts.json", timeline)

    timeline.sort(key=lambda x: x.get('timestamp', ''))
    with open(f"{processed_dir}/timeline.json", "w") as f:
        json.dump(timeline, f, indent=2)

    enriched = {
        "run_id": run_id,
        "event_count": len(timeline),
        "techniques_observed": list(set(e.get('technique') for e in timeline if e.get('technique'))),
        "timeline": timeline[:50],
        "summary_stats": {
            "suricata_alerts": sum(1 for e in timeline if e.get('source') == 'suricata' and e.get('event_type') == 'alert'),
            "wazuh_alerts": sum(1 for e in timeline if e.get('source') == 'wazuh')
        }
    }
    with open(f"{processed_dir}/enriched_bundle.json", "w") as f:
        json.dump(enriched, f, indent=2)

    if verbose: print(f"[VERBOSE] Timeline has {len(timeline)} events. Enriched bundle saved.")
    print(f"[+] Collection complete. Timeline has {len(timeline)} events.")

def parse_suricata(file_path, timeline):
    if not os.path.exists(file_path):
        return
    with open(file_path) as f:
        for line in f:
            try:
                rec = json.loads(line)
                event = {
                    "timestamp": rec.get('timestamp', ''),
                    "source": "suricata",
                    "event_type": rec.get('event_type'),
                    "src_ip": rec.get('src_ip'),
                    "dest_ip": rec.get('dest_ip'),
                    "proto": rec.get('proto'),
                    "alert": rec.get('alert'),
                    "dns": rec.get('dns'),
                    "http": rec.get('http'),
                }
                if rec.get('alert') and rec['alert'].get('signature_id') == 1000001:
                    event['technique'] = "T1071.004"
                timeline.append(event)
            except:
                pass

def parse_zeek(raw_dir, timeline):
    conn_file = f"{raw_dir}/zeek/conn.log"
    if os.path.exists(conn_file):
        with open(conn_file) as f:
            for line in f:
                if line.startswith('#'):
                    continue
                parts = line.strip().split('\t')
                if len(parts) < 9:
                    continue
                event = {
                    "timestamp": parts[0],
                    "source": "zeek",
                    "event_type": "conn",
                    "src_ip": parts[2],
                    "dest_ip": parts[4],
                    "proto": parts[6],
                    "service": parts[7] if len(parts) > 7 else "",
                }
                timeline.append(event)
    dns_file = f"{raw_dir}/zeek/dns.log"
    if os.path.exists(dns_file):
        with open(dns_file) as f:
            for line in f:
                if line.startswith('#'):
                    continue
                parts = line.strip().split('\t')
                if len(parts) < 8:
                    continue
                event = {
                    "timestamp": parts[0],
                    "source": "zeek",
                    "event_type": "dns",
                    "src_ip": parts[2],
                    "dest_ip": parts[4],
                    "query": parts[8] if len(parts) > 8 else "",
                }
                timeline.append(event)

def parse_audit(file_path, timeline):
    if not os.path.exists(file_path):
        return
    with open(file_path) as f:
        for line in f:
            if "type=SYSCALL" in line:
                timestamp = line.split()[0] if line else ""
                event = {
                    "timestamp": timestamp,
                    "source": "auditd",
                    "event_type": "syscall",
                    "raw": line.strip()
                }
                if "shadow" in line:
                    event['technique'] = "T1003.008"
                timeline.append(event)

def parse_wazuh(file_path, timeline):
    if not os.path.exists(file_path):
        return
    with open(file_path) as f:
        for line in f:
            try:
                rec = json.loads(line)
                event = {
                    "timestamp": rec.get('timestamp'),
                    "source": "wazuh",
                    "event_type": "alert",
                    "rule_id": rec.get('rule', {}).get('id'),
                    "rule_description": rec.get('rule', {}).get('description'),
                    "technique": rec.get('rule', {}).get('mitre', {}).get('id', [None])[0] if rec.get('rule') else None,
                    "data": rec.get('data'),
                }
                timeline.append(event)
            except:
                pass
