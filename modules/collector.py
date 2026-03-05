"""Collector Module (PurpleLab)

Purpose
- Copies telemetry from host-based and network sensors into a per-run folder.
- Normalizes multi-source logs (Suricata EVE, Zeek, auditd, optional Wazuh) into a unified timeline.
- Produces a small "enriched bundle" for LLM analysis (size-bounded for prompt efficiency).

Key Outputs (per run)
- runs/<run_id>/raw/*            Raw sensor logs (best-effort copies).
- runs/<run_id>/processed/*      timeline.json and enriched_bundle.json.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, List


def collect(config: Dict[str, Any], run_id: str, verbose: bool = False) -> None:
    if verbose:
        print("[VERBOSE] Collecting logs from sensors...")

    run_dir = f"{config['paths']['runs_base']}/{run_id}"
    raw_dir = f"{run_dir}/raw"
    processed_dir = f"{run_dir}/processed"
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(processed_dir, exist_ok=True)

    # Suricata
    suricata_file = config.get('suricata', {}).get('eve_file', '/var/log/suricata/eve.json')
    if os.path.exists(suricata_file):
        if verbose:
            print(f"[VERBOSE] Copying Suricata logs from {suricata_file}")
        subprocess.run(["bash", "-lc", f"cp '{suricata_file}' '{raw_dir}/suricata_eve.json'"], check=False)

    # Zeek
    zeek_dir = config.get('zeek', {}).get('log_dir', '/var/log/zeek/current/')
    if os.path.exists(zeek_dir):
        if verbose:
            print(f"[VERBOSE] Copying Zeek logs from {zeek_dir}")
        subprocess.run(["bash", "-lc", f"cp -r '{zeek_dir}' '{raw_dir}/zeek'"], check=False)

    # auditd — best effort
    audit_file = config.get('auditd', {}).get('log_file', '/var/log/audit/audit.log')
    if os.path.exists(audit_file):
        if verbose:
            print("[VERBOSE] Exporting audit events from today...")
        # ausearch reads from audit subsystem; do not pass the log path as -f (that's a file filter).
        subprocess.run(
            ["bash", "-lc", f"sudo ausearch -ts today > '{raw_dir}/audit.log' 2>/dev/null"],
            check=False,
        )

    # Wazuh (optional)
    wazuh_alerts = config.get('wazuh', {}).get('alerts_file', '/var/ossec/logs/alerts/alerts.json')
    if os.path.exists(wazuh_alerts):
        if verbose:
            print(f"[VERBOSE] Copying Wazuh alerts from {wazuh_alerts}")
        subprocess.run(["bash", "-lc", f"cp '{wazuh_alerts}' '{raw_dir}/wazuh_alerts.json'"], check=False)

    if verbose:
        print("[VERBOSE] Parsing logs and building timeline...")

    timeline: List[Dict[str, Any]] = []
    parse_suricata(f"{raw_dir}/suricata_eve.json", timeline)
    parse_zeek(raw_dir, timeline)
    parse_audit(f"{raw_dir}/audit.log", timeline)
    parse_wazuh(f"{raw_dir}/wazuh_alerts.json", timeline)

    timeline.sort(key=lambda x: x.get('timestamp', ''))
    with open(f"{processed_dir}/timeline.json", "w", encoding="utf-8") as f:
        json.dump(timeline, f, indent=2)

    enriched = {
        "run_id": run_id,
        "event_count": len(timeline),
        "techniques_observed": sorted(list({e.get('technique') for e in timeline if e.get('technique')})),
        "timeline": timeline[:50],
        "summary_stats": {
            "suricata_alerts": sum(
                1 for e in timeline if e.get('source') == 'suricata' and e.get('event_type') == 'alert'
            ),
            "wazuh_alerts": sum(1 for e in timeline if e.get('source') == 'wazuh'),
        },
    }

    with open(f"{processed_dir}/enriched_bundle.json", "w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2)

    if verbose:
        print(f"[VERBOSE] Timeline has {len(timeline)} events. Enriched bundle saved.")
    print(f"[+] Collection complete. Timeline has {len(timeline)} events.")


def parse_suricata(file_path: str, timeline: List[Dict[str, Any]]) -> None:
    if not os.path.exists(file_path):
        return

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                event: Dict[str, Any] = {
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

                # Deterministic mapping for our custom rule
                if rec.get('alert') and rec['alert'].get('signature_id') == 1000001:
                    event['technique'] = "T1071.004"  # DNS

                timeline.append(event)
            except Exception:
                continue


def parse_zeek(raw_dir: str, timeline: List[Dict[str, Any]]) -> None:
    conn_file = f"{raw_dir}/zeek/conn.log"
    if os.path.exists(conn_file):
        with open(conn_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith('#'):
                    continue
                parts = line.strip().split('\t')
                if len(parts) < 9:
                    continue
                timeline.append(
                    {
                        "timestamp": parts[0],
                        "source": "zeek",
                        "event_type": "conn",
                        "src_ip": parts[2],
                        "dest_ip": parts[4],
                        "proto": parts[6],
                        "service": parts[7] if len(parts) > 7 else "",
                    }
                )

    dns_file = f"{raw_dir}/zeek/dns.log"
    if os.path.exists(dns_file):
        with open(dns_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith('#'):
                    continue
                parts = line.strip().split('\t')
                if len(parts) < 9:
                    continue
                timeline.append(
                    {
                        "timestamp": parts[0],
                        "source": "zeek",
                        "event_type": "dns",
                        "src_ip": parts[2],
                        "dest_ip": parts[4],
                        "query": parts[8] if len(parts) > 8 else "",
                    }
                )


def parse_audit(file_path: str, timeline: List[Dict[str, Any]]) -> None:
    if not os.path.exists(file_path):
        return

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "type=SYSCALL" in line or "type=PATH" in line:
                # ausearch output starts with something like: "----" then "time->" lines;
                # keep raw chunk timestamps best-effort.
                timestamp = ""
                if "time->" in line:
                    timestamp = line.split("time->", 1)[-1].strip()

                event: Dict[str, Any] = {
                    "timestamp": timestamp,
                    "source": "auditd",
                    "event_type": "audit",
                    "raw": line.strip(),
                }

                if "/etc/shadow" in line or "shadow" in line:
                    event['technique'] = "T1003.008"

                timeline.append(event)


def parse_wazuh(file_path: str, timeline: List[Dict[str, Any]]) -> None:
    if not os.path.exists(file_path):
        return

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                rule = rec.get('rule', {}) or {}
                mitre = rule.get('mitre', {}) or {}
                mitre_ids = mitre.get('id', []) if isinstance(mitre.get('id', []), list) else []

                timeline.append(
                    {
                        "timestamp": rec.get('timestamp'),
                        "source": "wazuh",
                        "event_type": "alert",
                        "rule_id": rule.get('id'),
                        "rule_description": rule.get('description'),
                        "technique": mitre_ids[0] if mitre_ids else None,
                        "data": rec.get('data'),
                    }
                )
            except Exception:
                continue
