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
from datetime import datetime, timezone
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

    # auditd — best effort, non-blocking in non-interactive shells
    audit_file = config.get('auditd', {}).get('log_file', '/var/log/audit/audit.log')
    if os.path.exists(audit_file):
        if verbose:
            print("[VERBOSE] Exporting audit events from today...")

        audit_exported = False

        # Prefer passwordless sudo if available; never block on password prompt.
        if subprocess.run(["sudo", "-n", "true"], check=False).returncode == 0:
            rc = subprocess.run(
                ["bash", "-lc", f"sudo -n ausearch -ts today > '{raw_dir}/audit.log' 2>/dev/null"],
                check=False,
            ).returncode
            audit_exported = rc == 0 and os.path.exists(f"{raw_dir}/audit.log")

        # Fallback: direct file copy if readable by current user.
        if not audit_exported and os.access(audit_file, os.R_OK):
            subprocess.run(["bash", "-lc", f"cp '{audit_file}' '{raw_dir}/audit.log'"], check=False)
            audit_exported = os.path.exists(f"{raw_dir}/audit.log")

        if verbose and not audit_exported:
            print("[VERBOSE] Skipping audit export (no sudo -n access and audit log not readable).")

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

    # Reduce noisy historical events by keeping data near this run's emulation window.
    timeline = _filter_timeline_to_run_window(timeline, run_dir)

    timeline.sort(key=lambda x: x.get('timestamp', ''))
    max_events = int(config.get('ai', {}).get('max_events_for_ai', 200))
    if len(timeline) > max_events:
        timeline = timeline[-max_events:]
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
    if len(timeline) == 0:
        print("[!] Warning: No telemetry events were collected.")
        print("    Check sensors and permissions: suricata/auditd services, log paths, and sudo access for ausearch.")
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
                elif rec.get('event_type') == 'dns':
                    event['technique'] = "T1071.004"
                elif rec.get('event_type') == 'http':
                    event['technique'] = "T1071.001"
                elif rec.get('alert') and isinstance(rec.get('alert'), dict):
                    sig = str(rec['alert'].get('signature', '')).lower()
                    if 'nmap' in sig or 'scan' in sig:
                        event['technique'] = "T1046"

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
                elif "purplelab_payload_sim" in line:
                    event['technique'] = "T1105"
                elif "purplelab_revshell_sim" in line or "reverse-shell simulation" in line:
                    event['technique'] = "T1059.004"

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


def _parse_ts(ts: Any) -> Any:
    if not ts or not isinstance(ts, str):
        return None
    t = ts.strip()
    if not t:
        return None

    # Suricata commonly emits timezone as -0500 (no colon), while
    # datetime.fromisoformat expects -05:00 on some Python versions.
    if len(t) > 5 and (t[-5] in {'+', '-'}) and t[-3] != ':':
        t = t[:-2] + ':' + t[-2:]

    try:
        if t.endswith('Z'):
            return datetime.fromisoformat(t.replace('Z', '+00:00'))
        return datetime.fromisoformat(t)
    except Exception:
        return None


def _run_window(run_dir: str) -> Any:
    """Return (start,end) datetimes from emulation log if available."""
    path = f"{run_dir}/red_runlog.jsonl"
    if not os.path.exists(path):
        return None, None

    start = None
    end = None
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            st = _parse_ts(rec.get('timestamp'))
            et = _parse_ts(rec.get('end_time')) or st
            if st is not None and (start is None or st < start):
                start = st
            if et is not None and (end is None or et > end):
                end = et
    return start, end


def _filter_timeline_to_run_window(timeline: List[Dict[str, Any]], run_dir: str, grace_s: int = 120) -> List[Dict[str, Any]]:
    start, end = _run_window(run_dir)
    if start is None or end is None:
        return timeline

    filtered: List[Dict[str, Any]] = []
    for e in timeline:
        ts = _parse_ts(e.get('timestamp'))
        if ts is None:
            # Keep unparseable audit-like events only if they carry mapped technique.
            if e.get('source') == 'auditd' and e.get('technique'):
                filtered.append(e)
            continue
        if (start.timestamp() - grace_s) <= ts.timestamp() <= (end.timestamp() + grace_s):
            filtered.append(e)
    return filtered
