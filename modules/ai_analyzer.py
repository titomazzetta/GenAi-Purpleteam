"""AI Analyzer Module (PurpleLab) — Ollama-only

Purpose
- Calls a locally running Ollama instance to produce structured, SOC-style outputs:
  executive summary, timeline, IOCs, MITRE mapping, and draft detection rules.

Design Notes
- Expects an "enriched_bundle.json" produced by modules/collector.py.
- JSON-mode responses are preferred so the downstream pipeline stays deterministic.

Security / Safety
- Lab-only educational analysis. No exploitation or malware generation.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import Any, Dict, Optional

import requests


def _heuristic_insights(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Fallback insights when Ollama is unavailable.

    Produces deterministic defensive output so runs still demonstrate value
    even if the local model/service is down.
    """
    timeline = bundle.get("timeline") if isinstance(bundle, dict) else []
    if not isinstance(timeline, list):
        timeline = []

    iocs = []
    seen = set()

    def add_ioc(ioc_type: str, value: str, notes: str) -> None:
        key = (ioc_type, value)
        if not value or key in seen:
            return
        seen.add(key)
        iocs.append({"type": ioc_type, "value": value, "confidence": "medium", "notes": notes})

    for e in timeline:
        if not isinstance(e, dict):
            continue
        dip = e.get("dest_ip")
        sip = e.get("src_ip")
        if isinstance(dip, str) and dip and dip not in {"127.0.0.1", "::1"}:
            add_ioc("ipv4-addr", dip, "Observed destination in captured telemetry")
        if isinstance(sip, str) and sip and sip not in {"127.0.0.1", "::1"}:
            add_ioc("ipv4-addr", sip, "Observed source in captured telemetry")

        dns = e.get("dns")
        if isinstance(dns, dict):
            q = dns.get("rrname") or dns.get("query")
            if isinstance(q, str):
                add_ioc("domain-name", q.strip('.'), "Observed DNS query")
        q2 = e.get("query")
        if isinstance(q2, str):
            add_ioc("domain-name", q2.strip('.'), "Observed DNS query")

        http = e.get("http")
        if isinstance(http, dict):
            host = http.get("hostname") or http.get("host")
            url = http.get("url")
            if isinstance(host, str) and isinstance(url, str) and host and url:
                add_ioc("url", f"http://{host}{url}", "Observed HTTP request")

        raw = str(e.get("raw") or "")
        if "/etc/shadow" in raw:
            add_ioc("file-path", "/etc/shadow", "Sensitive file access attempt observed")

    techniques = sorted({e.get("technique") for e in timeline if isinstance(e, dict) and e.get("technique")})
    findings = [f"Telemetry events analyzed: {len(timeline)}"]
    if techniques:
        findings.append("Observed ATT&CK techniques: " + ", ".join(techniques[:8]))
    if iocs:
        findings.append(f"Extracted {len(iocs)} candidate IOC(s) from telemetry without LLM dependency.")

    return {
        "executive_summary": "Fallback analysis was used because Ollama was unavailable. Findings were derived from collected telemetry using deterministic parsing.",
        "key_findings": findings,
        "iocs": iocs[:20],
        "mitre_techniques": [
            {
                "id": t,
                "name": "Observed technique",
                "why_it_matches": "Technique tag present in normalized timeline event.",
                "evidence": "timeline[].technique",
            }
            for t in techniques[:12]
        ],
        "detection_gaps": [],
        "recommended_mitigations": [
            "Ensure Suricata and auditd are running before demo execution.",
            "Tune collection scope to reduce noisy background telemetry.",
            "Run Ollama locally for richer contextual analysis and rule suggestions.",
        ],
        "defensive_improvements": [
            "Enable strict egress DNS/HTTP monitoring for high-signal detections.",
            "Forward normalized timeline data to SIEM with ATT&CK tags.",
        ],
        "soc_playbook": [
            "Validate sensor health (suricata/auditd/zeek) and log freshness.",
            "Review extracted IOC list and pivot across local logs.",
            "Correlate detected ATT&CK techniques with control coverage gaps.",
        ],
        "awareness_points": [
            "Phishing click simulation should trigger network telemetry.",
            "Credential-file access attempts should be monitored by host audit controls.",
        ],
        "sigma_rules": [],
        "suricata_rules": [],
        "analysis_mode": "heuristic_fallback",
    }




def _list_local_models(base_url: str, timeout_s: int = 5) -> list[str]:
    """Return model tags available in local Ollama."""
    r = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=timeout_s)
    r.raise_for_status()
    data = r.json() or {}
    return [m.get("name", "") for m in data.get("models", []) if isinstance(m, dict) and m.get("name")]


def _ensure_model_available(base_url: str, model: str, timeout_s: int = 5) -> None:
    """Ensure the configured model is present locally; try auto-pull if missing."""
    local = set(_list_local_models(base_url, timeout_s=timeout_s))
    if model in local:
        return

    # Accept either exact tag match or same base model family (e.g., mistral vs mistral:latest).
    base = model.split(":", 1)[0]
    if any(m.split(":", 1)[0] == base for m in local):
        return

    if not shutil.which("ollama"):
        raise RuntimeError(
            f"Ollama model '{model}' is not installed and 'ollama' CLI is not available to pull it."
        )

    pull = subprocess.run(["ollama", "pull", model], check=False, capture_output=True, text=True)
    if pull.returncode != 0:
        stderr = (pull.stderr or "").strip()[-500:]
        raise RuntimeError(f"Failed to pull Ollama model '{model}': {stderr or 'unknown error'}")


def _call_with_retry(base_url: str, model: str, prompt: str, json_mode: bool, timeout_s: int, retries: int) -> str:
    """Retry Ollama generate calls for transient local service hiccups."""
    last_err: Optional[Exception] = None
    attempts = max(1, retries + 1)
    for i in range(attempts):
        try:
            return _ollama_generate(base_url, model, prompt, json_mode=json_mode, timeout_s=timeout_s)
        except Exception as e:
            last_err = e
            if i < attempts - 1:
                time.sleep(1 + i)
                continue
            break
    assert last_err is not None
    raise last_err


def _ollama_generate(base_url: str, model: str, prompt: str, json_mode: bool, timeout_s: int) -> str:
    url = f"{base_url.rstrip('/')}/api/generate"

    payload: Dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }

    # Ollama supports "format":"json" which forces the model to return JSON.
    # The API still wraps that inside the "response" string.
    if json_mode:
        payload["format"] = "json"

    resp = requests.post(url, json=payload, timeout=timeout_s)
    resp.raise_for_status()

    data = resp.json()
    # Expected shape: {"response": "...", ...}
    return data.get("response", "")


def call_llm(config: Dict[str, Any], prompt: str, json_mode: bool = False) -> Any:
    """Call Ollama and return either a string (text mode) or a parsed JSON object (json_mode)."""
    ai_cfg = config.get("ai", {})

    provider = (ai_cfg.get("provider") or "ollama").lower()
    if provider != "ollama":
        raise ValueError(
            "This project is Ollama-only. Set ai.provider=ollama in config/purplelab.yaml."
        )

    base_url = ai_cfg.get("base_url", "http://localhost:11434")
    model = ai_cfg.get("model", "mistral")
    timeout_s = int(ai_cfg.get("timeout_s", 180))
    retries = int(ai_cfg.get("retries", 1))
    auto_pull_model = bool(ai_cfg.get("auto_pull_model", True))

    if auto_pull_model:
        _ensure_model_available(base_url, model, timeout_s=min(10, timeout_s))

    raw = _call_with_retry(base_url, model, prompt, json_mode=json_mode, timeout_s=timeout_s, retries=retries)

    if not json_mode:
        return raw

    # Robust JSON parsing: models sometimes wrap JSON in text.
    raw_str = raw.strip()
    try:
        return json.loads(raw_str)
    except Exception:
        # Try extracting the first JSON object/array from the text.
        start_obj = raw_str.find("{")
        start_arr = raw_str.find("[")
        starts = [s for s in [start_obj, start_arr] if s != -1]
        if not starts:
            raise
        start = min(starts)
        cut = raw_str[start:]
        return json.loads(cut)


def analyze(config: Dict[str, Any], run_id: str, verbose: bool = False) -> None:
    if verbose:
        print("[VERBOSE] Running AI analysis (Ollama) on enriched bundle...")

    run_dir = f"{config['paths']['runs_base']}/{run_id}"
    bundle_file = f"{run_dir}/processed/enriched_bundle.json"
    if not os.path.exists(bundle_file):
        print("[!] Enriched bundle not found. Run collection first.")
        return

    with open(bundle_file, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    # Keep prompt size bounded: the bundle is already trimmed.
    prompt = (
        "You are a senior SOC analyst performing incident triage on a *lab-only simulated* attack. "
        "Your job is to extract evidence, map to MITRE ATT&CK, and propose concrete defensive improvements.\n\n"
        "Return exactly ONE JSON object (no markdown, no extra text) with keys:\n"
        "1) executive_summary: string (2–4 sentences)\n"
        "2) key_findings: list of strings (bullets)\n"
        "3) iocs: list of {type,value,confidence,notes} where type in [ipv4-addr, domain-name, url, file-path, process, user, hash]\n"
        "4) mitre_techniques: list of {id,name,why_it_matches,evidence} (evidence should reference fields in the bundle)\n"
        "5) detection_gaps: list of {technique_id, gap_description, why_missed, recommended_detection}\n"
        "6) recommended_mitigations: list of strings (prioritized, practical)\n"
        "7) defensive_improvements: list of strings (logging, hardening, network controls)\n"
        "8) soc_playbook: ordered list of strings (step-by-step actions an L2 analyst should take)\n"
        "9) awareness_points: list of strings (end-user training takeaways)\n"
        "10) sigma_rules: list of strings (each is YAML)\n"
        "11) suricata_rules: list of strings (each is a Suricata rule)\n\n"
        "Constraints:\n"
        "- Keep recommendations safe and defensive (no offensive how-to).\n"
        "- Prefer realistic enterprise controls (EDR/SIEM, email security, DNS filtering, least privilege).\n\n"
        "Incident bundle (JSON):\n"
        f"{json.dumps(bundle, indent=2)}\n"
    )

    if verbose:

        print("[VERBOSE] Sending prompt to Ollama...")

    try:
        insights = call_llm(config, prompt, json_mode=True)
        if verbose:
            print("[VERBOSE] AI analysis received and parsed.")
    except Exception as e:
        print(f"[!] AI analysis failed: {e}")
        print("[!] Falling back to deterministic heuristic analysis.")
        insights = _heuristic_insights(bundle)
        insights["error"] = str(e)

    os.makedirs(f"{run_dir}/processed", exist_ok=True)
    with open(f"{run_dir}/processed/ai_insights.json", "w", encoding="utf-8") as f:
        json.dump(insights, f, indent=2)

    # Derive STIX bundle
    iocs = insights.get("iocs", []) if isinstance(insights, dict) else []
    stix_bundle = generate_stix(iocs)
    os.makedirs(f"{run_dir}/iocs", exist_ok=True)
    with open(f"{run_dir}/iocs/iocs.stix.json", "w", encoding="utf-8") as f:
        json.dump(stix_bundle, f, indent=2)

    # Save drafted rules
    os.makedirs(f"{run_dir}/rules", exist_ok=True)
    if isinstance(insights, dict) and "sigma_rules" in insights:
        for i, rule in enumerate(insights.get("sigma_rules", []) or []):
            with open(f"{run_dir}/rules/sigma_{i+1}.yml", "w", encoding="utf-8") as f:
                f.write(rule)

    if isinstance(insights, dict) and "suricata_rules" in insights:
        with open(f"{run_dir}/rules/suricata_custom.rules", "w", encoding="utf-8") as f:
            for rule in insights.get("suricata_rules", []) or []:
                f.write(rule.rstrip() + "\n")

    if verbose:
        print("[VERBOSE] Insights, STIX IOCs, and rules saved.")
    print(f"[+] AI analysis complete. Insights saved to {run_dir}/processed/ai_insights.json")


def _stable_id(prefix: str, value: str) -> str:
    # Stable-but-simple ID: not a real UUID, but consistent across runs for identical values.
    h = abs(hash(value)) % 10**10
    return f"{prefix}--{h:010d}"


def generate_stix(iocs: Any) -> Dict[str, Any]:
    objects = []
    if not isinstance(iocs, list):
        iocs = []

    for ioc in iocs:
        if not isinstance(ioc, dict):
            continue
        ioc_type = ioc.get("type")
        value = ioc.get("value")
        if not ioc_type or not value:
            continue

        if ioc_type == "ipv4-addr":
            objects.append(
                {
                    "type": "ipv4-addr",
                    "spec_version": "2.1",
                    "id": _stable_id("ipv4-addr", str(value)),
                    "value": str(value),
                }
            )
        elif ioc_type == "domain-name":
            objects.append(
                {
                    "type": "domain-name",
                    "spec_version": "2.1",
                    "id": _stable_id("domain-name", str(value)),
                    "value": str(value),
                }
            )
        elif ioc_type == "url":
            objects.append(
                {
                    "type": "url",
                    "spec_version": "2.1",
                    "id": _stable_id("url", str(value)),
                    "value": str(value),
                }
            )
        # file-path isn't a first-class STIX SCO; keep it out of STIX bundle for correctness.

    return {
        "type": "bundle",
        "id": _stable_id("bundle", json.dumps(objects, sort_keys=True)),
        "spec_version": "2.1",
        "objects": objects,
    }
