"""Reporter Module (PurpleLab)

Purpose
- Builds a polished, portfolio-ready Markdown report from a run folder:
  scenario, emulation log, collected telemetry timeline, AI insights, IOCs, and rules.

Design goals
- Readable in GitHub
- Evidence-first (what happened, what was observed)
- Actionable (coverage score + gaps + mitigations)

Safety
- Defensive reporting only; no exploitation guidance.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Tuple


def _safe_read(path: str, default: Any):
    try:
        with open(path, "r", encoding="utf-8") as f:
            if path.endswith(".json"):
                return json.load(f)
            return f.read()
    except Exception:
        return default


def _coverage(attack_plan: List[Dict[str, Any]], timeline: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], str]:
    """Coverage = techniques emulated vs techniques detected by sensors.

    Important: only treat *sensor* sources as detections. Emulation logs should not count.
    """
    def _tid(raw: Any) -> str:
        text = str(raw or "").upper()
        m = re.search(r"T\d{4}(?:\.\d{3})?", text)
        return m.group(0) if m else ""

    emulated = {_tid(s.get("technique")) for s in (attack_plan or []) if _tid(s.get("technique"))}

    sensor_sources = {"suricata", "zeek", "auditd", "wazuh"}
    detected = {
        _tid(e.get("technique"))
        for e in (timeline or [])
        if _tid(e.get("technique")) and (e.get("source") in sensor_sources)
    }

    rows: List[Dict[str, Any]] = []
    for t in sorted([t for t in emulated if t]):
        rows.append({"technique": t, "emulated": True, "detected": t in detected})

    score = "N/A"
    if rows:
        det = sum(1 for r in rows if r["detected"])
        score = f"{det}/{len(rows)} ({int(round(100*det/len(rows)))}%)"
    return rows, score


def build_terminal_summary(config: Dict[str, Any], run_id: str) -> str:
    run_dir = f"{config['paths']['runs_base']}/{run_id}"
    attack_plan = _safe_read(f"{run_dir}/scenario/attack_plan.json", [])
    timeline = _safe_read(f"{run_dir}/processed/timeline.json", [])
    insights = _safe_read(f"{run_dir}/processed/ai_insights.json", {})

    coverage_rows, coverage_score = _coverage(attack_plan, timeline)

    # Pull key pieces from insights
    exec_sum = ""
    key_findings = []
    iocs = []
    mitigations = []
    gaps = []
    if isinstance(insights, dict):
        exec_sum = (insights.get("executive_summary") or "").strip()
        key_findings = insights.get("key_findings") or []
        iocs = insights.get("iocs") or []
        mitigations = insights.get("recommended_mitigations") or []
        gaps = insights.get("detection_gaps") or []

    def _fmt_bullets(items, limit=6):
        out = []
        for x in (items or [])[:limit]:
            if isinstance(x, str):
                out.append(f"• {x}")
            elif isinstance(x, dict):
                val = x.get("value") or x.get("id") or json.dumps(x)
                out.append(f"• {val}")
            else:
                out.append(f"• {str(x)}")
        return "\n".join(out) if out else "(none)"

    # Missed techniques from coverage
    missed = [r["technique"] for r in coverage_rows if not r["detected"]]

    summary = []
    summary.append("=" * 60)
    summary.append("PURPLE LAB — AI DEFENSIVE ANALYSIS SUMMARY")
    summary.append("=" * 60)
    if exec_sum:
        summary.append(exec_sum)
        summary.append("")

    summary.append(f"Detection Coverage: {coverage_score}")
    if missed:
        summary.append("Missed Techniques:")
        summary.append("\n".join([f"• {t}" for t in missed[:6]]))
    else:
        summary.append("Missed Techniques: (none)")

    summary.append("")
    summary.append("Top IOCs:")
    summary.append(_fmt_bullets(iocs, limit=6))

    summary.append("")
    if mitigations:
        summary.append("Recommended Mitigations:")
        summary.append(_fmt_bullets(mitigations, limit=6))
    else:
        summary.append("Recommended Mitigations: (none)")

    # Show 1–2 detection gaps if present
    if gaps:
        summary.append("")
        summary.append("Notable Detection Gaps:")
        for g in gaps[:2]:
            if isinstance(g, dict):
                tid = g.get("technique_id") or ""
                desc = g.get("gap_description") or ""
                rec = g.get("recommended_detection") or ""
                line = f"• {tid} {desc}".strip()
                summary.append(line)
                if rec:
                    summary.append(f"  ↳ {rec}")
            else:
                summary.append(f"• {str(g)}")

    report_path = f"{run_dir}/report.md"
    summary.append("")
    summary.append(f"Full report: {report_path}")
    return "\n".join(summary) + "\n"


def generate(config: Dict[str, Any], run_id: str, verbose: bool = False) -> None:
    if verbose:
        print("[VERBOSE] Generating final Markdown report...")

    run_dir = f"{config['paths']['runs_base']}/{run_id}"
    report_file = f"{run_dir}/report.md"

    email = _safe_read(f"{run_dir}/scenario/email_template.txt", "Not available")
    attack_plan = _safe_read(f"{run_dir}/scenario/attack_plan.json", [])
    emu_log = _safe_read(f"{run_dir}/emulation/emulation.log", "")
    timeline = _safe_read(f"{run_dir}/processed/timeline.json", [])
    insights = _safe_read(f"{run_dir}/processed/ai_insights.json", {})

    coverage_rows, coverage_score = _coverage(attack_plan, timeline)

    # Normalize insight fields
    def _get_list(key: str) -> List[Any]:
        if isinstance(insights, dict):
            v = insights.get(key) or []
            return v if isinstance(v, list) else []
        return []

    executive_summary = (insights.get("executive_summary") if isinstance(insights, dict) else "") or ""
    key_findings = _get_list("key_findings")
    iocs = _get_list("iocs")
    mitre = _get_list("mitre_techniques")
    gaps = _get_list("detection_gaps")
    mitigations = _get_list("recommended_mitigations")
    improvements = _get_list("defensive_improvements")
    playbook = _get_list("soc_playbook")
    awareness = _get_list("awareness_points")

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

    # Build report
    lines: List[str] = []
    lines.append(f"# PurpleLab Threat Simulation Report")
    lines.append("")
    lines.append(f"**Run ID:** `{run_id}`  ")
    lines.append(f"**Generated:** `{ts}`  ")
    lines.append("**Scope:** Lab-only purple-team simulation (safe emulation + detection + AI triage).  ")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 1. Scenario Overview (AI-generated)")
    lines.append("")
    lines.append("### Phishing Pretext (Template)")
    lines.append("```text")
    lines.append((email or "").strip() or "Not available")
    lines.append("```")
    lines.append("")
    lines.append("### ATT&CK-mapped Emulation Plan")
    lines.append("")
    if attack_plan:
        lines.append("| Step | Technique | Description |")
        lines.append("|---:|---|---|")
        for i, step in enumerate(attack_plan, start=1):
            tech = step.get("technique", "")
            desc = step.get("description", step.get("name", ""))
            lines.append(f"| {i} | `{tech}` | {desc} |")
    else:
        lines.append("(attack plan not available)")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 2. Emulation Evidence")
    lines.append("")
    lines.append("This section shows the local, non-destructive emulation commands executed to generate telemetry.")
    lines.append("")
    lines.append("```text")
    lines.append((emu_log or "").strip() or "(no emulation log)")
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 3. Blue Team Telemetry (Normalized Timeline)")
    lines.append("")
    if timeline:
        lines.append("| Timestamp | Source | Type | Technique | Summary |")
        lines.append("|---|---|---|---|---|")
        for e in timeline[:60]:
            ts_ = e.get("timestamp", "")
            src = e.get("source", "")
            et = e.get("event_type", "")
            tech = e.get("technique", "") or ""
            # short summary
            summ = ""
            if src == "suricata" and isinstance(e.get("alert"), dict):
                summ = e["alert"].get("signature", "alert")
            elif src == "wazuh":
                summ = str(e.get("rule") or e.get("decoder") or "alert")
            else:
                summ = str(e.get("summary") or "")
            summ = summ.replace("\n", " ")[:120]
            lines.append(f"| {ts_} | {src} | {et} | `{tech}` | {summ} |")
    else:
        lines.append("(no timeline events captured — verify sensors and rerun collection)")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 4. Detection Coverage Scoring")
    lines.append("")
    lines.append(f"**Coverage Score:** **{coverage_score}**  ")
    lines.append("")
    if coverage_rows:
        lines.append("| Technique | Emulated | Detected |")
        lines.append("|---|:---:|:---:|")
        for r in coverage_rows:
            lines.append(f"| `{r['technique']}` | ✅ | {'✅' if r['detected'] else '❌'} |")
    else:
        lines.append("(no ATT&CK techniques found in the emulation plan)")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 5. AI SOC Analysis (Ollama)")
    lines.append("")
    if executive_summary:
        lines.append("### Executive Summary")
        lines.append(executive_summary.strip())
        lines.append("")
    if key_findings:
        lines.append("### Key Findings")
        for f in key_findings:
            lines.append(f"- {f}")
        lines.append("")
    if iocs:
        lines.append("### Indicators of Compromise (IOCs)")
        lines.append("| Type | Value | Confidence | Notes |")
        lines.append("|---|---|---:|---|")
        for ioc in iocs:
            if not isinstance(ioc, dict):
                continue
            lines.append(
                f"| {ioc.get('type','')} | `{ioc.get('value','')}` | {ioc.get('confidence','')} | {ioc.get('notes','')} |"
            )
        lines.append("")
    if mitre:
        lines.append("### MITRE ATT&CK Mapping")
        lines.append("| Technique | Name | Why it matches | Evidence |")
        lines.append("|---|---|---|---|")
        for m in mitre:
            if not isinstance(m, dict):
                continue
            lines.append(
                f"| `{m.get('id','')}` | {m.get('name','')} | {m.get('why_it_matches','')} | {m.get('evidence','')} |"
            )
        lines.append("")
    if gaps:
        lines.append("### Detection Gaps (What was missed and how to detect next time)")
        for g in gaps:
            if isinstance(g, dict):
                lines.append(f"- **{g.get('technique_id','')}**: {g.get('gap_description','')}")
                if g.get("why_missed"):
                    lines.append(f"  - Why missed: {g.get('why_missed')}")
                if g.get("recommended_detection"):
                    lines.append(f"  - Recommended detection: {g.get('recommended_detection')}")
            else:
                lines.append(f"- {str(g)}")
        lines.append("")
    if mitigations:
        lines.append("### Recommended Mitigations (Prioritized)")
        for m in mitigations:
            lines.append(f"- {m}")
        lines.append("")
    if improvements:
        lines.append("### Defensive Improvements (Logging / Hardening / Controls)")
        for x in improvements:
            lines.append(f"- {x}")
        lines.append("")
    if playbook:
        lines.append("### SOC L2 Playbook (Suggested Response Steps)")
        for i, step in enumerate(playbook, start=1):
            lines.append(f"{i}. {step}")
        lines.append("")
    if awareness:
        lines.append("### Security Awareness Notes")
        for a in awareness:
            lines.append(f"- {a}")
        lines.append("")
    if isinstance(insights, dict) and insights.get("error"):
        lines.append("⚠️ AI analysis error:")
        lines.append(f"`{insights.get('error')}`")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 6. Artifacts")
    lines.append("")
    lines.append("- `processed/ai_insights.json` — raw AI JSON output")
    lines.append("- `iocs/iocs.stix.json` — IOC bundle (STIX 2.1 objects where applicable)")
    lines.append("- `rules/` — drafted Sigma and Suricata rules")
    lines.append("- `raw/` — copied sensor logs (best effort)")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 7. Limitations")
    lines.append("")
    lines.append("- This is a **single-host lab simulation**; enterprise environments will produce richer telemetry.")
    lines.append("- Some detections depend on sensors being installed and running (Suricata/Zeek/auditd/Wazuh).")

    os.makedirs(run_dir, exist_ok=True)
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).strip() + "\n")

    if verbose:
        print(f"[VERBOSE] Report written: {report_file}")
    print(f"[+] Report generated: {report_file}")
