#!/usr/bin/env python3
"""PurpleLab — Automated Purple Team Simulation (Ollama-only)

What this CLI does
- Orchestrates a complete purple-team exercise end-to-end:
  1) Generate scenario (phishing pretext + ATT&CK plan) via Ollama
  2) Execute safe local emulation steps (Red Team behavior emulation)
  3) Collect telemetry from sensors (Blue Team detection view)
  4) Ask Ollama to produce SOC-grade insights + rules + IOCs
  5) Generate a portfolio-ready Markdown report

Operational Model
- Demo-first, single-VM workflow (emulation + sensors on one host).
- Designed to be headless and reproducible for GitHub / capstone grading.

Lab-only / educational use.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import Any, Dict

import yaml

from modules import setup, emulation, collector, ai_analyzer, reporter


BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║  PurpleLab — Automated Purple Team Simulation (Ollama-only)      ║
║  Safe, lab-only adversary emulation + detection + AI reporting   ║
╚══════════════════════════════════════════════════════════════════╝
"""


def load_config() -> Dict[str, Any]:
    """Load YAML config from config/purplelab.yaml."""
    cfg_path = os.path.join("config", "purplelab.yaml")
    if not os.path.exists(cfg_path):
        raise FileNotFoundError(
            f"Config not found at {cfg_path}. Did you copy config/purplelab.yaml into the repo?"
        )
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    # Defaults / forward-compatible flags
    cfg.setdefault("features", {})
    cfg.setdefault("ai", {})
    cfg["ai"].setdefault("provider", "ollama")
    cfg["ai"].setdefault("base_url", "http://localhost:11434")
    cfg["ai"].setdefault("timeout_s", 180)
    cfg["ai"].setdefault("retries", 1)
    cfg["ai"].setdefault("auto_pull_model", True)
    cfg.setdefault("paths", {})
    cfg["paths"].setdefault("runs_base", "./runs")
    cfg["paths"].setdefault("log_file", "./logs/purplelab.log")

    return cfg


def setup_logging(config: Dict[str, Any], verbose: bool) -> None:
    """Configure file-based logging; console output is kept human-friendly."""
    log_file = config['paths']['log_file']
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(filename=log_file, level=level, format='%(asctime)s %(levelname)s %(message)s')


def doctor(config: Dict[str, Any]) -> int:
    """Sanity checks for UX: config, folders, Ollama connectivity."""
    print("\n[Doctor] Basic health checks\n")

    # Runs folder
    runs_base = config.get("paths", {}).get("runs_base", "./runs")
    os.makedirs(runs_base, exist_ok=True)
    print(f"✅ runs directory: {runs_base}")

    # Ollama
    try:
        base_url = config.get("ai", {}).get("base_url", "http://localhost:11434").rstrip("/")
        model = config.get("ai", {}).get("model", "mistral")
        r = __import__("requests").get(f"{base_url}/api/tags", timeout=5)
        if r.status_code == 200:
            print(f"✅ Ollama reachable: {base_url}")
            tags = r.json() or {}
            models = [m.get("name") for m in tags.get("models", []) if isinstance(m, dict) and m.get("name")]
            if model in models or any((x or '').split(':',1)[0] == model.split(':',1)[0] for x in models):
                print(f"✅ Ollama model available: {model}")
            else:
                print(f"⚠️  Ollama reachable but model not found locally: {model}")
                print(f"   Fix: ollama pull {model}")
        else:
            print(f"⚠️  Ollama responded but unexpected status: {r.status_code}")
    except Exception as e:
        print(f"❌ Ollama not reachable: {e}")
        print("   Fix: ensure 'ollama serve' is running or run: sudo systemctl start ollama")
        return 2

    print("\n[Doctor] Done.\n")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="PurpleLab - Purple Team Automation (Ollama-only)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print detailed progress messages")

    subparsers = parser.add_subparsers(dest="command", required=True)

    setup_parser = subparsers.add_parser("setup", help="Install and configure components (sensors + optional Ollama)")
    setup_parser.add_argument("--force", action="store_true", help="Reinstall even if already present")
    setup_parser.add_argument(
        "--guided",
        action="store_true",
        help="Interactive guided installer (select features + Ollama model, then runs setup)",
    )

    subparsers.add_parser(
        "init",
        help="Interactive project initializer (writes config/purplelab.yaml without installing anything)",
    )

    doctor_parser = subparsers.add_parser("doctor", help="Run basic health checks")

    show_parser = subparsers.add_parser("show", help="Print key artifacts to the terminal")
    show_parser.add_argument("what", choices=["summary", "report", "insights"], help="What to display")
    show_parser.add_argument("--run-id", help="Run ID (defaults to last run)")

    run_parser = subparsers.add_parser("run", help="Run exercise steps")
    run_sub = run_parser.add_subparsers(dest="run_type", required=True)

    run_demo = run_sub.add_parser("demo", help="Fast demo run (shorter emulation) for quick validation")
    run_demo.add_argument("--model", help="Override Ollama model")

    run_full = run_sub.add_parser("full", help="Run complete exercise (generate, emulate, collect, analyze, report)")
    run_full.add_argument("--model", help="Override Ollama model (e.g., mistral, llama3, phi3)")

    run_gen = run_sub.add_parser("generate", help="Generate AI scenario only")
    run_gen.add_argument("--model", help="Override Ollama model")

    run_emu = run_sub.add_parser("emulate", help="Run local emulation only")
    run_emu.add_argument("--run-id", help="Existing run ID (optional)")

    run_col = run_sub.add_parser("collect", help="Collect and correlate logs")
    run_col.add_argument("run_id", help="Run ID")

    run_ana = run_sub.add_parser("analyze", help="Run AI analysis")
    run_ana.add_argument("run_id", help="Run ID")
    run_ana.add_argument("--model", help="Override Ollama model")

    run_rep = run_sub.add_parser("report", help="Generate final report")
    run_rep.add_argument("run_id", help="Run ID")

    args = parser.parse_args()

    print(BANNER)

    config = load_config()
    setup_logging(config, args.verbose)

    # Override model if provided
    if hasattr(args, 'model') and args.model:
        config['ai']['model'] = args.model
        if args.verbose:
            print(f"[VERBOSE] Ollama model set to: {args.model}")

    if args.command == "setup":
        if getattr(args, "guided", False):
            config = setup.guided_configure(config, verbose=args.verbose, write_config=True)
        setup.run(config, args.force, args.verbose)
        return

    if args.command == "init":
        setup.guided_configure(config, verbose=args.verbose, write_config=True)
        print("[+] Wrote config/purplelab.yaml. Next: python3 purplelab.py setup --guided OR python3 purplelab.py setup")
        return

    if args.command == "doctor":
        raise SystemExit(doctor(config))

    if args.command == "show":
        run_id = args.run_id or emulation.get_last_run_id(config)
        if not run_id:
            print("[!] No run found yet. Run: python3 purplelab.py run full")
            return
        if args.what == "summary":
            print(reporter.build_terminal_summary(config, run_id))
            return
        run_dir = f"{config['paths']['runs_base']}/{run_id}"
        if args.what == "report":
            path = f"{run_dir}/report.md"
        else:
            path = f"{run_dir}/processed/ai_insights.json"
        try:
            with open(path, "r", encoding="utf-8") as f:
                print(f.read())
        except Exception as e:
            print(f"[!] Unable to read {path}: {e}")
        return


    if args.command == "run":
        if args.run_type == "demo":
            # Demo = generate + emulate with first 2-3 steps only, then collect/analyze/report
            run_id = emulation.generate_scenario(config, args.verbose, demo_mode=True)
            emulation.run_local(config, run_id, args.verbose, max_steps=3)
            collector.collect(config, run_id, args.verbose)
            ai_analyzer.analyze(config, run_id, args.verbose)
            reporter.generate(config, run_id, args.verbose)
            print(reporter.build_terminal_summary(config, run_id))
            return

        if args.run_type == "full":
            if args.verbose:
                print("\n[PHASE 1] Generating AI scenario...")
            run_id = emulation.generate_scenario(config, args.verbose)

            if args.verbose:
                print("\n[PHASE 2] Executing local emulation...")
            emulation.run_local(config, run_id, args.verbose)

            if args.verbose:
                print("\n[PHASE 3] Collecting and correlating logs...")
            collector.collect(config, run_id, args.verbose)

            if args.verbose:
                print("\n[PHASE 4] Running AI analysis...")
            ai_analyzer.analyze(config, run_id, args.verbose)

            if args.verbose:
                print("\n[PHASE 5] Generating final report...")
            reporter.generate(config, run_id, args.verbose)

            print(reporter.build_terminal_summary(config, run_id))
            return

        if args.run_type == "generate":
            run_id = emulation.generate_scenario(config, args.verbose)
            print(f"Scenario generated. Run ID: {run_id}")
            return

        if args.run_type == "emulate":
            run_id = args.run_id or emulation.get_last_run_id(config)
            if not run_id:
                print("[!] No existing run found. Run: python3 purplelab.py run generate")
                return
            emulation.run_local(config, run_id, args.verbose)
            return

        if args.run_type == "collect":
            collector.collect(config, args.run_id, args.verbose)
            return

        if args.run_type == "analyze":
            ai_analyzer.analyze(config, args.run_id, args.verbose)
            return

        if args.run_type == "report":
            reporter.generate(config, args.run_id, args.verbose)
            return


if __name__ == "__main__":
    main()
