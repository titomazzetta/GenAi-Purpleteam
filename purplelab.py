#!/usr/bin/env python3
"""
PurpleLab - Automated Purple Team Simulation with Generative AI
Single-VM version for Debian.
"""
import argparse
import logging
import sys
import os
import yaml
from modules import setup, emulation, collector, ai_analyzer, reporter

def load_config():
    with open("config/purplelab.yaml") as f:
        return yaml.safe_load(f)

def setup_logging(config, verbose):
    log_file = config['paths']['log_file']
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        filename=log_file,
        level=level,
        format='%(asctime)s %(levelname)s %(message)s'
    )

def main():
    parser = argparse.ArgumentParser(description="PurpleLab - Purple Team Automation with GenAI")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print detailed progress messages")
    subparsers = parser.add_subparsers(dest="command", required=True)

    setup_parser = subparsers.add_parser("setup", help="Install and configure all components")
    setup_parser.add_argument("--force", action="store_true", help="Reinstall even if already present")

    run_parser = subparsers.add_parser("run", help="Run exercise steps")
    run_sub = run_parser.add_subparsers(dest="run_type", required=True)

    run_full = run_sub.add_parser("full", help="Run complete exercise (generate, emulate, collect, analyze, report)")
    run_full.add_argument("--model", help="Override AI model (e.g., mistral:7b, phi3:mini)")

    run_gen = run_sub.add_parser("generate", help="Generate AI scenario only")
    run_gen.add_argument("--model", help="Override AI model")

    run_emu = run_sub.add_parser("emulate", help="Run local emulation only")
    run_emu.add_argument("--run-id", help="Existing run ID (optional)")

    run_col = run_sub.add_parser("collect", help="Collect and correlate logs")
    run_col.add_argument("run_id", help="Run ID")

    run_ana = run_sub.add_parser("analyze", help="Run AI analysis")
    run_ana.add_argument("run_id", help="Run ID")
    run_ana.add_argument("--model", help="Override AI model")

    run_rep = run_sub.add_parser("report", help="Generate final report")
    run_rep.add_argument("run_id", help="Run ID")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze an existing run")
    analyze_parser.add_argument("run_id", help="Run ID")
    analyze_parser.add_argument("--model", help="Override AI model")

    report_parser = subparsers.add_parser("report", help="Generate report for a run")
    report_parser.add_argument("run_id", help="Run ID")

    args = parser.parse_args()
    config = load_config()
    setup_logging(config, args.verbose)

    # Override AI model if provided
    if hasattr(args, 'model') and args.model:
        config['ai']['model'] = args.model
        if args.verbose:
            print(f"[VERBOSE] AI model set to: {args.model}")

    if args.command == "setup":
        setup.run(config, args.force, args.verbose)
    elif args.command == "run":
        if args.run_type == "full":
            if args.verbose: print("\n[PHASE 1] Generating AI scenario...")
            run_id = emulation.generate_scenario(config, args.verbose)
            if args.verbose: print("\n[PHASE 2] Executing local emulation...")
            emulation.run_local(config, run_id, args.verbose)
            if args.verbose: print("\n[PHASE 3] Collecting and correlating logs...")
            collector.collect(config, run_id, args.verbose)
            if args.verbose: print("\n[PHASE 4] Running AI analysis...")
            ai_analyzer.analyze(config, run_id, args.verbose)
            if args.verbose: print("\n[PHASE 5] Generating final report...")
            reporter.generate(config, run_id, args.verbose)
            print(f"\n✅ Full exercise complete. Run ID: {run_id}\nFinal report: runs/{run_id}/report.md")
        elif args.run_type == "generate":
            run_id = emulation.generate_scenario(config, args.verbose)
            print(f"Scenario generated. Run ID: {run_id}")
        elif args.run_type == "emulate":
            run_id = args.run_id or emulation.get_last_run_id(config)
            emulation.run_local(config, run_id, args.verbose)
        elif args.run_type == "collect":
            collector.collect(config, args.run_id, args.verbose)
        elif args.run_type == "analyze":
            ai_analyzer.analyze(config, args.run_id, args.verbose)
        elif args.run_type == "report":
            reporter.generate(config, args.run_id, args.verbose)
    elif args.command == "analyze":
        ai_analyzer.analyze(config, args.run_id, args.verbose)
    elif args.command == "report":
        reporter.generate(config, args.run_id, args.verbose)

if __name__ == "__main__":
    main()
