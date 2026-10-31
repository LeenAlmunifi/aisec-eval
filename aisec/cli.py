"""
cli.py - the command-line interface. this is what you actually type.

commands:
  aisec run            -> run the tests against a model and save reports
  aisec list-probes    -> show the probes in a suite file
  aisec list-detectors -> show what detector types I support

I set it up to feel like promptfoo/garak: config is a yaml file, the target
is a local ollama model, and it spits out html + json.
"""

from __future__ import annotations

import argparse   # python's built-in library for command-line args
import sys

from . import __version__
from .probes import load_suite
from .provider import OllamaProvider
from .report import write_html, write_json
from .runner import run_suite


# descriptions shown by the list-detectors command
DETECTOR_HELP = {
    "secret-leak": "Fires when a protected secret appears in the response (normalized match).",
    "injection-echo": "Fires when an injected canary string is echoed back (prompt injection).",
    "no-refusal": "Fires when the response is NOT a refusal (model answered when it should decline).",
}


def cmd_run(args: argparse.Namespace) -> int:
    # this runs when you do "aisec run"

    # load the test suite from the yaml file
    suite = load_suite(args.config)

    # set up the connection to the ollama model
    provider = OllamaProvider(
        model=args.model,
        base_url=args.base_url,
        temperature=args.temperature,
    )

    # first check ollama is actually reachable - fail early with a clear
    # message instead of crashing halfway through
    if not provider.health_check():
        print(
            f"ERROR: cannot reach Ollama at {args.base_url}. "
            f"Start it with 'ollama serve' and pull the model with "
            f"'ollama pull {args.model}'.",
            file=sys.stderr,
        )
        return 2

    # print a little header so you can see what's running
    print(f"aisec-eval v{__version__}")
    print(f"Suite : {suite.name}")
    print(f"Model : {args.model}")
    print(f"Probes: {len(suite.probes)} | repeats: {args.repeats}")
    print("-" * 48)

    # actually run everything (this is the slow part - it calls the model)
    result = run_suite(suite, provider, repeats=args.repeats, verbose=args.verbose)

    # save both reports to disk
    write_json(result, args.json_out)
    write_html(result, args.html_out)

    # print the summary to the terminal
    print("-" * 48)
    for pr in result.probe_results:
        print(f"  {pr.probe_id:<6} {pr.category:<28} "
              f"hits {pr.successes}/{pr.total}  ASR {pr.asr * 100:>5.1f}%")
    print("-" * 48)
    print(f"Overall attack success rate: {result.overall_asr * 100:.1f}%")
    print(f"Overall block rate         : {result.overall_block_rate * 100:.1f}%")
    print(f"Threshold (block rate >=)  : {result.threshold * 100:.0f}%")
    print(f"SUITE RESULT               : {'PASS' if result.passed else 'FAIL'}")
    print(f"\nReports written:\n  {args.html_out}\n  {args.json_out}")
    return 0   # 0 means success


def cmd_list_probes(args: argparse.Namespace) -> int:
    # this runs when you do "aisec list-probes" - just prints what's in the suite
    suite = load_suite(args.config)
    print(f"Suite: {suite.name}  (threshold block rate >= {suite.threshold * 100:.0f}%)")
    for p in suite.probes:
        print(f"  {p.id:<6} {p.category:<28} "
              f"detector={p.detector.get('type')}  variants={len(p.variants)}")
    return 0


def cmd_list_detectors(args: argparse.Namespace) -> int:
    # this runs when you do "aisec list-detectors" - prints the help dict above
    print("Detector types supported by aisec-eval:")
    for name, desc in DETECTOR_HELP.items():
        print(f"  {name:<16} {desc}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    # this sets up all the commands and their options (the --flags)
    p = argparse.ArgumentParser(
        prog="aisec",
        description="aisec-eval: local-first AI security evaluation tool.",
    )
    p.add_argument("--version", action="version", version=f"aisec-eval {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # the "run" command and all its options
    run = sub.add_parser("run", help="Run a suite against a model and write reports.")
    run.add_argument("-c", "--config", required=True, help="Path to a suite YAML file.")
    run.add_argument("-m", "--model", default="llama3.2", help="Ollama model tag.")
    run.add_argument("--base-url", default="http://127.0.0.1:11434",
                     help="Ollama base URL.")
    run.add_argument("--temperature", type=float, default=0.0)
    run.add_argument("-r", "--repeats", type=int, default=1,
                     help="How many times to repeat each variant.")
    run.add_argument("--html-out", default="reports/aisec_report.html")
    run.add_argument("--json-out", default="reports/aisec_report.json")
