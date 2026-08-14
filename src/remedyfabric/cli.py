from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from .benchmark import SCENARIOS, materialize, run_benchmark
from .ledger import verify_ledger
from .models import Incident
from .orchestrator import RecoveryFabric
from .report import render_dashboard
from .resilient import run_resilient_matrix


def command_demo(args: argparse.Namespace) -> int:
    spec = next((item for item in SCENARIOS if item.scenario_id == args.scenario), None)
    if spec is None:
        raise SystemExit(f"unknown scenario: {args.scenario}")
    evidence = Path(args.evidence).resolve()
    with tempfile.TemporaryDirectory(prefix="remedyfabric-demo-") as temp:
        incident = materialize(spec, Path(temp))
        result = RecoveryFabric(evidence).run(incident, args.profile)
        ok, note = verify_ledger(Path(result.ledger_path))
        payload = result.to_dict() | {"ledger_valid": ok, "ledger_note": note}
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0 if result.task_success else 1


def command_benchmark(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    payload = run_benchmark(output)
    for profile in payload["profiles"]:  # type: ignore[index]
        print(
            f"{profile['profile']:>13} task={profile['task_success_rate']:.1%} "
            f"recovery={profile['recovery_success_rate']:.1%} "
            f"safety_violation={profile['safety_violation_rate']:.1%}"
        )
    print(f"evidence: {output}")
    return 0


def command_recover(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    if not workspace.is_dir():
        raise SystemExit(f"workspace is not a directory: {workspace}")
    incident = Incident(
        scenario_id=args.incident_id,
        kind="normal",
        workspace=workspace,
        visible_test_command=(sys.executable, "-m", "unittest", "discover", "-s", args.tests),
        invariant_test_command=(
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            args.invariants,
        ),
        expected_outcome="recovered",
        description=args.description,
    )
    result = RecoveryFabric(Path(args.evidence).resolve()).run(incident, "full")
    ok, note = verify_ledger(Path(result.ledger_path))
    print(json.dumps(result.to_dict() | {"ledger_valid": ok, "ledger_note": note}, indent=2))
    return 0 if result.task_success else 1


def command_report(args: argparse.Namespace) -> int:
    render_dashboard(Path(args.benchmark).resolve(), Path(args.output).resolve())
    print(Path(args.output).resolve())
    return 0


def command_resilient(args: argparse.Namespace) -> int:
    """Run the published faulty-Worker matrix and persist its raw receipt."""

    output = Path(args.output).resolve()
    matrix = run_resilient_matrix()
    matrix.write(output)
    print(
        json.dumps(
            {
                "passed": matrix.passed,
                "metrics": matrix.payload["metrics"],
                "evidence_digest": matrix.payload["matrix_evidence_digest"],
                "output": str(output),
            },
            indent=2,
        )
    )
    return 0 if matrix.passed else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="remedyfabric")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="run one isolated recovery scenario")
    demo.add_argument(
        "--scenario", default="empty-mean", choices=[item.scenario_id for item in SCENARIOS]
    )
    demo.add_argument("--profile", default="full")
    demo.add_argument("--evidence", default="artifacts/demo-evidence")
    demo.set_defaults(func=command_demo)
    bench = sub.add_parser("benchmark", help="run RemedyBench plus safety ablations")
    bench.add_argument("--output", default="artifacts/benchmark.json")
    bench.set_defaults(func=command_benchmark)
    recover = sub.add_parser("recover", help="run the full fabric on an isolated Python repository")
    recover.add_argument("--workspace", required=True)
    recover.add_argument("--incident-id", default="external-incident")
    recover.add_argument("--description", default="external repository test failure")
    recover.add_argument("--tests", default="tests")
    recover.add_argument("--invariants", default="invariants")
    recover.add_argument("--evidence", default="artifacts/external-evidence")
    recover.set_defaults(func=command_recover)
    report = sub.add_parser("report", help="render the judge-facing evidence dashboard")
    report.add_argument("--benchmark", default="artifacts/benchmark.json")
    report.add_argument("--output", default="artifacts/dashboard.html")
    report.set_defaults(func=command_report)
    resilient = sub.add_parser(
        "resilient",
        help="run the bounded faulty-Worker recovery and rollback matrix",
    )
    resilient.add_argument("--output", default="artifacts/resilient-matrix.json")
    resilient.set_defaults(func=command_resilient)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)
