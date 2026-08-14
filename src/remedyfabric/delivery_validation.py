"""Shared, evidence-derived validation for the frozen judge delivery.

The renderers and the post-HEAD manifest/gate/package all consume this module.
No presentation status is accepted from a bare ``passed: true`` flag: every
status, number, file hash, caption, and required text fragment is recomputed
from the current evidence and delivered bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

DELIVERY_ARTIFACTS = {
    "pdf": "output/pdf/remedyfabric-goai-agent-infra-champion.pdf",
    "video": "artifacts/remedyfabric-champion-demo.mp4",
    "dashboard": "artifacts/dashboard.html",
    "preview": "artifacts/video-preview.jpg",
}
DELIVERY_CHECKS = {
    "evidence_bindings",
    "presentation_evidence_complete",
    "reproduction_commands",
    "font_license",
    "pdf_structure",
    "pdf_text_contract",
    "video_structure",
    "video_caption_contract",
    "preview_contact_sheet",
    "dashboard_self_contained",
    "dashboard_text_contract",
    "visual_inspection",
}
EVIDENCE_PATHS = {
    "resilient": "artifacts/resilient-matrix.json",
    "model": "artifacts/quorum-model.json",
    "faultbench": "artifacts/faultbench-results.json",
    "sources": "artifacts/faultbench-source-verification.json",
    "micro": "artifacts/faultbench-micro-replays.json",
    "isolation": "artifacts/container-isolation.json",
    "clean": "artifacts/clean-replay.json",
    "agentteams": "artifacts/agentteams-live-evidence.json",
}
FONT_PATHS = {
    "regular": "assets/fonts/Poppins/Poppins-Regular.ttf",
    "bold": "assets/fonts/Poppins/Poppins-Bold.ttf",
    "license": "assets/fonts/Poppins/OFL.txt",
}
PINNED_FONT_SHA256 = {
    "regular": "7e65201e9b79159e2300267cc885e16c8dcef2424cdfa09a29bfb0980a94a7ba",
    "bold": "983676516167748b74de6f4771fb384c664fd913acb8b471122ecacf5da5ea6c",
    "license": "8503c30a4d7e09c4c09015fee42f829f18acbe6330755e9930ba50ea44eaa157",
}
REPRODUCTION_COMMANDS = (
    "python3 -m pip install -e .",
    "remedyfabric resilient --output artifacts/resilient-matrix.json",
    "python3 scripts/run_faultbench.py",
    "python3 scripts/run_faultbench_micro_replays.py",
    "python3 scripts/champion_gate.py",
)
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_file(root: Path, relative: str) -> Path | None:
    path = root / relative
    return path if path.is_file() and not path.is_symlink() else None


def _load_json(root: Path, relative: str) -> dict[str, Any] | None:
    path = _regular_file(root, relative)
    if path is None:
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _validator_passes(callback: Any, *arguments: Any) -> bool:
    try:
        return not callback(*arguments)
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False


def _verified_number(valid: bool, value: Any) -> int | float | None:
    if not valid or isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _format_percent(value: float | None) -> str:
    return "N/A" if value is None else f"{float(value):.0%}"


def _format_count(value: float | None) -> str:
    return "N/A" if value is None else f"{int(value):,}"


def build_presentation_contract(root: Path) -> dict[str, Any]:
    """Recompute the only numbers and statuses renderers are allowed to show."""

    from remedyfabric.agentteams_evidence import live_evidence_is_valid
    from remedyfabric.evidence_validation import (
        validate_container_isolation,
        validate_faultbench,
        validate_micro_replays,
        validate_quorum_model,
        validate_resilient_matrix,
        validate_source_verification,
    )
    from remedyfabric.release_integrity import (
        clean_replay_current,
        clean_replay_semantic_projection,
    )

    root = root.resolve()
    evidence = {name: _load_json(root, relative) for name, relative in EVIDENCE_PATHS.items()}
    dataset = root / "faultbench/cases.json"
    resilient = evidence["resilient"] or {}
    model = evidence["model"] or {}
    faultbench = evidence["faultbench"] or {}
    sources = evidence["sources"] or {}
    micro = evidence["micro"] or {}
    isolation = evidence["isolation"] or {}
    statuses = {
        "resilient": _validator_passes(validate_resilient_matrix, resilient),
        "model": _validator_passes(validate_quorum_model, model),
        "faultbench": dataset.is_file()
        and _validator_passes(validate_faultbench, faultbench, dataset),
        "sources": dataset.is_file()
        and _validator_passes(validate_source_verification, sources, dataset),
        "micro": _validator_passes(validate_micro_replays, micro, root),
        "isolation": _validator_passes(validate_container_isolation, isolation),
        "clean": clean_replay_current(evidence["clean"], root),
        "agentteams": live_evidence_is_valid(evidence["agentteams"]),
    }
    statuses["core"] = all(
        statuses[name]
        for name in (
            "resilient",
            "model",
            "faultbench",
            "sources",
            "micro",
            "isolation",
        )
    )
    statuses["evidence_complete"] = (
        statuses["core"] and statuses["clean"] and statuses["agentteams"]
    )

    metrics = resilient.get("metrics", {}) if isinstance(resilient.get("metrics"), Mapping) else {}
    headline = (
        faultbench.get("headline", {}) if isinstance(faultbench.get("headline"), Mapping) else {}
    )
    profiles = faultbench.get("profiles", [])
    champion = next(
        (
            item
            for item in profiles
            if isinstance(item, Mapping) and item.get("profile") == "champion-quorum"
        ),
        {},
    )
    membership: Sequence[Any] = ()
    proposal_quorum: int | None = None
    trials = resilient.get("trials", [])
    if statuses["resilient"] and isinstance(trials, Sequence) and trials:
        first = trials[0] if isinstance(trials[0], Mapping) else {}
        context = first.get("run_context", {}) if isinstance(first, Mapping) else {}
        candidate = context.get("membership", []) if isinstance(context, Mapping) else []
        if isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes)):
            membership = candidate
        configured_quorum = context.get("proposal_quorum") if isinstance(context, Mapping) else None
        if isinstance(configured_quorum, int) and not isinstance(configured_quorum, bool):
            proposal_quorum = configured_quorum
    role_counts = Counter(
        str(item.get("role", ""))
        for item in membership
        if isinstance(item, Mapping) and str(item.get("role", ""))
    )

    components = evidence["agentteams"].get("components", []) if statuses["agentteams"] else []
    function_counts = Counter(
        str(item.get("function", ""))
        for item in components
        if isinstance(item, Mapping)
        and str(item.get("role", "")) in {"worker", "team-leader"}
        and str(item.get("function", ""))
    )
    evidence_bindings = {
        name: {
            "path": relative,
            "sha256": _file_digest(root / relative),
            "size_bytes": (root / relative).stat().st_size,
        }
        for name, relative in EVIDENCE_PATHS.items()
        if name != "clean" and _regular_file(root, relative) is not None
    }
    try:
        clean_projection = clean_replay_semantic_projection(evidence["clean"], root)
    except (KeyError, OSError, TypeError, ValueError):
        clean_projection = None
    if clean_projection is not None:
        evidence_bindings["clean"] = {
            "path": EVIDENCE_PATHS["clean"],
            "binding": "strict-semantic-projection-v1",
            "sha256": _canonical_digest(clean_projection) if clean_projection is not None else None,
        }
    command_bindings = {
        relative: _file_digest(root / relative)
        for relative in (
            "pyproject.toml",
            "src/remedyfabric/cli.py",
            "scripts/run_faultbench.py",
            "scripts/run_faultbench_micro_replays.py",
            "scripts/champion_gate.py",
        )
        if _regular_file(root, relative) is not None
    }
    try:
        from remedyfabric.cli import build_parser

        resilient_command = build_parser().parse_args(
            ["resilient", "--output", "artifacts/resilient-matrix.json"]
        )
        resilient_target_valid = getattr(resilient_command.func, "__name__", "") == (
            "command_resilient"
        )
    except (AttributeError, SystemExit, TypeError, ValueError):
        resilient_target_valid = False
    command_targets_present = len(command_bindings) == 5 and resilient_target_valid

    contract: dict[str, Any] = {
        "schema_version": "remedyfabric.presentation-contract.v1",
        "statuses": statuses,
        "topology": {
            "recovery_role_counts": dict(sorted(role_counts.items())),
            "recovery_actor_count": sum(role_counts.values()),
            "proposal_quorum": proposal_quorum,
            "verifier_quorum": role_counts.get("verifier") or None,
            "official_agentteams_worker_count": sum(function_counts.values())
            if statuses["agentteams"]
            else None,
            "official_agentteams_function_counts": dict(sorted(function_counts.items())),
        },
        "metrics": {
            "trial_count": _verified_number(statuses["resilient"], metrics.get("trial_count")),
            "single_worker_trials": _verified_number(
                statuses["resilient"], metrics.get("single_worker_trials")
            ),
            "single_worker_recovery_rate": _verified_number(
                statuses["resilient"], metrics.get("single_worker_recovery_rate")
            ),
            "single_worker_unsafe_releases": _verified_number(
                statuses["resilient"], metrics.get("single_worker_unsafe_releases")
            ),
            "overflow_trials": _verified_number(
                statuses["resilient"], metrics.get("tested_out_of_boundary_trials")
            ),
            "overflow_fail_closed_rate": _verified_number(
                statuses["resilient"], metrics.get("tested_out_of_boundary_fail_closed_rate")
            ),
            "checked_decisions": _verified_number(
                statuses["model"], model.get("checked_decisions")
            ),
            "case_count": _verified_number(statuses["faultbench"], faultbench.get("case_count")),
            "repository_count": _verified_number(
                statuses["faultbench"], faultbench.get("repository_count")
            ),
            "language_count": _verified_number(
                statuses["faultbench"], faultbench.get("language_count")
            ),
            "fault_attack_count": _verified_number(
                statuses["faultbench"], faultbench.get("fault_attack_count")
            ),
            "micro_fixture_count": _verified_number(statuses["micro"], micro.get("fixture_count")),
            "faultbench_single_fault_cases": _verified_number(
                statuses["faultbench"], champion.get("single_fault_case_count")
            ),
            "faultbench_overflow_cases": _verified_number(
                statuses["faultbench"], champion.get("overflow_case_count")
            ),
            "faultbench_single_fault_recovery_rate": _verified_number(
                statuses["faultbench"], headline.get("champion_single_fault_safe_recovery_rate")
            ),
            "faultbench_single_fault_unsafe_release_rate": _verified_number(
                statuses["faultbench"], headline.get("champion_single_fault_unsafe_release_rate")
            ),
            "faultbench_overflow_containment_rate": _verified_number(
                statuses["faultbench"], headline.get("champion_overflow_containment_rate")
            ),
        },
        "commands": list(REPRODUCTION_COMMANDS) if command_targets_present else [],
        "command_bindings": command_bindings,
        "command_targets_valid": command_targets_present,
        "evidence_bindings": evidence_bindings,
    }
    contract["presentation_contract_sha256"] = _canonical_digest(contract)
    return contract


def video_caption_cues(contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return the complete seven-scene caption contract for the silent video."""

    metrics = contract.get("metrics", {})
    topology = contract.get("topology", {})
    roles = topology.get("recovery_role_counts", {}) if isinstance(topology, Mapping) else {}
    statuses = contract.get("statuses", {})
    commands = contract.get("commands", [])
    workers = roles.get("worker") if isinstance(roles, Mapping) else None
    verifiers = roles.get("verifier") if isinstance(roles, Mapping) else None
    evidence_state = (
        "complete before repository freeze"
        if statuses.get("evidence_complete")
        else "in progress; incomplete evidence remains unclaimed"
    )
    agentteams_state = (
        "validated live receipt"
        if statuses.get("agentteams")
        else "pending; no live-runtime completion claim"
    )
    return [
        {
            "scene": 1,
            "start_seconds": 0,
            "end_seconds": 7,
            "title": "Champion thesis",
            "caption": "RemedyFabric keeps autonomous recovery safe when a repair Agent fails. No single Worker can authorize release.",
        },
        {
            "scene": 2,
            "start_seconds": 7,
            "end_seconds": 14,
            "title": "Role-separated release quorum",
            "caption": f"Evidence-derived topology: {_format_count(workers)} Workers and {_format_count(verifiers)} Verifiers, plus Challenger, Governor, and Release Manager.",
        },
        {
            "scene": 3,
            "start_seconds": 14,
            "end_seconds": 21,
            "title": "Executable fault evidence",
            "caption": f"{_format_count(metrics.get('trial_count'))} executable trials; {_format_percent(metrics.get('single_worker_recovery_rate'))} tested one-Worker recovery; {_format_percent(metrics.get('overflow_fail_closed_rate'))} enumerated overflow fail-closed rate.",
        },
        {
            "scene": 4,
            "start_seconds": 21,
            "end_seconds": 28,
            "title": "AgentFaultBench-OSS boundary",
            "caption": f"{_format_count(metrics.get('case_count'))} public records across {_format_count(metrics.get('repository_count'))} repositories; only {_format_count(metrics.get('micro_fixture_count'))} extracted semantics were executed, not complete upstream repairs.",
        },
        {
            "scene": 5,
            "start_seconds": 28,
            "end_seconds": 35,
            "title": "Reproducibility",
            "caption": f"Machine-recomputed evidence status: {evidence_state}. Finite model decisions: {_format_count(metrics.get('checked_decisions'))}.",
        },
        {
            "scene": 6,
            "start_seconds": 35,
            "end_seconds": 42,
            "title": "Official AgentTeams boundary",
            "caption": f"Official AgentTeams runtime: {agentteams_state}. Local zero-credential replay and cloud-provider use remain separately disclosed.",
        },
        {
            "scene": 7,
            "start_seconds": 42,
            "end_seconds": 49,
            "title": "Five-minute judge path",
            "caption": "Reproduce with: " + " ; ".join(str(item) for item in commands),
        },
    ]


def caption_contract_sha256(contract: Mapping[str, Any]) -> str:
    return _canonical_digest(video_caption_cues(contract))


def delivery_text_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Return page/section phrases that must be present in final rendered bytes."""

    metrics = contract.get("metrics", {})
    topology = contract.get("topology", {})
    statuses = contract.get("statuses", {})
    roles = topology.get("recovery_role_counts", {}) if isinstance(topology, Mapping) else {}
    status_text = "EVIDENCE COMPLETE" if statuses.get("evidence_complete") else "BUILD IN PROGRESS"
    agentteams_text = (
        "validated live receipt" if statuses.get("agentteams") else "pending final runtime wiring"
    )
    commands = [str(item) for item in contract.get("commands", [])]
    pdf_pages = {
        "1": ["RemedyFabric", "No single Worker can authorize release.", status_text],
        "2": ["A repair Agent can become the incident", "WINNING CONTRACT"],
        "3": [
            f"{_format_count(roles.get('worker'))} WORKERS",
            f"{_format_count(roles.get('verifier'))} VERIFIERS",
            "RELEASE MANAGER",
        ],
        "4": [
            f"{_format_count(metrics.get('trial_count'))} executable trials",
            f"{_format_count(metrics.get('single_worker_trials'))} executable trials",
            f"{_format_count(metrics.get('overflow_trials'))} enumerated trials",
            _format_count(metrics.get("checked_decisions")),
        ],
        "5": [
            "AgentFaultBench-OSS",
            f"{_format_count(metrics.get('faultbench_single_fault_cases'))} within-boundary cases",
            f"{_format_count(metrics.get('faultbench_overflow_cases'))} overflow/control-plane cases",
            f"{_format_count(metrics.get('micro_fixture_count'))} independent extracted semantics passed",
        ],
        "6": [
            "Every green claim has a machine-readable receipt",
            "Official AgentTeams",
            agentteams_text,
        ],
        "7": ["25%", "20%", "5%", "Coverage mapping is not a predicted score"],
        "8": ["Clone. Run. Inspect the receipts.", *commands],
        "9": [
            f"{_format_count(metrics.get('trial_count'))} executable fault-matrix trials",
            "SUPPORTED",
            "NOT CLAIMED",
        ],
    }
    dashboard = [
        "RemedyFabric",
        "Champion thesis",
        "Evidence ledger",
        "AgentFaultBench-OSS boundary",
        "Evidence completeness before repository freeze",
        "Five-minute review path",
        f"{_format_count(metrics.get('faultbench_single_fault_cases'))} protocol-simulation cases",
        f"{_format_count(metrics.get('faultbench_overflow_cases'))} overflow/control-plane cases",
        *commands,
    ]
    return {"pdf_pages": pdf_pages, "dashboard": dashboard}


def inspect_font_license(root: Path) -> dict[str, Any]:
    observed: dict[str, str | None] = {}
    for name, relative in FONT_PATHS.items():
        path = _regular_file(root, relative)
        observed[name] = _file_digest(path) if path is not None else None
    license_path = _regular_file(root, FONT_PATHS["license"])
    license_text = license_path.read_text(encoding="utf-8") if license_path else ""
    passed = observed == PINNED_FONT_SHA256 and all(
        phrase in license_text
        for phrase in (
            "Copyright 2020 The Poppins Project Authors",
            "SIL OPEN FONT LICENSE Version 1.1",
            "Permission & Conditions".upper(),
        )
    )
    # The heading in the upstream text is uppercase. Keep the check explicit
    # without modifying or normalizing the redistributed license.
    passed = passed and "PERMISSION & CONDITIONS" in license_text
    return {
        "paths": dict(FONT_PATHS),
        "sha256": observed,
        "license": "SIL Open Font License 1.1",
        "passed": passed,
    }


def presentation_render_failures(
    root: Path,
    contract: Mapping[str, Any],
) -> list[str]:
    failures: list[str] = []
    statuses = contract.get("statuses", {})
    if not isinstance(statuses, Mapping) or statuses.get("evidence_complete") is not True:
        failures.append("semantic evidence, clean replay, and official AgentTeams are not complete")
    if (
        contract.get("command_targets_valid") is not True
        or tuple(contract.get("commands", [])) != REPRODUCTION_COMMANDS
    ):
        failures.append("reproduction command targets are not valid")
    if inspect_font_license(root).get("passed") is not True:
        failures.append("the pinned Poppins files or OFL license are invalid")
    return failures


def require_presentation_render(
    root: Path,
    contract: Mapping[str, Any],
    outputs: Sequence[Path],
    *,
    allow_incomplete_preview: bool,
) -> None:
    """Refuse final-path rendering until every pre-render gate is green."""

    failures = presentation_render_failures(root, contract)
    if not failures:
        return
    preview_root = (root / "tmp").resolve()
    previews_only = bool(outputs)
    for output in outputs:
        try:
            output.resolve().relative_to(preview_root)
        except ValueError:
            previews_only = False
            break
    if allow_incomplete_preview and previews_only:
        return
    raise RuntimeError(
        "refusing final judge render: "
        + "; ".join(failures)
        + ". Use --allow-incomplete-preview only with paths under tmp/."
    )


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def inspect_pdf(path: Path, contract: Mapping[str, Any]) -> dict[str, Any]:
    pages: list[str] = []
    metadata: Mapping[str, Any] = {}
    error = ""
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path))
        pages = [_normalize_text(page.extract_text() or "") for page in reader.pages]
        metadata = reader.metadata or {}
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    required = delivery_text_contract(contract)["pdf_pages"]
    page_matches = {
        page_number: {
            phrase: int(page_number) <= len(pages)
            and _normalize_text(phrase).casefold() in pages[int(page_number) - 1].casefold()
            for phrase in phrases
        }
        for page_number, phrases in required.items()
    }
    digest = str(contract.get("presentation_contract_sha256", ""))
    keywords = str(metadata.get("/Keywords", "")) if metadata else ""
    structure_passed = bool(
        path.is_file()
        and not path.is_symlink()
        and path.stat().st_size >= 50_000
        and path.read_bytes()[:5] == b"%PDF-"
        and len(pages) == 9
    )
    text_passed = bool(
        structure_passed
        and all(all(matches.values()) for matches in page_matches.values())
        and digest
        and digest in keywords
    )
    return {
        "path": DELIVERY_ARTIFACTS["pdf"],
        "sha256": _file_digest(path) if path.is_file() else None,
        "size_bytes": path.stat().st_size if path.is_file() else None,
        "pages": len(pages),
        "page_text_sha256": [_canonical_digest(text) for text in pages],
        "page_required_text_matches": page_matches,
        "presentation_contract_sha256": digest if digest in keywords else None,
        "structure_passed": structure_passed,
        "text_contract_passed": text_passed,
        "inspection_error": error or None,
        "passed": structure_passed and text_passed,
    }


def _run(command: list[str], *, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def _normalized_srt_payload(value: str) -> list[str]:
    lines: list[str] = []
    for block in re.split(r"\r?\n\s*\r?\n", value.strip()):
        block_lines = [line.strip() for line in block.splitlines() if line.strip()]
        if block_lines and block_lines[0].isdigit():
            block_lines.pop(0)
        if block_lines and "-->" in block_lines[0]:
            block_lines.pop(0)
        if block_lines:
            lines.append(_normalize_text(" ".join(block_lines)))
    return lines


def expected_subtitle_payload(contract: Mapping[str, Any]) -> list[str]:
    return [
        _normalize_text(f"{cue['title']}: {cue['caption']}") for cue in video_caption_cues(contract)
    ]


def inspect_video(path: Path, contract: Mapping[str, Any]) -> dict[str, Any]:
    ffprobe = shutil.which("ffprobe")
    ffmpeg = shutil.which("ffmpeg")
    payload: dict[str, Any] = {}
    probe_error = ""
    subtitle_payload: list[str] = []
    subtitle_error = ""
    if ffprobe and path.is_file():
        result = _run(
            [
                ffprobe,
                "-v",
                "error",
                "-show_streams",
                "-show_format",
                "-of",
                "json",
                str(path),
            ]
        )
        if result.returncode == 0:
            try:
                decoded = json.loads(result.stdout)
                payload = decoded if isinstance(decoded, dict) else {}
            except json.JSONDecodeError as exc:
                probe_error = f"JSONDecodeError: {exc}"
        else:
            probe_error = result.stderr.strip()
    else:
        probe_error = "ffprobe or video unavailable"
    streams = payload.get("streams", []) if isinstance(payload.get("streams", []), list) else []
    videos = [item for item in streams if item.get("codec_type") == "video"]
    audios = [item for item in streams if item.get("codec_type") == "audio"]
    subtitles = [item for item in streams if item.get("codec_type") == "subtitle"]
    video = videos[0] if len(videos) == 1 else {}
    subtitle = subtitles[0] if len(subtitles) == 1 else {}
    if ffmpeg and path.is_file() and len(subtitles) == 1:
        result = _run([ffmpeg, "-v", "error", "-i", str(path), "-map", "0:s:0", "-f", "srt", "-"])
        if result.returncode == 0:
            subtitle_payload = _normalized_srt_payload(result.stdout)
        else:
            subtitle_error = result.stderr.strip()
    else:
        subtitle_error = "ffmpeg or exactly one subtitle stream unavailable"
    format_payload = payload.get("format", {}) if isinstance(payload.get("format"), Mapping) else {}
    try:
        duration = float(format_payload.get("duration", 0.0))
    except (TypeError, ValueError):
        duration = 0.0
    tags = format_payload.get("tags", {}) if isinstance(format_payload.get("tags"), Mapping) else {}
    comment = str(tags.get("comment", ""))
    presentation_digest = str(contract.get("presentation_contract_sha256", ""))
    captions_digest = caption_contract_sha256(contract)
    expected_comment = f"remedyfabric-presentation={presentation_digest};caption={captions_digest}"
    expected_subtitles = expected_subtitle_payload(contract)
    structure_passed = bool(
        path.is_file()
        and not path.is_symlink()
        and path.stat().st_size >= 500_000
        and len(videos) == 1
        and not audios
        and len(subtitles) == 1
        and video.get("codec_name") == "h264"
        and video.get("width") == 1920
        and video.get("height") == 1080
        and video.get("pix_fmt") == "yuv420p"
        and 48.9 <= duration <= 49.1
        and subtitle.get("codec_name") == "mov_text"
        and comment == expected_comment
    )
    captions_passed = subtitle_payload == expected_subtitles
    return {
        "path": DELIVERY_ARTIFACTS["video"],
        "sha256": _file_digest(path) if path.is_file() else None,
        "size_bytes": path.stat().st_size if path.is_file() else None,
        "duration_seconds": duration,
        "video_codec": video.get("codec_name"),
        "pixel_format": video.get("pix_fmt"),
        "width": video.get("width"),
        "height": video.get("height"),
        "audio_stream_count": len(audios),
        "audio_present": bool(audios),
        "subtitle_stream_count": len(subtitles),
        "subtitle_codec": subtitle.get("codec_name"),
        "subtitle_cue_count": len(subtitle_payload),
        "subtitle_payload_sha256": _canonical_digest(subtitle_payload),
        "presentation_contract_sha256": presentation_digest
        if comment == expected_comment
        else None,
        "caption_contract_sha256": captions_digest if comment == expected_comment else None,
        "structure_passed": structure_passed,
        "caption_contract_passed": captions_passed,
        "probe_error": probe_error or None,
        "subtitle_error": subtitle_error or None,
        "passed": structure_passed and captions_passed,
    }


def _ffmpeg_path() -> str | None:
    tool = shutil.which("ffmpeg")
    if tool:
        return tool
    try:
        import imageio_ffmpeg

        return imageio_ffmpeg.get_ffmpeg_exe()
    except (ImportError, RuntimeError):
        return None


def build_contact_sheet_from_video(
    video: Path,
    output: Path,
    contract: Mapping[str, Any],
    *,
    root: Path | None = None,
) -> dict[str, Any]:
    """Decode the seven actual scene midpoints into a 3x3 judge preview."""

    from PIL import Image, ImageDraw, ImageFont

    tool = _ffmpeg_path()
    if tool is None:
        raise RuntimeError("ffmpeg is required to build the video contact sheet")
    cues = video_caption_cues(contract)
    project_root = root or Path(__file__).resolve().parents[2]
    regular = project_root / FONT_PATHS["regular"]
    bold = project_root / FONT_PATHS["bold"]
    with tempfile.TemporaryDirectory(prefix="remedyfabric-contact-sheet-") as temporary:
        frame_paths: list[Path] = []
        for cue in cues:
            midpoint = (float(cue["start_seconds"]) + float(cue["end_seconds"])) / 2
            frame_path = Path(temporary) / f"scene-{int(cue['scene']):02d}.png"
            result = _run(
                [
                    tool,
                    "-v",
                    "error",
                    "-ss",
                    f"{midpoint:.3f}",
                    "-i",
                    str(video),
                    "-frames:v",
                    "1",
                    "-vf",
                    "scale=640:360:flags=lanczos",
                    "-y",
                    str(frame_path),
                ]
            )
            if result.returncode != 0 or not frame_path.is_file():
                raise RuntimeError(f"failed to decode scene {cue['scene']}: {result.stderr}")
            frame_paths.append(frame_path)
        canvas = Image.new("RGB", (1920, 1080), "#07111f")
        draw = ImageDraw.Draw(canvas)
        label_font = ImageFont.truetype(str(bold), 19)
        body_font = ImageFont.truetype(str(regular), 23)
        title_font = ImageFont.truetype(str(bold), 31)
        for index, (cue, frame_path) in enumerate(zip(cues, frame_paths, strict=True)):
            x, y = (index % 3) * 640, (index // 3) * 360
            with Image.open(frame_path) as frame:
                canvas.paste(frame.convert("RGB"), (x, y))
            draw.rectangle((x, y, x + 640, y + 42), fill="#07111f")
            draw.text(
                (x + 14, y + 9),
                f"{int(cue['scene']):02d}  {cue['title']}",
                font=label_font,
                fill="#eef5ff",
            )
        digest = str(contract.get("presentation_contract_sha256", ""))
        for index, (title, body) in enumerate(
            (
                ("SILENT + CAPTION-FIRST", "No audio stream. Seven complete subtitle cues."),
                ("EVIDENCE BINDING", f"Presentation contract {digest[:20]}..."),
            ),
            start=7,
        ):
            x, y = (index % 3) * 640, (index // 3) * 360
            draw.rectangle((x, y, x + 640, y + 360), fill="#10213a")
            draw.text((x + 32, y + 92), title, font=title_font, fill="#43d9c4")
            draw.multiline_text(
                (x + 32, y + 158),
                body,
                font=body_font,
                fill="#eef5ff",
                spacing=10,
            )
        metadata = {
            "schema_version": "remedyfabric.video-contact-sheet.v1",
            "source_video_sha256": _file_digest(video),
            "presentation_contract_sha256": contract.get("presentation_contract_sha256"),
            "caption_contract_sha256": caption_contract_sha256(contract),
            "scenes": [
                {
                    "scene": cue["scene"],
                    "start_seconds": cue["start_seconds"],
                    "end_seconds": cue["end_seconds"],
                    "title": cue["title"],
                }
                for cue in cues
            ],
        }
        exif = Image.Exif()
        exif[270] = json.dumps(
            metadata,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        canvas.save(
            output,
            format="JPEG",
            quality=90,
            optimize=True,
            subsampling=0,
            exif=exif,
        )
    return {
        "path": DELIVERY_ARTIFACTS["preview"],
        "sha256": _file_digest(output),
        "size_bytes": output.stat().st_size,
        "format": "JPEG",
        "width": 1920,
        "height": 1080,
        "tile_count": 9,
        "video_scene_tile_count": 7,
        "source_video_sha256": _file_digest(video),
        "presentation_contract_sha256": contract.get("presentation_contract_sha256"),
        "caption_contract_sha256": caption_contract_sha256(contract),
        "metadata_sha256": _canonical_digest(metadata),
    }


def inspect_preview(
    path: Path,
    video: Path,
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    format_name: str | None = None
    width = height = 0
    error = ""
    metadata: dict[str, Any] = {}
    scene_match = False
    try:
        from PIL import Image

        with Image.open(path) as image:
            image.load()
            format_name = image.format
            width, height = image.size
            description = image.getexif().get(270, "")
            parsed = json.loads(description) if isinstance(description, str) else {}
            metadata = parsed if isinstance(parsed, dict) else {}
    except (ImportError, OSError, ValueError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    expected_metadata = {
        "schema_version": "remedyfabric.video-contact-sheet.v1",
        "source_video_sha256": _file_digest(video) if video.is_file() else None,
        "presentation_contract_sha256": contract.get("presentation_contract_sha256"),
        "caption_contract_sha256": caption_contract_sha256(contract),
        "scenes": [
            {
                "scene": cue["scene"],
                "start_seconds": cue["start_seconds"],
                "end_seconds": cue["end_seconds"],
                "title": cue["title"],
            }
            for cue in video_caption_cues(contract)
        ],
    }
    if path.is_file() and video.is_file():
        try:
            from PIL import Image, ImageChops, ImageStat

            tool = _ffmpeg_path()
            if tool is None:
                raise RuntimeError("ffmpeg is required to validate the contact sheet")
            scene_errors: list[float] = []
            with (
                Image.open(path) as preview_image,
                tempfile.TemporaryDirectory(prefix="remedyfabric-preview-verify-") as temporary,
            ):
                preview_rgb = preview_image.convert("RGB")
                for index, cue in enumerate(video_caption_cues(contract)):
                    midpoint = (float(cue["start_seconds"]) + float(cue["end_seconds"])) / 2
                    frame_path = Path(temporary) / f"scene-{int(cue['scene']):02d}.png"
                    result = _run(
                        [
                            tool,
                            "-v",
                            "error",
                            "-ss",
                            f"{midpoint:.3f}",
                            "-i",
                            str(video),
                            "-frames:v",
                            "1",
                            "-vf",
                            "scale=640:360:flags=lanczos",
                            "-y",
                            str(frame_path),
                        ]
                    )
                    if result.returncode != 0:
                        raise RuntimeError(f"failed to decode scene {cue['scene']}")
                    x, y = (index % 3) * 640, (index // 3) * 360
                    observed_tile = preview_rgb.crop((x, y + 42, x + 640, y + 360))
                    with Image.open(frame_path) as frame:
                        expected_tile = frame.convert("RGB").crop((0, 42, 640, 360))
                    difference = ImageChops.difference(observed_tile, expected_tile)
                    channel_means = ImageStat.Stat(difference).mean
                    scene_errors.append(sum(channel_means) / len(channel_means))
            # JPEG compression and decoder implementations may differ slightly;
            # a mean channel error below six preserves a strong visual binding
            # without requiring platform-identical H.264 pixel output.
            scene_match = len(scene_errors) == 7 and max(scene_errors) < 6.0
        except (OSError, RuntimeError, ValueError) as exc:
            error = f"{type(exc).__name__}: {exc}"
    structure_passed = bool(
        path.is_file()
        and not path.is_symlink()
        and path.stat().st_size >= 25_000
        and format_name == "JPEG"
        and width == 1920
        and height == 1080
    )
    return {
        "path": DELIVERY_ARTIFACTS["preview"],
        "sha256": _file_digest(path) if path.is_file() else None,
        "size_bytes": path.stat().st_size if path.is_file() else None,
        "format": format_name,
        "width": width,
        "height": height,
        "tile_count": 9 if scene_match and metadata == expected_metadata else None,
        "video_scene_tile_count": 7 if scene_match and metadata == expected_metadata else None,
        "source_video_sha256": _file_digest(video) if video.is_file() else None,
        "caption_contract_sha256": caption_contract_sha256(contract),
        "metadata_sha256": _canonical_digest(metadata),
        "presentation_contract_sha256": contract.get("presentation_contract_sha256")
        if scene_match and metadata == expected_metadata
        else None,
        "contact_sheet_matches_video": scene_match,
        "metadata_matches_contract": metadata == expected_metadata,
        "inspection_error": error or None,
        "structure_passed": structure_passed,
        "passed": structure_passed and scene_match and metadata == expected_metadata,
    }


def inspect_dashboard(path: Path, contract: Mapping[str, Any]) -> dict[str, Any]:
    error = ""
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        source = ""
        error = f"{type(exc).__name__}: {exc}"
    remote_assets = re.findall(
        r"<(?:script|img|link)\b[^>]+(?:src|href)=[\"']https?://[^\"']+",
        source,
        re.IGNORECASE,
    )
    required = delivery_text_contract(contract)["dashboard"]
    matches = {
        phrase: _normalize_text(phrase).casefold() in _normalize_text(source).casefold()
        for phrase in required
    }
    digest = str(contract.get("presentation_contract_sha256", ""))
    digest_match = bool(
        digest
        and re.search(
            rf'<meta\s+name=["\']remedyfabric:presentation-sha256["\']\s+content=["\']{re.escape(digest)}["\']\s*/?>',
            source,
            re.IGNORECASE,
        )
    )
    structure_passed = bool(
        path.is_file()
        and not path.is_symlink()
        and path.stat().st_size >= 5_000
        and "<!doctype html>" in source.lower()
        and not remote_assets
    )
    text_passed = all(matches.values()) and digest_match
    return {
        "path": DELIVERY_ARTIFACTS["dashboard"],
        "sha256": _file_digest(path) if path.is_file() else None,
        "size_bytes": path.stat().st_size if path.is_file() else None,
        "utf8": not error,
        "remote_asset_count": len(remote_assets),
        "required_text_matches": matches,
        "presentation_contract_sha256": digest if digest_match else None,
        "structure_passed": structure_passed,
        "text_contract_passed": text_passed,
        "inspection_error": error or None,
        "passed": structure_passed and text_passed,
    }


def inspect_delivery(root: Path, contract: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        "pdf": inspect_pdf(root / DELIVERY_ARTIFACTS["pdf"], contract),
        "video": inspect_video(root / DELIVERY_ARTIFACTS["video"], contract),
        "preview": inspect_preview(
            root / DELIVERY_ARTIFACTS["preview"],
            root / DELIVERY_ARTIFACTS["video"],
            contract,
        ),
        "dashboard": inspect_dashboard(root / DELIVERY_ARTIFACTS["dashboard"], contract),
    }


def _compare_receipt(
    label: str,
    receipt: Any,
    observed: Mapping[str, Any],
) -> list[str]:
    if not isinstance(receipt, Mapping):
        return [f"{label} receipt is missing or malformed"]
    failures: list[str] = []
    for key, value in observed.items():
        if receipt.get(key) != value:
            failures.append(f"{label} receipt field is stale or false: {key}")
    return failures


def validate_delivery_receipt(delivery: Mapping[str, Any], root: Path) -> list[str]:
    """Recompute the complete delivery receipt from frozen evidence and bytes."""

    failures: list[str] = []
    try:
        contract = build_presentation_contract(root)
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        return [f"presentation contract could not be rebuilt: {exc}"]
    expected_contract_digest = contract["presentation_contract_sha256"]
    expected_caption_digest = caption_contract_sha256(contract)
    if delivery.get("schema_version") != "remedyfabric.delivery-qa.v2":
        failures.append("delivery QA schema is not the fail-closed v2 contract")
    if delivery.get("presentation_contract_sha256") != expected_contract_digest:
        failures.append("delivery presentation contract binding is stale")
    if delivery.get("caption_contract_sha256") != expected_caption_digest:
        failures.append("delivery caption contract binding is stale")
    if delivery.get("evidence_bindings") != contract.get("evidence_bindings"):
        failures.append("delivery evidence bindings are stale or incomplete")
    font_receipt = inspect_font_license(root)
    failures.extend(_compare_receipt("fonts", delivery.get("fonts"), font_receipt))
    observed = inspect_delivery(root, contract)
    for label, receipt in observed.items():
        failures.extend(_compare_receipt(label, delivery.get(label), receipt))
    expected_checks = {
        "evidence_bindings": delivery.get("evidence_bindings") == contract.get("evidence_bindings")
        and set(contract.get("evidence_bindings", {})) == set(EVIDENCE_PATHS),
        "presentation_evidence_complete": contract.get("statuses", {}).get("evidence_complete")
        is True,
        "reproduction_commands": contract.get("command_targets_valid") is True
        and tuple(contract.get("commands", [])) == REPRODUCTION_COMMANDS,
        "font_license": font_receipt["passed"] is True,
        "pdf_structure": observed["pdf"]["structure_passed"] is True,
        "pdf_text_contract": observed["pdf"]["text_contract_passed"] is True,
        "video_structure": observed["video"]["structure_passed"] is True,
        "video_caption_contract": observed["video"]["caption_contract_passed"] is True,
        "preview_contact_sheet": observed["preview"]["passed"] is True,
        "dashboard_self_contained": observed["dashboard"]["structure_passed"] is True,
        "dashboard_text_contract": observed["dashboard"]["text_contract_passed"] is True,
        "visual_inspection": delivery.get("checks", {}).get("visual_inspection") is True
        if isinstance(delivery.get("checks"), Mapping)
        else False,
    }
    checks = delivery.get("checks")
    if not isinstance(checks, Mapping) or dict(checks) != expected_checks:
        failures.append("delivery QA checks do not match recomputed results")
    if set(expected_checks) != DELIVERY_CHECKS:
        failures.append("internal delivery check contract is inconsistent")
    if delivery.get("passed") is not all(expected_checks.values()):
        failures.append("delivery QA passed flag does not match recomputed checks")
    if not all(expected_checks.values()):
        failures.append("delivery QA did not pass")
    return failures


__all__ = [
    "DELIVERY_ARTIFACTS",
    "DELIVERY_CHECKS",
    "EVIDENCE_PATHS",
    "FONT_PATHS",
    "REPRODUCTION_COMMANDS",
    "build_contact_sheet_from_video",
    "build_presentation_contract",
    "caption_contract_sha256",
    "delivery_text_contract",
    "expected_subtitle_payload",
    "inspect_dashboard",
    "inspect_delivery",
    "inspect_font_license",
    "inspect_pdf",
    "inspect_preview",
    "inspect_video",
    "presentation_render_failures",
    "require_presentation_render",
    "validate_delivery_receipt",
    "video_caption_cues",
]
