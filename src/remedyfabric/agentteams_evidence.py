"""Evidence helpers for a live upstream AgentTeams execution.

This module does not emulate AgentTeams.  It only normalizes and validates
records captured from the official runtime, while removing credentials before
they are written to a public artifact.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any

from .faults import AgentIdentity, AgentRole, Attestation, EvidenceBinding, EvidenceKind, Verdict
from .models import FileEdit, PatchCandidate
from .quorum import CandidateProposal, QuorumGate, patch_digest
from .release_integrity import source_tree_digest

OFFICIAL_REPOSITORY = "https://github.com/agentscope-ai/AgentTeams"
OFFICIAL_TAG = "v1.2.2"
OFFICIAL_COMMIT = "849182af8e017168a5a200a87b1062142caf462d"
OFFICIAL_REGISTRY_PREFIX = "higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/agentteams-"
PROJECT_ROOT = Path.cwd() if (Path.cwd() / "agentteams").is_dir() else Path(__file__).parents[2]
TEAM_MANIFEST = PROJECT_ROOT / "agentteams/remedyfabric-live-local.yaml"
IMAGE_LOCK = PROJECT_ROOT / "agentteams/official-runtime-images.lock.json"
CAPTURE_TOOL = PROJECT_ROOT / "scripts/capture_agentteams_live.py"
MATRIX_SENDER = PROJECT_ROOT / "scripts/agentteams_matrix_sender.py"
ROLE_HELPER = PROJECT_ROOT / "scripts/agentteams_role_tool.py"
RECOVERY_SKILL_CONTRACT = PROJECT_ROOT / "skills/remedyfabric-recovery/SKILL.md"

_SECRET_KEY = re.compile(
    r"(?:authorization|credential|password|secret|api[_-]?key|access[_-]?key|token)",
    re.IGNORECASE,
)
_BEARER_VALUE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_PUBLIC_SECRET_VALUE = re.compile(
    r"(?:\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"syt_[A-Za-z0-9._=-]{16,})\b|"
    r"\b(?:TOKEN|API[_-]?KEY|ACCESS[_-]?TOKEN|ACCESS[_-]?KEY(?:[_-]?SECRET)?|"
    r"PASSWORD|SECRET)\s*=\s*(?!\[REDACTED\]|none\b|null\b|false\b|true\b|0\b)"
    r"[^\s,;\]\}\"']{8,})",
    re.IGNORECASE,
)
_MATRIX_EVENT_ID = re.compile(r"^\$\S{10,}$")
_MATRIX_ROOM_ID = re.compile(r"^!\S{10,}$")
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_LOOP_STAGES = {
    "delegate",
    "propose",
    "tool_execute",
    "verify",
    "review",
    "challenge",
    "govern",
    "decide",
    "relay",
}
_RECOVERY_SKILL = "remedyfabric-recovery"
_RECOVERY_SKILL_VERSION = "0.1.0"
_ALIBABA_CLOUD_SKILL = "alibabacloud-resourcecenter-search"
_ROLE_HELPER = "remedyfabric-role-helper"
_PROTOCOL_KEY = "com.remedyfabric.protocol"
_ROLE_OPERATIONS = {
    "rf-proposer-a": "proposer",
    "rf-proposer-b": "proposer",
    "rf-verifier": "verifier",
    "rf-verifier-b": "verifier",
    "rf-lead": "reviewer",
    "rf-challenger": "challenger",
    "rf-governor": "governor",
    "rf-release-manager": "release-manager",
}
_EXPECTED_ACTORS = {
    "manager": ("manager", "orchestrator", "manager"),
    "rf-lead": ("team-leader", "reviewer", "worker"),
    "rf-proposer-a": ("worker", "proposer", "worker"),
    "rf-proposer-b": ("worker", "proposer", "worker"),
    "rf-verifier": ("worker", "verifier", "worker"),
    "rf-verifier-b": ("worker", "verifier", "worker"),
    "rf-challenger": ("worker", "challenger", "worker"),
    "rf-governor": ("worker", "governor", "worker"),
    "rf-release-manager": ("worker", "release-manager", "worker"),
}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_text(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def redact_public(value: Any) -> Any:
    """Recursively redact credential-shaped fields and bearer values."""

    if isinstance(value, Mapping):
        return {
            str(key): (
                item
                if _SECRET_KEY.search(str(key)) and isinstance(item, (bool, type(None)))
                else "[REDACTED]"
                if _SECRET_KEY.search(str(key))
                else redact_public(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_public(item) for item in value]
    if isinstance(value, str):
        return _PUBLIC_SECRET_VALUE.sub("[REDACTED]", _BEARER_VALUE.sub("Bearer [REDACTED]", value))
    return value


def canonical_digest(value: Any) -> str:
    """Return a stable SHA-256 digest for a JSON-compatible value."""

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def file_digest(path: Path) -> str:
    """Return the SHA-256 digest of a file without loading it all at once."""

    digest = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _candidate_from_payload(payload: Any) -> PatchCandidate:
    if not isinstance(payload, Mapping):
        raise TypeError("missing patch candidate")
    edits = payload.get("edits")
    if not isinstance(edits, Sequence) or isinstance(edits, (str, bytes)):
        raise TypeError("invalid patch edits")
    return PatchCandidate(
        skill_name=str(payload.get("skill_name", "")),
        diagnosis=str(payload.get("diagnosis", "")),
        edits=tuple(
            FileEdit(
                path=str(edit.get("path", "")),
                old=str(edit.get("old", "")),
                new=str(edit.get("new", "")),
                reason=str(edit.get("reason", "")),
            )
            for edit in edits
            if isinstance(edit, Mapping)
        ),
        confidence=float(payload.get("confidence", 0.0)),
        estimated_cost_usd=float(payload.get("estimated_cost_usd", 0.0)),
        skill_version=str(payload.get("skill_version", "")),
        provider_name=str(payload.get("provider_name", "")),
        provider_version=str(payload.get("provider_version", "")),
    )


def _candidate_from_output(output: Mapping[str, Any]) -> PatchCandidate:
    return _candidate_from_payload(output.get("patch_candidate"))


def _proposal_from_payload(proposal: Any, candidate: PatchCandidate) -> CandidateProposal:
    if not isinstance(proposal, Mapping):
        raise TypeError("missing proposal")
    return CandidateProposal(
        identity=AgentIdentity(str(proposal.get("actor_id", "")), AgentRole.WORKER),
        run_id=str(proposal.get("run_id", "")),
        snapshot_digest=str(proposal.get("snapshot_digest", "")),
        candidate=candidate,
        claimed_patch_digest=str(proposal.get("claimed_patch_digest", "")),
    )


def _proposal_from_output(
    output: Mapping[str, Any], candidate: PatchCandidate
) -> CandidateProposal:
    return _proposal_from_payload(output.get("proposal"), candidate)


def _attestation_from_output(output: Mapping[str, Any]) -> Attestation:
    payload = output.get("attestation")
    if not isinstance(payload, Mapping):
        raise TypeError("missing attestation")
    binding = EvidenceBinding(
        run_id=str(payload.get("run_id", "")),
        candidate_digest=str(payload.get("candidate_digest", "")),
        snapshot_digest=str(payload.get("snapshot_digest", "")),
        kind=EvidenceKind(str(payload.get("evidence_kind", ""))),
        artifact_digest=str(payload.get("artifact_digest", "")),
    )
    return Attestation(
        identity=AgentIdentity(
            str(payload.get("actor_id", "")), AgentRole(str(payload.get("role", "")))
        ),
        verdict=Verdict(str(payload.get("verdict", ""))),
        binding=binding,
        claimed_binding_digest=str(payload.get("claimed_binding_digest", "")),
        detail=str(payload.get("detail", "")),
    )


def _role_argv_valid(argv: Any, operation: str) -> bool:
    if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)):
        return False
    values = [str(item) for item in argv]
    if len(values) < 6 or Path(values[0]).name not in {"python", "python3"}:
        return False
    try:
        role_index = values.index("--role")
        input_index = values.index("--input")
    except ValueError:
        return False
    return (
        role_index + 1 < len(values)
        and values[role_index + 1] == operation
        and input_index + 1 < len(values)
        and bool(values[input_index + 1])
        and any(Path(value).name == "agentteams_role_tool.py" for value in values)
    )


def _sender_argv_valid(argv: Any, adapter_path: str) -> bool:
    if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)):
        return False
    values = [str(item) for item in argv]
    if len(values) < 12 or Path(values[0]).name not in {"python", "python3"}:
        return False
    try:
        script_index = next(
            index for index, value in enumerate(values) if Path(value).name == MATRIX_SENDER.name
        )
        auth_index = values.index("--auth-state")
        room_index = values.index("--room-id")
        transaction_index = values.index("--txn-id")
        input_index = values.index("--input")
    except (StopIteration, ValueError):
        return False
    return bool(
        values[script_index] == adapter_path
        and all(
            index + 1 < len(values) and bool(values[index + 1])
            for index in (auth_index, room_index, transaction_index, input_index)
        )
    )


def _source_bundle_manifest(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): file_digest(path)
        for path in sorted((root / "src/remedyfabric").glob("*.py"))
        if path.is_file()
    }


def _source_bundle_digest(root: Path) -> str:
    return canonical_digest(_source_bundle_manifest(root))


def _runtime_file_expectations(tool: str) -> dict[str, str]:
    expected = {
        "role-helper": file_digest(ROLE_HELPER),
        **{
            f"source:{relative}": digest
            for relative, digest in _source_bundle_manifest(PROJECT_ROOT).items()
        },
    }
    if tool == _RECOVERY_SKILL:
        expected["skill:SKILL.md"] = file_digest(RECOVERY_SKILL_CONTRACT)
    elif tool == _ALIBABA_CLOUD_SKILL:
        cloud_files = (
            _load_json(PROJECT_ROOT / "agentteams/official-alibaba-cloud-skill.lock.json")
            .get("skill", {})
            .get("files", {})
        )
        if isinstance(cloud_files, Mapping):
            expected.update(
                {f"skill:{relative}": str(digest) for relative, digest in cloud_files.items()}
            )
    elif tool == _ROLE_HELPER:
        expected["skill:role-helper"] = file_digest(ROLE_HELPER)
    return expected


def _binding_export_valid(
    binding: Any,
    *,
    container_id: str,
    expected_files: Mapping[str, str],
) -> bool:
    if not isinstance(binding, Mapping):
        return False
    export = binding.get("docker_exec_export", {})
    observed = binding.get("files", {})
    paths = binding.get("paths", {})
    stdout = str(binding.get("stdout", ""))
    process = export.get("ProcessConfig", {}) if isinstance(export, Mapping) else {}
    entrypoint = process.get("entrypoint") if isinstance(process, Mapping) else None
    arguments = process.get("arguments", []) if isinstance(process, Mapping) else []
    argv = binding.get("argv", [])
    if not isinstance(paths, Mapping) or set(paths) != set(expected_files):
        return False
    ordered_keys = sorted(expected_files)
    ordered_paths = [str(paths[key]) for key in ordered_keys]
    if any(not path.startswith("/") or "\n" in path for path in ordered_paths):
        return False
    expected_stdout = "".join(f"{expected_files[key]}  {paths[key]}\n" for key in ordered_keys)
    return bool(
        binding.get("container_id") == container_id
        and binding.get("algorithm") == "sha256sum-v1"
        and observed == expected_files
        and stdout == expected_stdout
        and binding.get("stdout_sha256") == _sha256_text(stdout)
        and isinstance(export, Mapping)
        and binding.get("docker_exec_export_digest") == canonical_digest(export)
        and export.get("ContainerID") == container_id
        and export.get("Running") is False
        and export.get("ExitCode") == 0
        and isinstance(entrypoint, str)
        and isinstance(arguments, Sequence)
        and not isinstance(arguments, (str, bytes))
        and isinstance(argv, Sequence)
        and not isinstance(argv, (str, bytes))
        and [entrypoint, *arguments] == list(argv)
        and list(argv) == ["sha256sum", *ordered_paths]
    )


def _protocol_from_content(content: Mapping[str, Any], actor_id: str) -> Mapping[str, Any]:
    direct = content.get(_PROTOCOL_KEY)
    if actor_id != "manager":
        return direct if isinstance(direct, Mapping) else {}
    body = str(content.get("body", ""))
    prefix = "RFPROTO:"
    if not body.startswith(prefix):
        return {}
    first_line = body.splitlines()[0]
    try:
        decoded = json.loads(first_line.removeprefix(prefix))
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, Mapping) else {}


@dataclass(frozen=True)
class RuntimeComponent:
    role: str
    name: str
    image: str
    image_digest: str
    state: str

    def to_dict(self) -> dict[str, str]:
        return {
            "role": self.role,
            "name": self.name,
            "image": self.image,
            "image_digest": self.image_digest,
            "state": self.state,
        }


@dataclass(frozen=True)
class TraceEvent:
    sequence: int
    actor_role: str
    actor_id: str
    function: str
    stage: str
    action: str
    room_id: str
    event_id: str
    timestamp_utc: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "actor_role": self.actor_role,
            "actor_id": self.actor_id,
            "function": self.function,
            "stage": self.stage,
            "action": self.action,
            "room_id": self.room_id,
            "event_id": self.event_id,
            "timestamp_utc": self.timestamp_utc,
            "summary": self.summary,
        }


@dataclass(frozen=True)
class ACLProbe:
    actor_role: str
    attempted_action: str
    expected: str
    observed: str
    status_code: int | None
    allowed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_role": self.actor_role,
            "attempted_action": self.attempted_action,
            "expected": self.expected,
            "observed": self.observed,
            "status_code": self.status_code,
            "allowed": self.allowed,
        }


def validate_live_evidence(
    evidence: Mapping[str, Any], *, allow_synthetic_fixture: bool = False
) -> list[str]:
    """Return fail-closed validation failures for a public live-run record."""

    failures: list[str] = []
    synthetic_fixture = bool(
        allow_synthetic_fixture
        and evidence.get("provenance") == "synthetic-validator-fixture"
        and "SYNTHETIC VALIDATOR FIXTURE ONLY" in str(evidence.get("fixture_notice", ""))
    )
    if not synthetic_fixture and (
        evidence.get("fixture_notice") or evidence.get("provenance") != "live-official-runtime"
    ):
        failures.append("production live evidence provenance is missing or synthetic")
    upstream = evidence.get("upstream", {})
    if not isinstance(upstream, Mapping):
        return ["upstream record is missing"]
    if upstream.get("repository") != OFFICIAL_REPOSITORY:
        failures.append("runtime repository is not the pinned official AgentTeams source")
    if upstream.get("tag") != OFFICIAL_TAG:
        failures.append("runtime tag is not the pinned tested release")
    if upstream.get("commit") != OFFICIAL_COMMIT:
        failures.append("runtime commit does not match the pinned official tag")
    claim_boundary = evidence.get("claim_boundary")
    if not (
        isinstance(claim_boundary, str)
        and "operator-captured" in claim_boundary.lower()
        and "third-party" in claim_boundary.lower()
        and "not" in claim_boundary.lower()
        and "operator-assisted" in claim_boundary.lower()
        and "llm autonomy" in claim_boundary.lower()
        and "not claimed" in claim_boundary.lower()
    ):
        failures.append("live evidence does not disclose its operator-captured boundary")

    capture = evidence.get("capture_bundle", {})
    if not isinstance(capture, Mapping):
        failures.append("operator capture bundle is missing")
        capture = {}
    challenge_nonce = str(capture.get("challenge_nonce", ""))
    captured_run_id = str(capture.get("run_id", ""))
    captured_task_digest = str(capture.get("task_digest", ""))
    task_payload = evidence.get("task")
    if not (
        capture.get("schema_version") == "remedyfabric.agentteams-capture.v1"
        and capture.get("capture_tool_sha256") == file_digest(CAPTURE_TOOL)
        and capture.get("source_tree_sha256") == source_tree_digest(PROJECT_ROOT)
        and capture.get("team_manifest_sha256") == file_digest(TEAM_MANIFEST)
        and capture.get("image_lock_sha256") == file_digest(IMAGE_LOCK)
        and len(challenge_nonce) >= 32
        and challenge_nonce.strip() == challenge_nonce
        and captured_run_id
        and _HEX_DIGEST.fullmatch(captured_task_digest)
        and isinstance(task_payload, Mapping)
        and canonical_digest(task_payload) == captured_task_digest
        and _UTC_TIMESTAMP.fullmatch(str(capture.get("started_at_utc", "")))
        and _UTC_TIMESTAMP.fullmatch(str(capture.get("finished_at_utc", "")))
    ):
        failures.append("operator capture bundle header is invalid")
    try:
        capture_started = datetime.fromisoformat(str(capture.get("started_at_utc", "")))
        capture_finished = datetime.fromisoformat(str(capture.get("finished_at_utc", "")))
        if capture_started > capture_finished:
            raise ValueError("capture window is reversed")
    except ValueError:
        capture_started = datetime.max.replace(tzinfo=UTC)
        capture_finished = datetime.min.replace(tzinfo=UTC)
        failures.append("operator capture time window is invalid")

    runtime_capture = evidence.get("runtime_capture", {})
    if not isinstance(runtime_capture, Mapping):
        failures.append("Docker runtime capture is missing")
        runtime_capture = {}
    engine_export = runtime_capture.get("engine_version_export", {})
    if not (
        isinstance(engine_export, Mapping)
        and runtime_capture.get("engine_version_status") == 200
        and runtime_capture.get("engine_version_export_digest") == canonical_digest(engine_export)
        and str(engine_export.get("Version", "")).strip()
        and str(engine_export.get("ApiVersion", "")).strip()
    ):
        failures.append("Docker Engine version export is invalid")
    image_lock = _load_json(IMAGE_LOCK)
    locked_images = image_lock.get("images", {})
    image_exports = runtime_capture.get("image_inspect_exports", [])
    if not isinstance(image_exports, Sequence) or isinstance(image_exports, (str, bytes)):
        failures.append("Docker image inspect exports are missing")
        image_exports = []
    observed_image_keys: set[str] = set()
    for item in image_exports:
        if not isinstance(item, Mapping):
            failures.append("Docker image inspect export is malformed")
            continue
        key = str(item.get("image_key", ""))
        export = item.get("export", {})
        locked = locked_images.get(key, {}) if isinstance(locked_images, Mapping) else {}
        if not (
            key in {"controller", "manager", "worker"}
            and isinstance(export, Mapping)
            and item.get("export_digest") == canonical_digest(export)
            and export.get("Id") == locked.get("image_id")
            and export.get("RepoDigests") == [locked.get("repo_digest")]
            and item.get("reference") == locked.get("reference")
        ):
            failures.append(f"Docker image inspect export is invalid: {key or '[missing]'}")
        else:
            observed_image_keys.add(key)
    if observed_image_keys != {"controller", "manager", "worker"}:
        failures.append("Docker image inspect export set does not match the runtime lock")
    inspect_exports = runtime_capture.get("container_inspect_exports", [])
    if not isinstance(inspect_exports, Sequence) or isinstance(inspect_exports, (str, bytes)):
        failures.append("Docker container inspect exports are missing")
        inspect_exports = []
    inspect_by_id: dict[str, Mapping[str, Any]] = {}
    for item in inspect_exports:
        if not isinstance(item, Mapping):
            failures.append("Docker container inspect export is malformed")
            continue
        export = item.get("export", {})
        container_id = str(item.get("container_id", ""))
        if not (
            isinstance(export, Mapping)
            and _CONTAINER_ID.fullmatch(container_id)
            and item.get("export_digest") == canonical_digest(export)
            and export.get("Id") == container_id
            and export.get("State", {}).get("Running") is True
            and _IMAGE_DIGEST.fullmatch(str(export.get("Image", "")))
            and str(export.get("Config", {}).get("Image", ""))
            in {
                locked_images.get("controller", {}).get("reference"),
                locked_images.get("manager", {}).get("reference"),
                locked_images.get("worker", {}).get("reference"),
            }
            and _UTC_TIMESTAMP.fullmatch(
                str(export.get("State", {}).get("StartedAt", "")).replace("+00:00", "Z")
            )
            and isinstance(export.get("RestartCount"), int)
            and isinstance(export.get("NetworkSettings", {}).get("Networks"), Mapping)
            and bool(export.get("NetworkSettings", {}).get("Networks"))
        ):
            failures.append(
                f"Docker container inspect export is invalid: {container_id or '[missing]'}"
            )
            continue
        inspect_by_id[container_id] = export

    components = evidence.get("components", [])
    if not isinstance(components, Sequence) or isinstance(components, (str, bytes)):
        failures.append("components must be a sequence")
        components = []
    roles = set()
    running_worker_ids: set[str] = set()
    component_roles: dict[str, str] = {}
    component_functions: dict[str, str] = {}
    component_senders: dict[str, str] = {}
    expected_container_ids: dict[str, str] = {}
    matrix_ids: set[str] = set()
    for component in components:
        if not isinstance(component, Mapping):
            failures.append("component record is malformed")
            continue
        image = str(component.get("image", ""))
        if not image.startswith(OFFICIAL_REGISTRY_PREFIX):
            failures.append(f"non-official runtime image: {image or '[missing]'}")
        if component.get("state") != "running":
            failures.append(f"component is not running: {component.get('name', '[missing]')}")
        if not _IMAGE_DIGEST.fullmatch(str(component.get("image_digest", ""))):
            failures.append(
                f"component image digest is invalid: {component.get('name', '[missing]')}"
            )
        role = str(component.get("role", ""))
        roles.add(role)
        actor_id = str(component.get("actor_id", ""))
        function = str(component.get("function", ""))
        matrix_id = str(component.get("matrix_id", ""))
        container_id = str(component.get("container_id", ""))
        expected_component = _EXPECTED_ACTORS.get(actor_id)
        expected_image_key = expected_component[2] if expected_component else ""
        expected_image = locked_images.get(expected_image_key, {})
        if not actor_id:
            failures.append(f"component actor ID is missing: {component.get('name', '[missing]')}")
        elif actor_id in component_roles:
            failures.append(f"component actor ID is duplicated: {actor_id}")
        else:
            component_roles[actor_id] = role
            component_functions[actor_id] = function
            component_senders[actor_id] = matrix_id
        if not function:
            failures.append(f"component function is missing: {component.get('name', '[missing]')}")
        if not matrix_id.startswith("@") or ":" not in matrix_id:
            failures.append(f"component Matrix ID is invalid: {component.get('name', '[missing]')}")
        elif matrix_id in matrix_ids:
            failures.append(f"component Matrix ID is duplicated: {matrix_id}")
        matrix_ids.add(matrix_id)
        inspect_export = inspect_by_id.get(container_id, {})
        if expected_component is not None:
            expected_container_ids[actor_id] = container_id
        if not (
            inspect_export
            and component.get("name") == inspect_export.get("Name", "").lstrip("/")
            and image == inspect_export.get("Config", {}).get("Image")
            and component.get("image_digest") == inspect_export.get("Image")
            and image == expected_image.get("reference")
            and component.get("image_digest") == expected_image.get("image_id")
            and expected_component is not None
            and role == expected_component[0]
            and function == expected_component[1]
        ):
            failures.append(
                f"component is not derived from Docker inspect: {actor_id or '[missing]'}"
            )
        if role in {"worker", "team-leader"} and component.get("state") == "running":
            if not actor_id:
                failures.append(f"Worker actor ID is missing: {component.get('name', '[missing]')}")
            running_worker_ids.add(actor_id)
    if "manager" not in roles:
        failures.append("official Manager component is missing")
    if set(component_roles) != set(_EXPECTED_ACTORS):
        failures.append("runtime actor set does not match the committed champion topology")
    if len(set(expected_container_ids.values())) != len(_EXPECTED_ACTORS):
        failures.append("runtime topology does not bind every actor to a distinct container")
    if len(running_worker_ids) != 8:
        failures.append("the complete eight-Worker champion topology is not running")
    controller_reference = locked_images.get("controller", {}).get("reference")
    controller_image_id = locked_images.get("controller", {}).get("image_id")
    if not any(
        export.get("Config", {}).get("Image") == controller_reference
        and export.get("Image") == controller_image_id
        for export in inspect_by_id.values()
    ):
        failures.append("official embedded Controller container is not captured as running")

    trace = evidence.get("trace", [])
    if not isinstance(trace, Sequence) or isinstance(trace, (str, bytes)):
        failures.append("trace must be a sequence")
        trace = []
    trace_roles: set[str] = set()
    manager_positions: list[int] = []
    worker_positions: list[int] = []
    worker_actor_ids: set[str] = set()
    worker_functions: set[str] = set()
    stages: set[str] = set()
    event_ids: set[str] = set()
    event_digests: dict[str, str] = {}
    events_by_id: dict[str, Mapping[str, Any]] = {}
    previous_sequence = -1
    previous_origin_server_ts = -1
    previous_timestamp: datetime | None = None
    previous_event_id: str | None = None
    previous_protocol_digest: str | None = None
    protocol_by_event_id: dict[str, Mapping[str, Any]] = {}
    protocol_output_receipts: dict[str, tuple[str, str]] = {}
    matrix_exports = evidence.get("matrix_authenticated_exports", {})
    if not isinstance(matrix_exports, Mapping):
        failures.append("authenticated Matrix exports are missing")
        matrix_exports = {}
    whoami_exports = matrix_exports.get("whoami", [])
    event_exports = matrix_exports.get("events", [])
    if not isinstance(whoami_exports, Sequence) or isinstance(whoami_exports, (str, bytes)):
        failures.append("Matrix whoami exports are missing")
        whoami_exports = []
    if not isinstance(event_exports, Sequence) or isinstance(event_exports, (str, bytes)):
        failures.append("Matrix event exports are missing")
        event_exports = []
    whoami_by_actor: dict[str, str] = {}
    for item in whoami_exports:
        if not isinstance(item, Mapping):
            failures.append("Matrix whoami export is malformed")
            continue
        response = item.get("response", {})
        actor_id = str(item.get("actor_id", ""))
        user_id = str(response.get("user_id", "")) if isinstance(response, Mapping) else ""
        if not (
            item.get("request_path") == "/_matrix/client/v3/account/whoami"
            and item.get("status_code") == 200
            and isinstance(response, Mapping)
            and item.get("response_digest") == canonical_digest(response)
            and user_id == component_senders.get(actor_id)
        ):
            failures.append(f"Matrix whoami export is invalid: {actor_id or '[missing]'}")
        else:
            whoami_by_actor[actor_id] = user_id
    event_export_by_id: dict[str, Mapping[str, Any]] = {}
    event_send_capture_by_id: dict[str, Mapping[str, Any]] = {}
    for item in event_exports:
        if not isinstance(item, Mapping):
            failures.append("Matrix event export is malformed")
            continue
        response = item.get("response", {})
        send_capture = item.get("send_capture", {})
        event_id = str(response.get("event_id", "")) if isinstance(response, Mapping) else ""
        room_id = str(response.get("room_id", "")) if isinstance(response, Mapping) else ""
        expected_path = f"/_matrix/client/v3/rooms/{room_id}/event/{event_id}"
        actor_id = str(item.get("actor_id", ""))
        request_content = (
            send_capture.get("request_content", {}) if isinstance(send_capture, Mapping) else {}
        )
        send_response = (
            send_capture.get("response", {}) if isinstance(send_capture, Mapping) else {}
        )
        send_export = (
            send_capture.get("docker_exec_export", {}) if isinstance(send_capture, Mapping) else {}
        )
        transport = (
            str(send_capture.get("transport", "")) if isinstance(send_capture, Mapping) else ""
        )
        send_valid = bool(
            isinstance(send_capture, Mapping)
            and actor_id in component_roles
            and send_capture.get("actor_id") == actor_id
            and isinstance(request_content, Mapping)
            and send_capture.get("request_content_digest") == canonical_digest(request_content)
            and send_capture.get("status_code") == 200
            and isinstance(send_response, Mapping)
            and send_capture.get("response_digest") == canonical_digest(send_response)
        )
        if actor_id == "manager":
            manager_text = str(send_capture.get("request_text", ""))
            send_valid = send_valid and bool(
                transport == "official-manager-api"
                and send_capture.get("request_path") == "/api/messages/send"
                and send_capture.get("manager_container_id")
                == expected_container_ids.get("manager")
                and manager_text == str(response.get("content", {}).get("body", ""))
                and send_capture.get("request_text_sha256") == _sha256_text(manager_text)
                and send_response
                == {"success": True, "message": "Message sent successfully to matrix"}
                and send_capture.get("event_id_resolution")
                == "authenticated-room-sync-match-by-exact-body"
            )
        else:
            process_config = (
                send_export.get("ProcessConfig", {}) if isinstance(send_export, Mapping) else {}
            )
            entrypoint = (
                process_config.get("entrypoint") if isinstance(process_config, Mapping) else None
            )
            arguments = (
                process_config.get("arguments", []) if isinstance(process_config, Mapping) else []
            )
            adapter_path = str(send_capture.get("adapter_path", ""))
            adapter_binding = send_capture.get("adapter_file_binding")
            send_valid = send_valid and bool(
                transport == "worker-container-matrix-adapter"
                and send_capture.get("adapter_sha256") == file_digest(MATRIX_SENDER)
                and Path(adapter_path).name == MATRIX_SENDER.name
                and send_capture.get("container_id") == expected_container_ids.get(actor_id)
                and isinstance(send_export, Mapping)
                and send_capture.get("docker_exec_export_digest") == canonical_digest(send_export)
                and send_export.get("ContainerID") == expected_container_ids.get(actor_id)
                and send_export.get("Running") is False
                and send_export.get("ExitCode") == 0
                and isinstance(entrypoint, str)
                and bool(entrypoint)
                and isinstance(arguments, Sequence)
                and not isinstance(arguments, (str, bytes))
                and isinstance(send_capture.get("argv"), Sequence)
                and not isinstance(send_capture.get("argv"), (str, bytes))
                and [entrypoint, *arguments] == list(send_capture.get("argv", []))
                and _sender_argv_valid(send_capture.get("argv"), adapter_path)
                and _binding_export_valid(
                    adapter_binding,
                    container_id=str(expected_container_ids.get(actor_id, "")),
                    expected_files={"adapter_sha256": file_digest(MATRIX_SENDER)},
                )
                and send_response.get("event_id") == event_id
                and send_capture.get("stdout")
                == json.dumps(send_response, sort_keys=True, separators=(",", ":")) + "\n"
                and send_capture.get("stdout_sha256")
                == _sha256_text(str(send_capture.get("stdout", "")))
                and send_capture.get("stderr") == ""
                and send_capture.get("stderr_sha256") == _sha256_text("")
            )
        response_sender = str(response.get("sender", "")) if isinstance(response, Mapping) else ""
        send_valid = send_valid and bool(
            response_sender == component_senders.get(actor_id)
            and whoami_by_actor.get(actor_id) == response_sender
        )
        if not (
            item.get("status_code") == 200
            and item.get("request_path") == expected_path
            and isinstance(response, Mapping)
            and item.get("response_digest") == canonical_digest(response)
            and _MATRIX_EVENT_ID.fullmatch(event_id)
            and _MATRIX_ROOM_ID.fullmatch(room_id)
            and send_valid
            and (actor_id == "manager" or request_content == response.get("content"))
        ):
            failures.append(
                f"Matrix authenticated event export is invalid: {event_id or '[missing]'}"
            )
        elif event_id in event_export_by_id:
            failures.append(f"Matrix authenticated event export is duplicated: {event_id}")
        else:
            event_export_by_id[event_id] = response
            event_send_capture_by_id[event_id] = send_capture
    for position, event in enumerate(trace):
        if not isinstance(event, Mapping):
            failures.append("trace event is malformed")
            continue
        role = str(event.get("actor_role", ""))
        actor_id = str(event.get("actor_id", ""))
        function = str(event.get("function", ""))
        stage = str(event.get("stage", ""))
        trace_roles.add(role)
        stages.add(stage)
        if role == "manager":
            manager_positions.append(position)
        if role in {"team-leader", "worker"}:
            worker_positions.append(position)
            if actor_id:
                worker_actor_ids.add(actor_id)
                if actor_id not in running_worker_ids:
                    failures.append(
                        f"trace Worker actor is not a running component at position {position}"
                    )
            if function:
                worker_functions.add(function)
        if not actor_id:
            failures.append(f"trace actor ID is missing at position {position}")
        elif actor_id not in component_roles:
            failures.append(f"trace actor is not a running component at position {position}")
        elif component_roles[actor_id] != role:
            failures.append(f"trace/component role mismatch at position {position}")
        if not function:
            failures.append(f"trace function is missing at position {position}")
        elif actor_id in component_functions and component_functions[actor_id] != function:
            failures.append(f"trace/component function mismatch at position {position}")
        if not stage:
            failures.append(f"trace stage is missing at position {position}")
        event_id = str(event.get("event_id", ""))
        if not _MATRIX_EVENT_ID.fullmatch(event_id):
            failures.append(f"trace event has invalid Matrix event ID at position {position}")
        elif event_id in event_ids:
            failures.append(f"trace reuses Matrix event ID: {event_id}")
        event_ids.add(event_id)
        sequence = event.get("sequence")
        if not isinstance(sequence, int) or sequence <= previous_sequence:
            failures.append("trace sequence is not strictly increasing")
        else:
            previous_sequence = sequence
        if not str(event.get("action", "")).strip():
            failures.append(f"trace action is missing at position {position}")
        if not str(event.get("summary", "")).strip():
            failures.append(f"trace summary is missing at position {position}")
        timestamp_text = str(event.get("timestamp_utc", ""))
        if not _UTC_TIMESTAMP.fullmatch(timestamp_text):
            failures.append(f"trace timestamp is invalid at position {position}")
        else:
            timestamp = datetime.fromisoformat(timestamp_text)
            if previous_timestamp is not None and timestamp < previous_timestamp:
                failures.append("trace timestamps are not monotonic")
            previous_timestamp = timestamp
        if not _MATRIX_ROOM_ID.fullmatch(str(event.get("room_id", ""))):
            failures.append(f"trace room ID is invalid at position {position}")
        raw_event = event.get("raw_event", {})
        if not isinstance(raw_event, Mapping):
            failures.append(f"trace raw Matrix event is missing at position {position}")
        else:
            if raw_event.get("event_id") != event_id:
                failures.append(f"trace/raw event ID mismatch at position {position}")
            if raw_event.get("room_id") != event.get("room_id"):
                failures.append(f"trace/raw room ID mismatch at position {position}")
            sender = str(raw_event.get("sender", ""))
            if not sender.strip():
                failures.append(f"raw Matrix sender is missing at position {position}")
            elif actor_id in component_senders and sender != component_senders[actor_id]:
                failures.append(f"trace/raw Matrix sender mismatch at position {position}")
            if raw_event.get("type") != "m.room.message":
                failures.append(f"raw Matrix event type is invalid at position {position}")
            origin_server_ts = raw_event.get("origin_server_ts")
            if not isinstance(origin_server_ts, int):
                failures.append(f"raw Matrix timestamp is invalid at position {position}")
            elif origin_server_ts < previous_origin_server_ts:
                failures.append("raw Matrix timestamps are not monotonic")
            else:
                previous_origin_server_ts = origin_server_ts
            content = raw_event.get("content", {})
            if not isinstance(content, Mapping) or not str(content.get("body", "")).strip():
                failures.append(f"raw Matrix message body is missing at position {position}")
                content = {}
            protocol = _protocol_from_content(content, actor_id)
            if not protocol:
                failures.append(f"typed protocol payload is missing at position {position}")
                protocol = {}
            unsigned_protocol = dict(protocol)
            claimed_protocol_digest = unsigned_protocol.pop("protocol_digest", None)
            input_receipts = protocol.get("input_receipt_digests", [])
            output_receipt = protocol.get("output_receipt_digest")
            if not (
                protocol.get("schema_version") == "remedyfabric.agentteams-event.v1"
                and protocol.get("run_id") == captured_run_id
                and protocol.get("challenge_nonce") == challenge_nonce
                and protocol.get("task_digest") == captured_task_digest
                and protocol.get("sequence") == sequence
                and protocol.get("actor_id") == actor_id
                and protocol.get("function") == function
                and protocol.get("stage") == stage
                and protocol.get("previous_event_id") == previous_event_id
                and protocol.get("previous_protocol_digest") == previous_protocol_digest
                and claimed_protocol_digest == canonical_digest(unsigned_protocol)
                and isinstance(input_receipts, Sequence)
                and not isinstance(input_receipts, (str, bytes))
                and all(_HEX_DIGEST.fullmatch(str(item)) for item in input_receipts)
                and (output_receipt is None or _HEX_DIGEST.fullmatch(str(output_receipt)))
            ):
                failures.append(f"typed protocol payload is invalid at position {position}")
            previous_event_id = event_id
            previous_protocol_digest = str(claimed_protocol_digest or "")
            protocol_by_event_id[event_id] = protocol
            if isinstance(output_receipt, str) and _HEX_DIGEST.fullmatch(output_receipt):
                if output_receipt in protocol_output_receipts:
                    failures.append(f"protocol output receipt is reused at position {position}")
                protocol_output_receipts[output_receipt] = (actor_id, stage)
            if isinstance(origin_server_ts, int):
                event_time = datetime.fromtimestamp(origin_server_ts / 1000, tz=UTC)
                if not capture_started <= event_time <= capture_finished:
                    failures.append(f"Matrix event falls outside capture window at {position}")
            event_digests[event_id] = canonical_digest(raw_event)
            events_by_id[event_id] = event
            if event_export_by_id.get(event_id) != raw_event:
                failures.append(
                    f"trace is not derived from authenticated Matrix export at {position}"
                )
            if whoami_by_actor.get(actor_id) != sender:
                failures.append(f"trace sender lacks matching Matrix whoami export at {position}")
    if "manager" not in trace_roles:
        failures.append("trace has no Manager-authored event")
    if len(trace_roles.intersection({"team-leader", "worker"})) < 1:
        failures.append("trace has no Worker-authored event")
    if len(trace) < 3:
        failures.append("trace is too short to establish a Manager/Worker round")
    if worker_actor_ids != running_worker_ids:
        failures.append("trace does not include every Worker in the champion topology")
    if worker_functions != {
        "reviewer",
        "proposer",
        "verifier",
        "challenger",
        "governor",
        "release-manager",
    }:
        failures.append("trace Worker functions do not match the champion topology")
    missing_stages = sorted(_REQUIRED_LOOP_STAGES.difference(stages))
    if missing_stages:
        failures.append(f"trace is missing complete-loop stages: {', '.join(missing_stages)}")
    if not any(
        first_manager < worker < final_manager
        for first_manager in manager_positions
        for worker in worker_positions
        for final_manager in manager_positions
    ):
        failures.append("trace does not establish a Manager-to-Worker-to-Manager causal round")
    expected_stage_actors = {
        "delegate": {"manager"},
        "propose": {"rf-proposer-a", "rf-proposer-b"},
        "verify": {"rf-verifier", "rf-verifier-b"},
        "review": {"rf-lead"},
        "challenge": {"rf-challenger"},
        "govern": {"rf-governor"},
        "decide": {"rf-release-manager"},
        "relay": {"manager"},
    }
    for required_stage, required_actors in expected_stage_actors.items():
        observed_actors = {
            str(event.get("actor_id", ""))
            for event in trace
            if isinstance(event, Mapping) and event.get("stage") == required_stage
        }
        if not required_actors.issubset(observed_actors):
            failures.append(f"trace stage lacks required actors: {required_stage}")
    if not (
        trace
        and isinstance(trace[0], Mapping)
        and trace[0].get("actor_id") == "manager"
        and trace[0].get("stage") == "delegate"
        and isinstance(trace[-1], Mapping)
        and trace[-1].get("actor_id") == "manager"
        and trace[-1].get("stage") == "relay"
    ):
        failures.append("trace is not bounded by Manager delegate and relay events")
    output_by_actor_stage = {
        (actor_id, stage): digest for digest, (actor_id, stage) in protocol_output_receipts.items()
    }
    proposer_receipts = {
        output_by_actor_stage.get((actor, "propose"))
        for actor in ("rf-proposer-a", "rf-proposer-b")
    }
    proposer_receipts.discard(None)
    required_control_receipts: set[str] = set()
    for actor, stage in (
        ("rf-verifier", "verify"),
        ("rf-verifier-b", "verify"),
        ("rf-lead", "review"),
        ("rf-challenger", "challenge"),
        ("rf-governor", "govern"),
    ):
        output_digest = output_by_actor_stage.get((actor, stage))
        event = next(
            (
                item
                for item in trace
                if isinstance(item, Mapping)
                and item.get("actor_id") == actor
                and item.get("stage") == stage
            ),
            {},
        )
        protocol = protocol_by_event_id.get(str(event.get("event_id", "")), {})
        if not (
            output_digest
            and proposer_receipts
            and proposer_receipts.issubset(set(protocol.get("input_receipt_digests", [])))
        ):
            failures.append(f"control event is not causally bound to both proposals: {actor}")
        else:
            required_control_receipts.add(output_digest)
    decision_event = next(
        (
            item
            for item in trace
            if isinstance(item, Mapping)
            and item.get("actor_id") == "rf-release-manager"
            and item.get("stage") == "decide"
        ),
        {},
    )
    decision_protocol = protocol_by_event_id.get(str(decision_event.get("event_id", "")), {})
    decision_receipt = decision_protocol.get("output_receipt_digest")
    if not (
        isinstance(decision_receipt, str)
        and set(decision_protocol.get("input_receipt_digests", []))
        == proposer_receipts | required_control_receipts
    ):
        failures.append("release decision does not consume the exact required receipt set")
    relay_event = trace[-1] if trace and isinstance(trace[-1], Mapping) else {}
    relay_protocol = protocol_by_event_id.get(str(relay_event.get("event_id", "")), {})
    if relay_protocol.get("input_receipt_digests") != [decision_receipt]:
        failures.append("Manager relay is not causally bound to the terminal decision")
    if len(event_export_by_id) != len(trace):
        failures.append("authenticated Matrix event export set does not exactly match trace")
    if set(whoami_by_actor) != set(component_roles):
        failures.append("Matrix whoami export set does not exactly match runtime components")

    shared_context = evidence.get("shared_context", {})
    if not isinstance(shared_context, Mapping):
        failures.append("structured shared context is missing")
    else:
        run_id = str(shared_context.get("run_id", ""))
        initial_digest = str(shared_context.get("initial_state_digest", ""))
        transitions = shared_context.get("transitions", [])
        previous_digest = initial_digest
        if not (
            shared_context.get("schema_version") == "remedyfabric.shared-context.v1"
            and run_id
            and re.fullmatch(r"[0-9a-f]{64}", initial_digest)
            and isinstance(transitions, Sequence)
            and not isinstance(transitions, (str, bytes))
            and len(transitions) == len(trace)
        ):
            failures.append("structured shared context header is invalid")
        else:
            for position, (event, transition) in enumerate(zip(trace, transitions, strict=True)):
                if not isinstance(event, Mapping) or not isinstance(transition, Mapping):
                    failures.append(f"shared context transition is malformed at {position}")
                    continue
                event_id = str(event.get("event_id", ""))
                raw_digest = event_digests.get(event_id, "")
                expected_state = canonical_digest(
                    {
                        "run_id": run_id,
                        "previous_state_digest": previous_digest,
                        "raw_event_digest": raw_digest,
                        "stage": event.get("stage"),
                        "actor_id": event.get("actor_id"),
                    }
                )
                raw_body = str(event.get("raw_event", {}).get("content", {}).get("body", ""))
                if not (
                    transition.get("event_id") == event_id
                    and transition.get("actor_id") == event.get("actor_id")
                    and transition.get("stage") == event.get("stage")
                    and transition.get("previous_state_digest") == previous_digest
                    and transition.get("state_digest") == expected_state
                    and run_id in raw_body
                ):
                    failures.append(f"shared context transition is invalid at {position}")
                previous_digest = expected_state
            if shared_context.get("final_state_digest") != previous_digest:
                failures.append("structured shared context final digest is invalid")

    skill_invocations = evidence.get("skill_invocations", [])
    if not isinstance(skill_invocations, Sequence) or isinstance(skill_invocations, (str, bytes)):
        failures.append("skill_invocations must be a sequence")
        skill_invocations = []
    valid_recovery_candidates: dict[str, str] = {}
    tool_receipts = evidence.get("worker_tool_receipts", [])
    if not isinstance(tool_receipts, Sequence) or isinstance(tool_receipts, (str, bytes)):
        failures.append("Worker tool execution receipts are missing")
        tool_receipts = []
    tool_receipts_by_id: dict[str, Mapping[str, Any]] = {}
    for receipt in tool_receipts:
        if not isinstance(receipt, Mapping):
            failures.append("Worker tool execution receipt is malformed")
            continue
        execution_id = str(receipt.get("execution_id", ""))
        actor_id = str(receipt.get("actor_id", ""))
        container_id = str(receipt.get("container_id", ""))
        tool = str(receipt.get("tool", ""))
        exec_export = receipt.get("docker_exec_export", {})
        receipt_input = receipt.get("input")
        receipt_output = receipt.get("output")
        receipt_stdout = receipt.get("stdout")
        receipt_stderr = receipt.get("stderr")
        process_config = (
            exec_export.get("ProcessConfig", {}) if isinstance(exec_export, Mapping) else {}
        )
        process_entrypoint = (
            process_config.get("entrypoint") if isinstance(process_config, Mapping) else None
        )
        process_arguments = (
            process_config.get("arguments", []) if isinstance(process_config, Mapping) else []
        )
        observed_exec_argv = (
            [process_entrypoint, *process_arguments]
            if isinstance(process_entrypoint, str)
            and process_entrypoint
            and isinstance(process_arguments, Sequence)
            and not isinstance(process_arguments, (str, bytes))
            and all(isinstance(item, str) for item in process_arguments)
            else []
        )
        expected_skill_digest = (
            file_digest(PROJECT_ROOT / "skills/remedyfabric-recovery/SKILL.md")
            if tool == _RECOVERY_SKILL
            else _load_json(PROJECT_ROOT / "agentteams/official-alibaba-cloud-skill.lock.json")
            .get("skill", {})
            .get("aggregate_sha256")
            if tool == _ALIBABA_CLOUD_SKILL
            else file_digest(PROJECT_ROOT / "scripts/agentteams_role_tool.py")
            if tool == _ROLE_HELPER
            else None
        )
        expected_operation = (
            "proposer"
            if tool == _RECOVERY_SKILL
            else "alibaba-cloud-preflight"
            if tool == _ALIBABA_CLOUD_SKILL
            else _ROLE_OPERATIONS.get(actor_id)
        )
        expected_helper_digest = file_digest(PROJECT_ROOT / "scripts/agentteams_role_tool.py")
        source_digest = _source_bundle_digest(PROJECT_ROOT)
        expected_runtime_files = _runtime_file_expectations(tool)
        receipt_unsigned = dict(receipt)
        claimed_receipt_digest = receipt_unsigned.pop("receipt_digest", None)
        # Matrix assigns event_id only after the role execution receipt has
        # already been embedded in the outbound typed event.  Keep event_id as
        # an authenticated post-send linkage, not a circular digest input.
        receipt_unsigned.pop("event_id", None)
        try:
            receipt_started = datetime.fromisoformat(str(receipt.get("started_at_utc", "")))
            receipt_finished = datetime.fromisoformat(str(receipt.get("finished_at_utc", "")))
            receipt_window_valid = (
                capture_started <= receipt_started <= receipt_finished <= capture_finished
            )
        except ValueError:
            receipt_window_valid = False
        if not (
            _HEX_DIGEST.fullmatch(execution_id)
            and execution_id not in tool_receipts_by_id
            and tool in {_RECOVERY_SKILL, _ALIBABA_CLOUD_SKILL, _ROLE_HELPER}
            and receipt.get("run_id") == captured_run_id
            and receipt.get("task_digest") == captured_task_digest
            and receipt.get("challenge_nonce") == challenge_nonce
            and receipt.get("actor_matrix_id") == component_senders.get(actor_id)
            and container_id in inspect_by_id
            and receipt.get("image_id") == inspect_by_id.get(container_id, {}).get("Image")
            and isinstance(receipt.get("argv"), Sequence)
            and not isinstance(receipt.get("argv"), (str, bytes))
            and bool(receipt.get("argv"))
            and isinstance(receipt.get("cwd"), str)
            and receipt.get("skill_files_sha256") == expected_skill_digest
            and receipt.get("role_helper_sha256") == expected_helper_digest
            and receipt.get("source_bundle_sha256") == source_digest
            and _binding_export_valid(
                receipt.get("runtime_file_binding"),
                container_id=container_id,
                expected_files=expected_runtime_files,
            )
            and receipt.get("operation") == expected_operation
            and expected_operation is not None
            and _role_argv_valid(receipt.get("argv"), expected_operation)
            and receipt.get("input_sha256") == canonical_digest(receipt_input)
            and isinstance(receipt_stdout, str)
            and receipt.get("stdout_sha256") == _sha256_text(receipt_stdout)
            and isinstance(receipt_stderr, str)
            and receipt.get("stderr_sha256") == _sha256_text(receipt_stderr)
            and receipt.get("output_sha256") == canonical_digest(receipt_output)
            and isinstance(receipt_output, Mapping)
            and json.loads(receipt_stdout) == receipt_output
            and _UTC_TIMESTAMP.fullmatch(str(receipt.get("started_at_utc", "")))
            and _UTC_TIMESTAMP.fullmatch(str(receipt.get("finished_at_utc", "")))
            and receipt_window_valid
            and receipt.get("timed_out") is False
            and isinstance(exec_export, Mapping)
            and receipt.get("docker_exec_export_digest") == canonical_digest(exec_export)
            and exec_export.get("ContainerID") == container_id
            and exec_export.get("Running") is False
            and exec_export.get("ExitCode") == receipt.get("exit_code")
            and observed_exec_argv == list(receipt.get("argv", []))
            and claimed_receipt_digest == canonical_digest(receipt_unsigned)
        ):
            failures.append(
                f"Worker tool execution receipt is invalid: {execution_id or '[missing]'}"
            )
            continue
        tool_receipts_by_id[execution_id] = receipt
    for invocation in skill_invocations:
        if not isinstance(invocation, Mapping):
            continue
        event_id = str(invocation.get("event_id", ""))
        actor_id = str(invocation.get("actor_id", ""))
        event = events_by_id.get(event_id, {})
        output = invocation.get("output", {})
        candidate = output.get("patch_candidate", {}) if isinstance(output, Mapping) else {}
        edits = candidate.get("edits", []) if isinstance(candidate, Mapping) else []
        edit_paths_safe = bool(edits) and all(
            isinstance(edit, Mapping)
            and isinstance(edit.get("old"), str)
            and isinstance(edit.get("new"), str)
            and bool(str(edit.get("path", "")))
            and not PurePosixPath(str(edit.get("path", ""))).is_absolute()
            and ".." not in PurePosixPath(str(edit.get("path", ""))).parts
            for edit in edits
        )
        candidate_binding = (
            {
                "skill_name": candidate.get("skill_name"),
                "skill_version": candidate.get("skill_version"),
                "provider_name": candidate.get("provider_name"),
                "provider_version": candidate.get("provider_version"),
                "edits": [
                    {"path": edit.get("path"), "old": edit.get("old"), "new": edit.get("new")}
                    for edit in edits
                    if isinstance(edit, Mapping)
                ],
            }
            if isinstance(candidate, Mapping)
            else {}
        )
        candidate_digest = canonical_digest(candidate_binding)
        raw_body = str(event.get("raw_event", {}).get("content", {}).get("body", ""))
        execution_id = str(invocation.get("execution_id", ""))
        execution_receipt = tool_receipts_by_id.get(execution_id, {})
        event_content = event.get("raw_event", {}).get("content", {})
        protocol = (
            _protocol_from_content(event_content, actor_id)
            if isinstance(event_content, Mapping)
            else {}
        )
        if (
            invocation.get("skill") == _RECOVERY_SKILL
            and invocation.get("skill_version") == _RECOVERY_SKILL_VERSION
            and invocation.get("status") == "completed"
            and event.get("function") == "proposer"
            and event.get("stage") == "tool_execute"
            and actor_id == event.get("actor_id")
            and actor_id in worker_actor_ids
            and invocation.get("evidence_digest") == event_digests.get(event_id)
            and isinstance(output, Mapping)
            and invocation.get("output_digest") == canonical_digest(output)
            and candidate.get("skill_name") == _RECOVERY_SKILL
            and candidate.get("skill_version") == _RECOVERY_SKILL_VERSION
            and bool(str(candidate.get("provider_name", "")))
            and bool(str(candidate.get("provider_version", "")))
            and edit_paths_safe
            and invocation.get("candidate_digest") == candidate_digest
            and candidate_digest in raw_body
            and execution_receipt.get("tool") == _RECOVERY_SKILL
            and execution_receipt.get("event_id") == event_id
            and execution_receipt.get("actor_id") == actor_id
            and execution_receipt.get("exit_code") == 0
            and execution_receipt.get("candidate_digest") == candidate_digest
            and execution_receipt.get("input") == invocation.get("input")
            and invocation.get("input_digest") == canonical_digest(invocation.get("input"))
            and execution_receipt.get("output") == output
            and execution_receipt.get("output_sha256") == invocation.get("output_digest")
            and isinstance(protocol, Mapping)
            and protocol.get("output_receipt_digest") == execution_receipt.get("receipt_digest")
            and execution_id in raw_body
            and execution_receipt.get("receipt_digest") in raw_body
        ):
            valid_recovery_candidates[actor_id] = candidate_digest
    if not (
        set(valid_recovery_candidates) == {"rf-proposer-a", "rf-proposer-b"}
        and len(set(valid_recovery_candidates.values())) == 1
    ):
        failures.append(
            "two distinct proposer Skill executions do not converge on one trace-bound candidate"
        )

    task_receipt = output_by_actor_stage.get(("manager", "delegate"))
    expected_task_receipt = canonical_digest(
        {
            "kind": "task",
            "run_id": captured_run_id,
            "task_digest": captured_task_digest,
            "task": evidence.get("task"),
        }
    )
    if task_receipt != expected_task_receipt:
        failures.append("Manager delegation does not emit the bound task receipt")

    proposer_stage_receipts: dict[str, str] = {}
    for actor_id in ("rf-proposer-a", "rf-proposer-b"):
        invocation = next(
            (
                item
                for item in skill_invocations
                if isinstance(item, Mapping) and item.get("actor_id") == actor_id
            ),
            {},
        )
        output = invocation.get("output", {}) if isinstance(invocation, Mapping) else {}
        proposal = output.get("proposal", {}) if isinstance(output, Mapping) else {}
        expected_proposal_receipt = canonical_digest(
            {
                "kind": "proposal",
                "actor_id": actor_id,
                "candidate_digest": invocation.get("candidate_digest"),
                "proposal": proposal,
            }
        )
        observed = output_by_actor_stage.get((actor_id, "propose"))
        propose_event = next(
            (
                item
                for item in trace
                if isinstance(item, Mapping)
                and item.get("actor_id") == actor_id
                and item.get("stage") == "propose"
            ),
            {},
        )
        propose_protocol = protocol_by_event_id.get(str(propose_event.get("event_id", "")), {})
        recovery_receipt = tool_receipts_by_id.get(str(invocation.get("execution_id", "")), {})
        if not (
            observed == expected_proposal_receipt
            and propose_protocol.get("input_receipt_digests")
            == [recovery_receipt.get("receipt_digest")]
        ):
            failures.append(f"proposal event is not derived from its Skill receipt: {actor_id}")
        else:
            proposer_stage_receipts[actor_id] = observed

    delegate_event = next(
        (
            item
            for item in trace
            if isinstance(item, Mapping)
            and item.get("actor_id") == "manager"
            and item.get("stage") == "delegate"
        ),
        {},
    )
    delegate_protocol = protocol_by_event_id.get(str(delegate_event.get("event_id", "")), {})
    if delegate_protocol.get("input_receipt_digests") != []:
        failures.append("Manager delegation unexpectedly consumes a prior receipt")
    for actor_id in ("rf-proposer-a", "rf-proposer-b"):
        invocation = next(
            (
                item
                for item in skill_invocations
                if isinstance(item, Mapping) and item.get("actor_id") == actor_id
            ),
            {},
        )
        tool_event = events_by_id.get(str(invocation.get("event_id", "")), {})
        tool_protocol = protocol_by_event_id.get(str(tool_event.get("event_id", "")), {})
        if tool_protocol.get("input_receipt_digests") != [task_receipt]:
            failures.append(f"proposer Skill execution does not consume the task: {actor_id}")

    cloud_invocation_record = evidence.get("alibaba_cloud_skill", {}).get("invocation", {})
    cloud_event_record = events_by_id.get(str(cloud_invocation_record.get("event_id", "")), {})
    cloud_protocol = protocol_by_event_id.get(str(cloud_event_record.get("event_id", "")), {})
    proposal_receipt_set = set(proposer_stage_receipts.values())
    if set(cloud_protocol.get("input_receipt_digests", [])) != proposal_receipt_set:
        failures.append("Alibaba Cloud Skill preflight is not causally bound to both proposals")
    cloud_execution_receipt = tool_receipts_by_id.get(
        str(cloud_invocation_record.get("execution_id", "")), {}
    )
    if not (
        cloud_execution_receipt.get("input", {}).get("input_receipt_digests")
        == list(proposer_stage_receipts.values())
        and cloud_execution_receipt.get("output", {}).get("consumed_receipt_digests")
        == sorted(proposer_stage_receipts.values())
    ):
        failures.append("Alibaba Cloud Skill helper did not consume both proposal receipts")

    role_receipts = [
        receipt for receipt in tool_receipts_by_id.values() if receipt.get("tool") == _ROLE_HELPER
    ]
    role_receipts_by_actor: dict[str, Mapping[str, Any]] = {}
    for receipt in role_receipts:
        actor_id = str(receipt.get("actor_id", ""))
        output = receipt.get("output", {})
        raw_stdout = str(receipt.get("stdout", ""))
        try:
            parsed_stdout = json.loads(raw_stdout)
        except json.JSONDecodeError:
            parsed_stdout = None
        event = events_by_id.get(str(receipt.get("event_id", "")), {})
        event_content = event.get("raw_event", {}).get("content", {})
        protocol = (
            _protocol_from_content(event_content, actor_id)
            if isinstance(event_content, Mapping)
            else {}
        )
        raw_body = str(event.get("raw_event", {}).get("content", {}).get("body", ""))
        expected_operation = _ROLE_OPERATIONS.get(actor_id)
        if not (
            actor_id in running_worker_ids
            and actor_id not in role_receipts_by_actor
            and receipt.get("operation") == expected_operation
            and isinstance(output, Mapping)
            and parsed_stdout == output
            and receipt.get("exit_code") == 0
            and event.get("function") == component_functions.get(actor_id)
            and isinstance(protocol, Mapping)
            and protocol.get("output_receipt_digest") == receipt.get("receipt_digest")
            and output.get("consumed_receipt_digests")
            == sorted(protocol.get("input_receipt_digests", []))
            and receipt.get("input", {}).get("input_receipt_digests")
            == protocol.get("input_receipt_digests")
            and receipt.get("execution_id") in raw_body
            and receipt.get("receipt_digest") in raw_body
        ):
            failures.append(f"role helper execution is not trace-bound: {actor_id or '[missing]'}")
            continue
        role_receipts_by_actor[actor_id] = receipt

    required_role_actors = {
        "rf-verifier",
        "rf-verifier-b",
        "rf-lead",
        "rf-challenger",
        "rf-governor",
        "rf-release-manager",
    }
    if set(role_receipts_by_actor) != required_role_actors:
        failures.append("the complete control plane lacks trace-bound role helper executions")
    control_receipt_by_actor = {
        actor_id: str(receipt.get("receipt_digest", ""))
        for actor_id, receipt in role_receipts_by_actor.items()
        if actor_id != "rf-release-manager"
    }
    expected_control_inputs = {
        "rf-verifier": [
            *proposer_stage_receipts.values(),
            str(
                tool_receipts_by_id.get(
                    str(cloud_invocation_record.get("execution_id", "")), {}
                ).get("receipt_digest", "")
            ),
        ],
        "rf-verifier-b": list(proposer_stage_receipts.values()),
        "rf-lead": list(proposer_stage_receipts.values()),
        "rf-challenger": list(proposer_stage_receipts.values()),
        "rf-governor": list(proposer_stage_receipts.values()),
    }
    for actor_id, expected_inputs in expected_control_inputs.items():
        receipt = role_receipts_by_actor.get(actor_id, {})
        if receipt.get("input", {}).get("input_receipt_digests") != expected_inputs:
            failures.append(f"control helper consumes an unexpected receipt set: {actor_id}")

    converged_candidate: PatchCandidate | None = None
    proposer_objects: list[CandidateProposal] = []
    for actor_id in ("rf-proposer-a", "rf-proposer-b"):
        invocation = next(
            (
                item
                for item in skill_invocations
                if isinstance(item, Mapping) and item.get("actor_id") == actor_id
            ),
            {},
        )
        output = invocation.get("output", {}) if isinstance(invocation, Mapping) else {}
        try:
            candidate_object = _candidate_from_output(output)
            proposal_object = _proposal_from_output(output, candidate_object)
        except (TypeError, ValueError):
            failures.append(f"proposer helper output cannot be reconstructed: {actor_id}")
            continue
        if converged_candidate is None:
            converged_candidate = candidate_object
        if patch_digest(candidate_object) != patch_digest(converged_candidate):
            failures.append("proposer helper outputs do not converge on one executable patch")
        proposer_objects.append(proposal_object)

    attestation_objects: list[Attestation] = []
    expected_control_roles = {
        "rf-verifier": AgentRole.VERIFIER,
        "rf-verifier-b": AgentRole.VERIFIER,
        "rf-challenger": AgentRole.CHALLENGER,
        "rf-governor": AgentRole.GOVERNOR,
    }
    for actor_id, expected_role in expected_control_roles.items():
        receipt = role_receipts_by_actor.get(actor_id, {})
        output = receipt.get("output", {}) if isinstance(receipt, Mapping) else {}
        try:
            attestation = _attestation_from_output(output)
        except (TypeError, ValueError):
            failures.append(f"control helper output cannot be reconstructed: {actor_id}")
            continue
        artifact = output.get("artifact", {}) if isinstance(output, Mapping) else {}
        expected_kind = {
            AgentRole.VERIFIER: EvidenceKind.TEST,
            AgentRole.CHALLENGER: EvidenceKind.CHALLENGE,
            AgentRole.GOVERNOR: EvidenceKind.POLICY,
        }[expected_role]
        artifact_semantics_valid = False
        if expected_role in {AgentRole.VERIFIER, AgentRole.CHALLENGER}:
            artifact_semantics_valid = bool(
                isinstance(artifact, Mapping)
                and artifact.get("actor_id") == actor_id
                and artifact.get("returncodes") == [0, 0]
                and len(artifact.get("commands", [])) == 2
                and all(
                    isinstance(item, str) and _HEX_DIGEST.fullmatch(item)
                    for key in ("stdout_sha256", "stderr_sha256")
                    for item in artifact.get(key, [])
                )
            )
        elif expected_role is AgentRole.GOVERNOR:
            artifact_semantics_valid = bool(
                isinstance(artifact, Mapping)
                and artifact.get("approved") is True
                and artifact.get("risk_score") == 0
                and artifact.get("reasons") == []
            )
        if not (
            attestation.identity.actor_id == actor_id
            and attestation.identity.role is expected_role
            and attestation.verdict is Verdict.APPROVE
            and attestation.integrity_valid
            and attestation.binding.run_id == captured_run_id
            and converged_candidate is not None
            and attestation.binding.candidate_digest == patch_digest(converged_candidate)
            and proposer_objects
            and attestation.binding.snapshot_digest == proposer_objects[0].snapshot_digest
            and attestation.binding.kind is expected_kind
            and attestation.binding.artifact_digest == canonical_digest(artifact)
            and artifact_semantics_valid
        ):
            failures.append(f"control helper attestation is invalid: {actor_id}")
        attestation_objects.append(attestation)

    reviewer_output = role_receipts_by_actor.get("rf-lead", {}).get("output", {})
    if not (
        isinstance(reviewer_output, Mapping)
        and reviewer_output.get("artifact", {}).get("converged") is True
        and reviewer_output.get("artifact", {}).get("authority_boundary")
        == "review-only; not a quorum attestation or release authority"
        and reviewer_output.get("review_receipt_digest")
        == canonical_digest(reviewer_output.get("artifact", {}))
        and reviewer_output.get("artifact", {}).get("candidate_digest")
        == (patch_digest(converged_candidate) if converged_candidate is not None else None)
        and reviewer_output.get("artifact", {}).get("observed_proposer_actors")
        == ["rf-proposer-a", "rf-proposer-b"]
        and reviewer_output.get("artifact", {}).get("proposal_integrity") == [True, True]
        and reviewer_output.get("artifact", {}).get("proposal_receipt_digests")
        == sorted(proposer_stage_receipts.values())
    ):
        failures.append("review helper did not recompute bounded proposal convergence")

    release_output = role_receipts_by_actor.get("rf-release-manager", {}).get("output", {})
    release_receipt = role_receipts_by_actor.get("rf-release-manager", {})
    release_input = release_receipt.get("input", {}) if isinstance(release_receipt, Mapping) else {}
    exact_release_inputs = [
        *proposer_stage_receipts.values(),
        *(
            control_receipt_by_actor.get(actor_id, "")
            for actor_id in (
                "rf-verifier",
                "rf-verifier-b",
                "rf-lead",
                "rf-challenger",
                "rf-governor",
            )
        ),
    ]
    if release_input.get("input_receipt_digests") != exact_release_inputs:
        failures.append("release helper does not consume the exact control DAG")
    if converged_candidate is None or len(proposer_objects) != 2 or len(attestation_objects) != 4:
        failures.append("release helper inputs cannot be reconstructed")
    else:
        input_candidate_valid = False
        input_proposals_valid = False
        input_attestations_valid = False
        try:
            input_candidate = _candidate_from_payload(release_input.get("candidate"))
            input_proposals = [
                _proposal_from_payload(item, input_candidate)
                for item in release_input.get("proposals", [])
            ]
            input_attestations = [
                _attestation_from_output({"attestation": item})
                for item in release_input.get("attestations", [])
            ]
            input_candidate_valid = patch_digest(input_candidate) == patch_digest(
                converged_candidate
            )
            input_proposals_valid = input_proposals == proposer_objects
            input_attestations_valid = input_attestations == attestation_objects
        except (TypeError, ValueError):
            pass
        reconstructed = QuorumGate(
            (
                AgentIdentity("rf-proposer-a", AgentRole.WORKER),
                AgentIdentity("rf-proposer-b", AgentRole.WORKER),
                AgentIdentity("rf-verifier", AgentRole.VERIFIER),
                AgentIdentity("rf-verifier-b", AgentRole.VERIFIER),
                AgentIdentity("rf-challenger", AgentRole.CHALLENGER),
                AgentIdentity("rf-governor", AgentRole.GOVERNOR),
                AgentIdentity("rf-release-manager", AgentRole.RELEASE_MANAGER),
            )
        ).evaluate(
            run_id=captured_run_id,
            snapshot_digest=proposer_objects[0].snapshot_digest,
            candidate=converged_candidate,
            proposals=proposer_objects,
            attestations=attestation_objects,
            requested_by=AgentIdentity("rf-release-manager", AgentRole.RELEASE_MANAGER),
        )
        if not (
            isinstance(release_output, Mapping)
            and release_output.get("decision") == reconstructed.to_dict()
            and reconstructed.authorized
            and input_candidate_valid
            and input_proposals_valid
            and input_attestations_valid
            and release_input.get("run_id") == captured_run_id
            and release_input.get("snapshot_digest") == proposer_objects[0].snapshot_digest
        ):
            failures.append("release helper decision does not replay through QuorumGate")

    terminal = evidence.get("terminal_decision", {})
    terminal_event = (
        events_by_id.get(str(terminal.get("event_id", "")), {})
        if isinstance(terminal, Mapping)
        else {}
    )
    terminal_protocol = (
        _protocol_from_content(
            terminal_event.get("raw_event", {}).get("content", {}),
            str(terminal_event.get("actor_id", "")),
        )
        if isinstance(terminal_event, Mapping)
        else {}
    )
    if not isinstance(terminal, Mapping):
        failures.append("terminal_decision is missing")
    elif not (
        terminal.get("decision") in {"release", "rollback"}
        and terminal.get("verified") is True
        and terminal.get("event_id") in event_ids
        and terminal.get("evidence_digest") == event_digests.get(terminal.get("event_id"))
        and events_by_id.get(str(terminal.get("event_id", "")), {}).get("function")
        == "release-manager"
        and events_by_id.get(str(terminal.get("event_id", "")), {}).get("stage") == "decide"
        and isinstance(terminal_protocol, Mapping)
        and terminal_protocol.get("decision") == terminal.get("decision")
        and terminal_protocol.get("output_receipt_digest")
        == terminal.get("decision_receipt_digest")
        and terminal.get("decision_receipt_digest") == decision_receipt
        and terminal.get("decision")
        == (
            release_output.get("decision", {}).get("action")
            if isinstance(release_output, Mapping)
            else None
        )
    ):
        failures.append("terminal decision is not verified and evidence-bound")

    probes = evidence.get("acl_probes", [])
    if not isinstance(probes, Sequence) or isinstance(probes, (str, bytes)):
        failures.append("acl_probes must be a sequence")
        probes = []
    acl_valid = False
    for probe in probes:
        if not isinstance(probe, Mapping):
            continue
        request = probe.get("authenticated_request", {})
        response = probe.get("response", {})
        exec_export = probe.get("docker_exec_export", {})
        container_id = str(probe.get("container_id", ""))
        if (
            probe.get("expected") == "deny"
            and probe.get("allowed") is False
            and probe.get("status_code") in {401, 403}
            and probe.get("challenge_nonce") == challenge_nonce
            and probe.get("actor_id") in running_worker_ids
            and probe.get("actor_matrix_id")
            == component_senders.get(str(probe.get("actor_id", "")))
            and container_id in inspect_by_id
            and isinstance(request, Mapping)
            and request.get("method") == "GET"
            and str(request.get("path", "")).startswith("/api/")
            and request.get("request_digest")
            == canonical_digest(
                {
                    "method": request.get("method"),
                    "path": request.get("path"),
                    "challenge_nonce": challenge_nonce,
                }
            )
            and isinstance(response, Mapping)
            and probe.get("response_digest") == canonical_digest(response)
            and isinstance(exec_export, Mapping)
            and probe.get("docker_exec_export_digest") == canonical_digest(exec_export)
            and exec_export.get("ContainerID") == container_id
            and exec_export.get("Running") is False
            and exec_export.get("ExitCode") == 0
        ):
            acl_valid = True
    if not acl_valid:
        failures.append("no expected-deny ACL probe was observed as denied")

    provider = evidence.get("provider", {})
    if not isinstance(provider, Mapping) or provider.get("external_network") is not False:
        failures.append("provider boundary does not prove local-only execution")
    if isinstance(provider, Mapping) and provider.get("cost_usd") != 0:
        failures.append("provider cost is not explicitly recorded as zero")
    if isinstance(provider, Mapping) and provider.get("commercial_api_used") is not False:
        failures.append("provider boundary does not exclude commercial API use")
    if isinstance(provider, Mapping) and provider.get("official_gateway_http_status") != 200:
        failures.append("official AgentTeams model gateway did not record HTTP 200")
    if isinstance(provider, Mapping):
        model = provider.get("model_capture", {})
        ollama = provider.get("ollama_version_export", {})
        show = provider.get("ollama_show_export", {})
        gateway = provider.get("gateway_probe", {})
        if not (
            isinstance(model, Mapping)
            and model.get("tag") == "gpt-oss:20b"
            and _HEX_DIGEST.fullmatch(str(model.get("digest", "")))
            and isinstance(model.get("parameter_size"), str)
            and isinstance(model.get("quantization"), str)
            and isinstance(model.get("license"), str)
            and isinstance(ollama, Mapping)
            and provider.get("ollama_version_export_digest") == canonical_digest(ollama)
            and isinstance(show, Mapping)
            and provider.get("ollama_show_export_digest") == canonical_digest(show)
            and show.get("model_info_digest") == model.get("digest")
            and isinstance(gateway, Mapping)
            and gateway.get("status_code") == 200
            and gateway.get("run_id") == captured_run_id
            and gateway.get("challenge_nonce") == challenge_nonce
            and gateway.get("request_digest") == canonical_digest(gateway.get("request"))
            and gateway.get("response_digest") == canonical_digest(gateway.get("response"))
        ):
            failures.append("local model and official gateway capture is incomplete or unbound")

    cloud_skill = evidence.get("alibaba_cloud_skill", {})
    if not isinstance(cloud_skill, Mapping):
        failures.append("Alibaba Cloud Skill record is missing")
    else:
        if cloud_skill.get("package_verified") is not True:
            failures.append("official Alibaba Cloud Skill package was not verified")
        if cloud_skill.get("assigned_to_worker") is not True:
            failures.append("official Alibaba Cloud Skill was not assigned to a Worker")
        if cloud_skill.get("cloud_api_invoked") is not False:
            failures.append("cloud API boundary must explicitly state that no call was made")
        invocation = cloud_skill.get("invocation", {})
        event_id = str(invocation.get("event_id", "")) if isinstance(invocation, Mapping) else ""
        event = events_by_id.get(event_id, {})
        raw_body = str(event.get("raw_event", {}).get("content", {}).get("body", ""))
        execution_id = (
            str(invocation.get("execution_id", "")) if isinstance(invocation, Mapping) else ""
        )
        execution_receipt = tool_receipts_by_id.get(execution_id, {})
        if not (
            isinstance(invocation, Mapping)
            and invocation.get("skill") == _ALIBABA_CLOUD_SKILL
            and invocation.get("status") == "blocked_before_cloud_api"
            and invocation.get("reason_code") == "missing_credentials"
            and invocation.get("credential_present") is False
            and invocation.get("request_sent") is False
            and invocation.get("cost_usd") == 0
            and event.get("function") == "verifier"
            and event.get("stage") == "tool_execute"
            and invocation.get("actor_id") == event.get("actor_id")
            and invocation.get("evidence_digest") == event_digests.get(event_id)
            and _ALIBABA_CLOUD_SKILL in raw_body
            and "blocked_before_cloud_api" in raw_body
            and execution_receipt.get("tool") == _ALIBABA_CLOUD_SKILL
            and execution_receipt.get("event_id") == event_id
            and execution_receipt.get("actor_id") == invocation.get("actor_id")
            and execution_receipt.get("exit_code") == 2
            and execution_receipt.get("reason_code") == "missing_credentials"
            and execution_receipt.get("request_sent") is False
            and execution_id in raw_body
            and execution_receipt.get("receipt_digest") in raw_body
        ):
            failures.append("official Alibaba Cloud Skill preflight is not trace-bound")

    serialized = json.dumps(redact_public(evidence), ensure_ascii=False).lower()
    for marker in (
        "local-ollama-no-secret",
        "bearer ey",
        "accesskeysecret",
        "ghp_",
        "github_pat_",
        "syt_",
    ):
        if marker in serialized:
            failures.append(f"public evidence contains a credential marker: {marker}")
    return failures


def write_public_evidence(path: Path, evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Redact, validate, and bind a public AgentTeams evidence artifact in memory."""

    public = redact_public(dict(evidence))
    failures = validate_live_evidence(public)
    public["validation"] = {
        "passed": not failures,
        "failures": failures,
    }
    public["evidence_digest"] = canonical_digest(public)
    return public


def persist_validated_live_evidence(path: Path, evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Atomically publish only a fully validated production live receipt."""

    import os
    import tempfile

    public = write_public_evidence(path, evidence)
    if public.get("validation", {}).get("passed") is not True:
        return public
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(public, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return public


def live_evidence_is_valid(evidence: Mapping[str, Any] | None) -> bool:
    """Revalidate a persisted receipt and its self-digest instead of trusting a status flag."""

    if not evidence or evidence.get("validation", {}).get("passed") is not True:
        return False
    failures = validate_live_evidence(evidence)
    if failures:
        return False
    unsigned = dict(evidence)
    expected = unsigned.pop("evidence_digest", None)
    return isinstance(expected, str) and expected == canonical_digest(unsigned)
