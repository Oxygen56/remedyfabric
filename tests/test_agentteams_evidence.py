from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from typing import Any

from remedyfabric.agentteams_evidence import (
    OFFICIAL_COMMIT,
    OFFICIAL_REPOSITORY,
    OFFICIAL_TAG,
    canonical_digest,
    file_digest,
    live_evidence_is_valid,
    redact_public,
    validate_live_evidence,
    write_public_evidence,
)
from remedyfabric.release_integrity import source_tree_digest
from scripts.agentteams_role_tool import EXPECTED_NEW, EXPECTED_OLD, execute

ROOT = Path(__file__).resolve().parents[1]
CAPTURE_TOOL = ROOT / "scripts/capture_agentteams_live.py"
TEAM_MANIFEST = ROOT / "agentteams/remedyfabric-live-local.yaml"
IMAGE_LOCK = ROOT / "agentteams/official-runtime-images.lock.json"
CLOUD_SKILL_LOCK = ROOT / "agentteams/official-alibaba-cloud-skill.lock.json"
RECOVERY_SKILL = ROOT / "skills/remedyfabric-recovery/SKILL.md"
ROLE_HELPER = ROOT / "scripts/agentteams_role_tool.py"
MATRIX_SENDER = ROOT / "scripts/agentteams_matrix_sender.py"
VISIBLE_TEST = (
    "import unittest\nfrom app.service import mean\n\n"
    "class VisibleMeanTests(unittest.TestCase):\n"
    "    def test_empty(self): self.assertEqual(mean([]), 0.0)\n"
)
INVARIANT_TEST = (
    "import unittest\nfrom app.service import mean\n\n"
    "class MeanInvariantTests(unittest.TestCase):\n"
    "    def test_nonempty(self): self.assertEqual(mean([2, 4]), 3.0)\n"
)


def _source_bundle_manifest() -> dict[str, str]:
    return {
        path.relative_to(ROOT).as_posix(): file_digest(path)
        for path in sorted((ROOT / "src/remedyfabric").glob("*.py"))
        if path.is_file()
    }


def _source_bundle_digest() -> str:
    return canonical_digest(_source_bundle_manifest())


def _runtime_files(tool: str, skill_digest: str) -> dict[str, str]:
    files = {
        "role-helper": file_digest(ROLE_HELPER),
        **{f"source:{relative}": digest for relative, digest in _source_bundle_manifest().items()},
    }
    if tool == "remedyfabric-recovery":
        files["skill:SKILL.md"] = skill_digest
    elif tool == "alibabacloud-resourcecenter-search":
        files.update(
            {
                f"skill:{relative}": digest
                for relative, digest in _load(CLOUD_SKILL_LOCK)["skill"]["files"].items()
            }
        )
    else:
        files["skill:role-helper"] = skill_digest
    return files


def _text_digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _template_snapshot_digest() -> str:
    digest = hashlib.sha256()
    for relative, content in sorted(
        {
            "app/service.py": EXPECTED_OLD,
            "tests/test_service.py": VISIBLE_TEST,
            "invariants/test_invariant.py": INVARIANT_TEST,
        }.items()
    ):
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update((0o644).to_bytes(4, "big"))
        digest.update(content.encode("utf-8"))
    return digest.hexdigest()


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _manager_body(protocol: dict[str, Any], body: str) -> str:
    human_body = body.split("\n", 1)[1] if body.startswith("RFPROTO:") else body
    encoded = json.dumps(
        protocol,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"RFPROTO:{encoded}\n{human_body}"


def _component(
    *,
    actor_id: str,
    role: str,
    function: str,
    image: str,
    image_id: str,
    container_id: str,
) -> dict[str, Any]:
    name = "agentteams-manager" if actor_id == "manager" else f"agentteams-worker-{actor_id}"
    return {
        "role": role,
        "name": name,
        "actor_id": actor_id,
        "matrix_id": f"@{actor_id}:matrix.synthetic.invalid",
        "function": function,
        "image": image,
        "image_digest": image_id,
        "container_id": container_id,
        "state": "running",
    }


def _container_export(*, container_id: str, name: str, image: str, image_id: str) -> dict[str, Any]:
    return {
        "Id": container_id,
        "Name": f"/{name}",
        "Image": image_id,
        "Config": {"Image": image},
        "State": {"Running": True, "StartedAt": "2026-08-13T00:00:00Z"},
        "RestartCount": 0,
        "NetworkSettings": {"Networks": {"agentteams": {"NetworkID": "synthetic-shape-only"}}},
    }


def _tool_receipt(
    *,
    execution_id: str,
    run_id: str,
    task_digest: str,
    nonce: str,
    actor_id: str,
    actor_matrix_id: str,
    container_id: str,
    image_id: str,
    event_id: str,
    tool: str,
    operation: str,
    skill_digest: str,
    input_path: str,
    input_payload: dict[str, Any],
    output_payload: dict[str, Any],
    exit_code: int,
    ordinal: int,
    candidate_digest: str | None = None,
    reason_code: str | None = None,
) -> dict[str, Any]:
    argv = [
        "python3",
        "scripts/agentteams_role_tool.py",
        "--role",
        operation,
        "--input",
        input_path,
    ]
    stdout = json.dumps(
        output_payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    receipt: dict[str, Any] = {
        "execution_id": execution_id,
        "run_id": run_id,
        "task_digest": task_digest,
        "challenge_nonce": nonce,
        "actor_id": actor_id,
        "actor_matrix_id": actor_matrix_id,
        "container_id": container_id,
        "image_id": image_id,
        "event_id": event_id,
        "tool": tool,
        "operation": operation,
        "argv": argv,
        "cwd": "/workspace/remedyfabric",
        "skill_files_sha256": skill_digest,
        "role_helper_sha256": file_digest(ROLE_HELPER),
        "source_bundle_sha256": _source_bundle_digest(),
        "input": input_payload,
        "input_sha256": canonical_digest(input_payload),
        "stdout": stdout,
        "stdout_sha256": _text_digest(stdout),
        "stderr": "",
        "stderr_sha256": _text_digest(""),
        "output": output_payload,
        "output_sha256": canonical_digest(output_payload),
        "started_at_utc": f"2026-08-13T00:00:{ordinal:02d}Z",
        "finished_at_utc": f"2026-08-13T00:00:{ordinal + 1:02d}Z",
        "timed_out": False,
        "exit_code": exit_code,
    }
    if candidate_digest is not None:
        receipt["candidate_digest"] = candidate_digest
    if reason_code is not None:
        receipt["reason_code"] = reason_code
        receipt["request_sent"] = False
    exec_export = {
        "ContainerID": container_id,
        "Running": False,
        "ExitCode": exit_code,
        "ProcessConfig": {"entrypoint": argv[0], "arguments": argv[1:]},
    }
    receipt["docker_exec_export"] = exec_export
    receipt["docker_exec_export_digest"] = canonical_digest(exec_export)
    runtime_files = _runtime_files(tool, skill_digest)
    runtime_paths = {
        key: (
            "/opt/remedyfabric/scripts/agentteams_role_tool.py"
            if key == "role-helper" or key == "skill:role-helper"
            else f"/opt/remedyfabric/{key.removeprefix('source:')}"
            if key.startswith("source:")
            else f"/opt/remedyfabric/skills/{key.removeprefix('skill:')}"
        )
        for key in runtime_files
    }
    ordered_keys = sorted(runtime_files)
    binding_stdout = "".join(
        f"{runtime_files[key]}  {runtime_paths[key]}\n" for key in ordered_keys
    )
    binding_argv = ["sha256sum", *(runtime_paths[key] for key in ordered_keys)]
    binding_export = {
        "ContainerID": container_id,
        "Running": False,
        "ExitCode": 0,
        "ProcessConfig": {
            "entrypoint": binding_argv[0],
            "arguments": binding_argv[1:],
        },
    }
    receipt["runtime_file_binding"] = {
        "algorithm": "sha256sum-v1",
        "container_id": container_id,
        "paths": runtime_paths,
        "files": runtime_files,
        "stdout": binding_stdout,
        "stdout_sha256": _text_digest(binding_stdout),
        "argv": binding_argv,
        "docker_exec_export": binding_export,
        "docker_exec_export_digest": canonical_digest(binding_export),
    }
    receipt_unsigned = dict(receipt)
    receipt_unsigned.pop("event_id")
    receipt["receipt_digest"] = canonical_digest(receipt_unsigned)
    return receipt


def _rebind_trace(evidence: dict[str, Any]) -> None:
    """Recompute only synthetic fixture bindings after a deliberate mutation."""

    previous_event_id: str | None = None
    previous_protocol_digest: str | None = None
    for event in evidence["trace"]:
        protocol = event["raw_event"]["content"]["com.remedyfabric.protocol"]
        protocol["previous_event_id"] = previous_event_id
        protocol["previous_protocol_digest"] = previous_protocol_digest
        protocol.pop("protocol_digest", None)
        protocol["protocol_digest"] = canonical_digest(protocol)
        if event["actor_id"] == "manager":
            event["raw_event"]["content"]["body"] = _manager_body(
                protocol, event["raw_event"]["content"]["body"]
            )
        previous_event_id = event["event_id"]
        previous_protocol_digest = protocol["protocol_digest"]

    components = {item["actor_id"]: item for item in evidence["components"]}
    authenticated_events = []
    for event in evidence["trace"]:
        actor_id = event["actor_id"]
        raw_event = copy.deepcopy(event["raw_event"])
        request_content = copy.deepcopy(raw_event["content"])
        send_response = {"event_id": event["event_id"]}
        send_capture: dict[str, Any] = {
            "transport": (
                "official-manager-api"
                if actor_id == "manager"
                else "worker-container-matrix-adapter"
            ),
            "actor_id": actor_id,
            "request_content": request_content,
            "request_content_digest": canonical_digest(request_content),
            "status_code": 200,
            "response": send_response,
            "response_digest": canonical_digest(send_response),
        }
        if actor_id == "manager":
            request_text = str(raw_event["content"]["body"])
            send_response = {"success": True, "message": "Message sent successfully to matrix"}
            send_capture.update(
                {
                    "request_path": "/api/messages/send",
                    "manager_container_id": components[actor_id]["container_id"],
                    "request_text": request_text,
                    "request_text_sha256": _text_digest(request_text),
                    "response": send_response,
                    "response_digest": canonical_digest(send_response),
                    "event_id_resolution": "authenticated-room-sync-match-by-exact-body",
                }
            )
        else:
            input_path = f"/tmp/rf-matrix-send-{event['sequence']:02d}.json"
            adapter_path = "/opt/remedyfabric/scripts/agentteams_matrix_sender.py"
            argv = [
                "python3",
                adapter_path,
                "--auth-state",
                f"/root/agentteams-fs/agents/{actor_id}/.qwenpaw/matrix_auth_state.json",
                "--room-id",
                event["room_id"],
                "--txn-id",
                f"rf-synthetic-{event['sequence']:02d}",
                "--input",
                input_path,
                "--timeout",
                "10",
            ]
            exec_export = {
                "ContainerID": components[actor_id]["container_id"],
                "Running": False,
                "ExitCode": 0,
                "ProcessConfig": {"entrypoint": argv[0], "arguments": argv[1:]},
            }
            send_capture.update(
                {
                    "container_id": components[actor_id]["container_id"],
                    "adapter_path": adapter_path,
                    "adapter_sha256": file_digest(MATRIX_SENDER),
                    "argv": argv,
                    "stdout": json.dumps(send_response, sort_keys=True, separators=(",", ":"))
                    + "\n",
                    "stdout_sha256": _text_digest(
                        json.dumps(send_response, sort_keys=True, separators=(",", ":")) + "\n"
                    ),
                    "stderr": "",
                    "stderr_sha256": _text_digest(""),
                    "docker_exec_export": exec_export,
                    "docker_exec_export_digest": canonical_digest(exec_export),
                }
            )
            binding_paths = {"adapter_sha256": adapter_path}
            binding_files = {"adapter_sha256": file_digest(MATRIX_SENDER)}
            binding_stdout = f"{file_digest(MATRIX_SENDER)}  {adapter_path}\n"
            binding_argv = ["sha256sum", adapter_path]
            binding_export = {
                "ContainerID": components[actor_id]["container_id"],
                "Running": False,
                "ExitCode": 0,
                "ProcessConfig": {
                    "entrypoint": binding_argv[0],
                    "arguments": binding_argv[1:],
                },
            }
            send_capture["adapter_file_binding"] = {
                "algorithm": "sha256sum-v1",
                "container_id": components[actor_id]["container_id"],
                "paths": binding_paths,
                "files": binding_files,
                "stdout": binding_stdout,
                "stdout_sha256": _text_digest(binding_stdout),
                "argv": binding_argv,
                "docker_exec_export": binding_export,
                "docker_exec_export_digest": canonical_digest(binding_export),
            }
        authenticated_events.append(
            {
                "actor_id": actor_id,
                "request_path": (
                    f"/_matrix/client/v3/rooms/{event['room_id']}/event/{event['event_id']}"
                ),
                "status_code": 200,
                "response": raw_event,
                "response_digest": canonical_digest(raw_event),
                "send_capture": send_capture,
            }
        )
    evidence["matrix_authenticated_exports"]["events"] = authenticated_events
    event_digests = {
        event["event_id"]: canonical_digest(event["raw_event"]) for event in evidence["trace"]
    }
    for invocation in evidence["skill_invocations"]:
        invocation["evidence_digest"] = event_digests[invocation["event_id"]]
    cloud = evidence["alibaba_cloud_skill"]["invocation"]
    cloud["evidence_digest"] = event_digests[cloud["event_id"]]
    terminal = evidence["terminal_decision"]
    terminal["evidence_digest"] = event_digests[terminal["event_id"]]

    shared = evidence["shared_context"]
    previous_state = shared["initial_state_digest"]
    transitions = []
    for event in evidence["trace"]:
        state_digest = canonical_digest(
            {
                "run_id": shared["run_id"],
                "previous_state_digest": previous_state,
                "raw_event_digest": event_digests[event["event_id"]],
                "stage": event["stage"],
                "actor_id": event["actor_id"],
            }
        )
        transitions.append(
            {
                "event_id": event["event_id"],
                "actor_id": event["actor_id"],
                "stage": event["stage"],
                "previous_state_digest": previous_state,
                "state_digest": state_digest,
            }
        )
        previous_state = state_digest
    shared["transitions"] = transitions
    shared["final_state_digest"] = previous_state


def valid_evidence() -> dict[str, Any]:
    """Build synthetic validator input; this is never evidence of a live run."""

    locks = _load(IMAGE_LOCK)
    images = locks["images"]
    run_id = "rfchain-synthetic-validator-fixture-20260813"
    task = {"kind": "bounded-recovery", "fixture": "shape-and-negative-tests-only"}
    task_digest = canonical_digest(task)
    nonce = "synthetic-nonce-" + "9" * 48
    actor_specs = [
        ("manager", "manager", "orchestrator", "manager"),
        ("rf-lead", "team-leader", "reviewer", "worker"),
        ("rf-proposer-a", "worker", "proposer", "worker"),
        ("rf-proposer-b", "worker", "proposer", "worker"),
        ("rf-verifier", "worker", "verifier", "worker"),
        ("rf-verifier-b", "worker", "verifier", "worker"),
        ("rf-challenger", "worker", "challenger", "worker"),
        ("rf-governor", "worker", "governor", "worker"),
        ("rf-release-manager", "worker", "release-manager", "worker"),
    ]
    container_ids = {
        actor_id: f"{index:x}" * 64
        for index, (actor_id, _role, _function, _image_key) in enumerate(actor_specs, start=1)
    }
    controller_id = "a" * 64
    components = [
        _component(
            actor_id=actor_id,
            role=role,
            function=function,
            image=images[image_key]["reference"],
            image_id=images[image_key]["image_id"],
            container_id=container_ids[actor_id],
        )
        for actor_id, role, function, image_key in actor_specs
    ]
    component_by_actor = {item["actor_id"]: item for item in components}

    snapshot_digest = _template_snapshot_digest()
    candidate = {
        "skill_name": "remedyfabric-recovery",
        "diagnosis": "visible empty-input contract failed",
        "edits": [
            {
                "path": "app/service.py",
                "old": EXPECTED_OLD,
                "new": EXPECTED_NEW,
                "reason": "guard an empty collection before division",
            }
        ],
        "confidence": 0.95,
        "estimated_cost_usd": 0.0,
        "skill_version": "0.1.0",
        "provider_name": "rule-based",
        "provider_version": "1.0.0",
    }
    candidate_binding = {
        "skill_name": candidate["skill_name"],
        "skill_version": candidate["skill_version"],
        "provider_name": candidate["provider_name"],
        "provider_version": candidate["provider_version"],
        "edits": [
            {"path": edit["path"], "old": edit["old"], "new": edit["new"]}
            for edit in candidate["edits"]
        ],
    }
    candidate_digest = canonical_digest(candidate_binding)
    proposals = {
        actor: {
            "actor_id": actor,
            "role": "worker",
            "run_id": run_id,
            "snapshot_digest": snapshot_digest,
            "claimed_patch_digest": candidate_digest,
        }
        for actor in ("rf-proposer-a", "rf-proposer-b")
    }
    recovery_outputs = {
        actor: {
            "produced_by_bound_skill": True,
            "skill_contract_path": "skills/remedyfabric-recovery/SKILL.md",
            "patch_candidate": candidate,
            "candidate_digest": candidate_digest,
            "proposal": proposals[actor],
        }
        for actor in ("rf-proposer-a", "rf-proposer-b")
    }
    recovery_inputs = {
        actor: {
            "actor_id": actor,
            "run_id": run_id,
            "snapshot_digest": snapshot_digest,
            "workspace": f"/workspace/remedyfabric/.synthetic/{actor}",
        }
        for actor in ("rf-proposer-a", "rf-proposer-b")
    }
    event_ids = {
        "tool-a": "$synthetic-tool-a-0001",
        "tool-b": "$synthetic-tool-b-0001",
        "cloud": "$synthetic-cloud-0001",
    }
    recovery_receipts = []
    for ordinal, actor, label in (
        (13, "rf-proposer-a", "a"),
        (17, "rf-proposer-b", "b"),
    ):
        component = component_by_actor[actor]
        recovery_receipts.append(
            _tool_receipt(
                execution_id=canonical_digest({"synthetic_execution": f"recovery-{label}"}),
                run_id=run_id,
                task_digest=task_digest,
                nonce=nonce,
                actor_id=actor,
                actor_matrix_id=component["matrix_id"],
                container_id=component["container_id"],
                image_id=component["image_digest"],
                event_id=event_ids[f"tool-{label}"],
                tool="remedyfabric-recovery",
                operation="proposer",
                skill_digest=file_digest(RECOVERY_SKILL),
                input_path=f"/tmp/remedyfabric-{actor}-proposer.json",
                input_payload=recovery_inputs[actor],
                output_payload=recovery_outputs[actor],
                exit_code=0,
                ordinal=ordinal,
                candidate_digest=candidate_digest,
            )
        )
    task_receipt = canonical_digest(
        {"kind": "task", "run_id": run_id, "task_digest": task_digest, "task": task}
    )
    proposal_receipts = {
        actor: canonical_digest(
            {
                "kind": "proposal",
                "actor_id": actor,
                "candidate_digest": candidate_digest,
                "proposal": proposals[actor],
            }
        )
        for actor in ("rf-proposer-a", "rf-proposer-b")
    }
    proposal_inputs = list(proposal_receipts.values())
    cloud_output = {
        "skill": "alibabacloud-resourcecenter-search",
        "status": "blocked_before_cloud_api",
        "reason_code": "missing_credentials",
        "credential_present": False,
        "request_sent": False,
        "cost_usd": 0,
        "consumed_receipt_digests": sorted(proposal_inputs),
    }
    cloud_input = {
        "actor_id": "rf-verifier",
        "run_id": run_id,
        "snapshot_digest": snapshot_digest,
        "input_receipt_digests": proposal_inputs,
    }
    cloud_lock = _load(CLOUD_SKILL_LOCK)
    verifier = component_by_actor["rf-verifier"]
    cloud_receipt = _tool_receipt(
        execution_id=canonical_digest({"synthetic_execution": "cloud-preflight"}),
        run_id=run_id,
        task_digest=task_digest,
        nonce=nonce,
        actor_id="rf-verifier",
        actor_matrix_id=verifier["matrix_id"],
        container_id=verifier["container_id"],
        image_id=verifier["image_digest"],
        event_id=event_ids["cloud"],
        tool="alibabacloud-resourcecenter-search",
        operation="alibaba-cloud-preflight",
        skill_digest=cloud_lock["skill"]["aggregate_sha256"],
        input_path="/tmp/remedyfabric-rf-verifier-cloud-preflight.json",
        input_payload=cloud_input,
        output_payload=cloud_output,
        exit_code=2,
        ordinal=21,
        reason_code="missing_credentials",
    )

    control_specs = (
        ("rf-verifier", "verifier", "verify", [*proposal_inputs, cloud_receipt["receipt_digest"]]),
        ("rf-verifier-b", "verifier", "verify", proposal_inputs),
        ("rf-lead", "reviewer", "review", proposal_inputs),
        ("rf-challenger", "challenger", "challenge", proposal_inputs),
        ("rf-governor", "governor", "govern", proposal_inputs),
    )
    control_receipt_inputs: dict[str, dict[str, Any]] = {}
    control_outputs: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory() as synthetic_workspace:
        workspace = Path(synthetic_workspace)
        (workspace / "app").mkdir()
        (workspace / "app/service.py").write_text(EXPECTED_OLD, encoding="utf-8")
        (workspace / "tests").mkdir()
        (workspace / "tests/test_service.py").write_text(
            VISIBLE_TEST,
            encoding="utf-8",
        )
        (workspace / "invariants").mkdir()
        (workspace / "invariants/test_invariant.py").write_text(
            INVARIANT_TEST,
            encoding="utf-8",
        )
        for actor, operation, _stage, inputs in control_specs:
            # Every Worker has a separate faulty copy in production.  Reset
            # this local fixture before capturing each role's actual input.
            (workspace / "app/service.py").write_text(EXPECTED_OLD, encoding="utf-8")
            payload: dict[str, Any] = {
                "actor_id": actor,
                "run_id": run_id,
                "snapshot_digest": snapshot_digest,
                "candidate": candidate,
                "workspace": synthetic_workspace,
                "input_receipt_digests": inputs,
            }
            if operation == "reviewer":
                payload["proposals"] = list(proposals.values())
            control_receipt_inputs[actor] = copy.deepcopy(payload)
            control_outputs[actor] = execute(operation, payload)

    control_receipts: dict[str, dict[str, Any]] = {}
    for ordinal, (actor, operation, stage, _inputs) in enumerate(control_specs, start=25):
        component = component_by_actor[actor]
        event_id = f"$synthetic-{stage}-{actor}-0001"
        event_ids[actor] = event_id
        control_receipts[actor] = _tool_receipt(
            execution_id=canonical_digest({"synthetic_execution": f"control-{actor}"}),
            run_id=run_id,
            task_digest=task_digest,
            nonce=nonce,
            actor_id=actor,
            actor_matrix_id=component["matrix_id"],
            container_id=component["container_id"],
            image_id=component["image_digest"],
            event_id=event_id,
            tool="remedyfabric-role-helper",
            operation=operation,
            skill_digest=file_digest(ROLE_HELPER),
            input_path=f"/tmp/remedyfabric-{actor}-{operation}.json",
            input_payload=control_receipt_inputs[actor],
            output_payload=control_outputs[actor],
            exit_code=0,
            ordinal=ordinal,
            candidate_digest=candidate_digest,
        )

    release_inputs = [
        *proposal_inputs,
        *(control_receipts[actor]["receipt_digest"] for actor, *_rest in control_specs),
    ]
    release_payload = {
        "actor_id": "rf-release-manager",
        "run_id": run_id,
        "snapshot_digest": snapshot_digest,
        "candidate": candidate,
        "proposals": list(proposals.values()),
        "attestations": [
            control_outputs[actor]["attestation"]
            for actor in ("rf-verifier", "rf-verifier-b", "rf-challenger", "rf-governor")
        ],
        "input_receipt_digests": release_inputs,
    }
    release_output = execute("release-manager", release_payload)
    release_event_id = "$synthetic-decide-rf-release-manager-0001"
    release_component = component_by_actor["rf-release-manager"]
    release_receipt = _tool_receipt(
        execution_id=canonical_digest({"synthetic_execution": "control-rf-release-manager"}),
        run_id=run_id,
        task_digest=task_digest,
        nonce=nonce,
        actor_id="rf-release-manager",
        actor_matrix_id=release_component["matrix_id"],
        container_id=release_component["container_id"],
        image_id=release_component["image_digest"],
        event_id=release_event_id,
        tool="remedyfabric-role-helper",
        operation="release-manager",
        skill_digest=file_digest(ROLE_HELPER),
        input_path="/tmp/remedyfabric-rf-release-manager-release-manager.json",
        input_payload=release_payload,
        output_payload=release_output,
        exit_code=0,
        ordinal=31,
        candidate_digest=candidate_digest,
    )
    decision_receipt = release_receipt["receipt_digest"]
    event_specs: list[dict[str, Any]] = [
        {"actor": "manager", "stage": "delegate", "inputs": [], "output": task_receipt},
        {
            "actor": "rf-proposer-a",
            "stage": "tool_execute",
            "inputs": [task_receipt],
            "output": recovery_receipts[0]["receipt_digest"],
            "event_id": event_ids["tool-a"],
            "body": (
                "remedyfabric-recovery completed "
                f"candidate_digest={candidate_digest} "
                f"execution_id={recovery_receipts[0]['execution_id']} "
                f"receipt_digest={recovery_receipts[0]['receipt_digest']}"
            ),
        },
        {
            "actor": "rf-proposer-a",
            "stage": "propose",
            "inputs": [recovery_receipts[0]["receipt_digest"]],
            "output": proposal_receipts["rf-proposer-a"],
        },
        {
            "actor": "rf-proposer-b",
            "stage": "tool_execute",
            "inputs": [task_receipt],
            "output": recovery_receipts[1]["receipt_digest"],
            "event_id": event_ids["tool-b"],
            "body": (
                "remedyfabric-recovery completed "
                f"candidate_digest={candidate_digest} "
                f"execution_id={recovery_receipts[1]['execution_id']} "
                f"receipt_digest={recovery_receipts[1]['receipt_digest']}"
            ),
        },
        {
            "actor": "rf-proposer-b",
            "stage": "propose",
            "inputs": [recovery_receipts[1]["receipt_digest"]],
            "output": proposal_receipts["rf-proposer-b"],
        },
        {
            "actor": "rf-verifier",
            "stage": "tool_execute",
            "inputs": list(proposal_receipts.values()),
            "output": cloud_receipt["receipt_digest"],
            "event_id": event_ids["cloud"],
            "body": (
                "alibabacloud-resourcecenter-search blocked_before_cloud_api "
                f"execution_id={cloud_receipt['execution_id']} "
                f"receipt_digest={cloud_receipt['receipt_digest']}"
            ),
        },
        {
            "actor": "rf-verifier",
            "stage": "verify",
            "inputs": [*proposal_inputs, cloud_receipt["receipt_digest"]],
            "output": control_receipts["rf-verifier"]["receipt_digest"],
            "event_id": event_ids["rf-verifier"],
            "body": (
                "remedyfabric-role-helper verifier completed "
                f"execution_id={control_receipts['rf-verifier']['execution_id']} "
                f"receipt_digest={control_receipts['rf-verifier']['receipt_digest']}"
            ),
        },
        {
            "actor": "rf-verifier-b",
            "stage": "verify",
            "inputs": proposal_inputs,
            "output": control_receipts["rf-verifier-b"]["receipt_digest"],
            "event_id": event_ids["rf-verifier-b"],
            "body": (
                "remedyfabric-role-helper verifier completed "
                f"execution_id={control_receipts['rf-verifier-b']['execution_id']} "
                f"receipt_digest={control_receipts['rf-verifier-b']['receipt_digest']}"
            ),
        },
        {
            "actor": "rf-lead",
            "stage": "review",
            "inputs": proposal_inputs,
            "output": control_receipts["rf-lead"]["receipt_digest"],
            "event_id": event_ids["rf-lead"],
            "body": (
                "remedyfabric-role-helper reviewer completed "
                f"execution_id={control_receipts['rf-lead']['execution_id']} "
                f"receipt_digest={control_receipts['rf-lead']['receipt_digest']}"
            ),
        },
        {
            "actor": "rf-challenger",
            "stage": "challenge",
            "inputs": proposal_inputs,
            "output": control_receipts["rf-challenger"]["receipt_digest"],
            "event_id": event_ids["rf-challenger"],
            "body": (
                "remedyfabric-role-helper challenger completed "
                f"execution_id={control_receipts['rf-challenger']['execution_id']} "
                f"receipt_digest={control_receipts['rf-challenger']['receipt_digest']}"
            ),
        },
        {
            "actor": "rf-governor",
            "stage": "govern",
            "inputs": proposal_inputs,
            "output": control_receipts["rf-governor"]["receipt_digest"],
            "event_id": event_ids["rf-governor"],
            "body": (
                "remedyfabric-role-helper governor completed "
                f"execution_id={control_receipts['rf-governor']['execution_id']} "
                f"receipt_digest={control_receipts['rf-governor']['receipt_digest']}"
            ),
        },
        {
            "actor": "rf-release-manager",
            "stage": "decide",
            "inputs": release_inputs,
            "output": decision_receipt,
            "event_id": release_event_id,
            "decision": "release",
            "body": (
                "remedyfabric-role-helper release-manager completed decision=release "
                f"execution_id={release_receipt['execution_id']} "
                f"receipt_digest={release_receipt['receipt_digest']}"
            ),
        },
        {
            "actor": "manager",
            "stage": "relay",
            "inputs": [decision_receipt],
            "output": None,
        },
    ]

    trace = []
    previous_event_id: str | None = None
    previous_protocol_digest: str | None = None
    for sequence, spec in enumerate(event_specs, start=1):
        actor = spec["actor"]
        component = component_by_actor[actor]
        event_id = spec.get("event_id", f"$synthetic-event-{sequence:02d}-0001")
        room_id = f"!synthetic-room-{actor}-0001"
        body = f"{spec.get('body', spec['stage'])} run_id={run_id}"
        protocol: dict[str, Any] = {
            "schema_version": "remedyfabric.agentteams-event.v1",
            "run_id": run_id,
            "challenge_nonce": nonce,
            "task_digest": task_digest,
            "sequence": sequence,
            "actor_id": actor,
            "function": component["function"],
            "stage": spec["stage"],
            "previous_event_id": previous_event_id,
            "previous_protocol_digest": previous_protocol_digest,
            "input_receipt_digests": spec["inputs"],
            "output_receipt_digest": spec["output"],
        }
        if "decision" in spec:
            protocol["decision"] = spec["decision"]
        protocol["protocol_digest"] = canonical_digest(protocol)
        if actor == "manager":
            body = _manager_body(protocol, body)
        raw_event = {
            "room_id": room_id,
            "event_id": event_id,
            "sender": component["matrix_id"],
            "type": "m.room.message",
            "origin_server_ts": 1_786_579_200_000 + sequence * 1_000,
            "content": {
                "msgtype": "m.text",
                "body": body,
                "com.remedyfabric.protocol": protocol,
            },
        }
        trace.append(
            {
                "sequence": sequence,
                "actor_role": component["role"],
                "actor_id": actor,
                "function": component["function"],
                "stage": spec["stage"],
                "action": f"synthetic {spec['stage']}",
                "room_id": room_id,
                "event_id": event_id,
                "timestamp_utc": f"2026-08-13T00:00:{sequence:02d}Z",
                "summary": f"Synthetic {spec['stage']} fixture event.",
                "raw_event": raw_event,
            }
        )
        previous_event_id = event_id
        previous_protocol_digest = protocol["protocol_digest"]

    container_exports = []
    controller_export = _container_export(
        container_id=controller_id,
        name="agentteams-controller",
        image=images["controller"]["reference"],
        image_id=images["controller"]["image_id"],
    )
    container_exports.append(
        {
            "container_id": controller_id,
            "export": controller_export,
            "export_digest": canonical_digest(controller_export),
        }
    )
    for component in components:
        export = _container_export(
            container_id=component["container_id"],
            name=component["name"],
            image=component["image"],
            image_id=component["image_digest"],
        )
        container_exports.append(
            {
                "container_id": component["container_id"],
                "export": export,
                "export_digest": canonical_digest(export),
            }
        )
    image_exports = []
    for image_key in ("controller", "manager", "worker"):
        locked = images[image_key]
        export = {"Id": locked["image_id"], "RepoDigests": [locked["repo_digest"]]}
        image_exports.append(
            {
                "image_key": image_key,
                "reference": locked["reference"],
                "export": export,
                "export_digest": canonical_digest(export),
            }
        )
    engine_export = {"Version": "synthetic-27.0.0", "ApiVersion": "1.46"}

    evidence: dict[str, Any] = {
        "provenance": "synthetic-validator-fixture",
        "fixture_notice": (
            "SYNTHETIC VALIDATOR FIXTURE ONLY; NOT A LIVE AGENTTEAMS EXECUTION RECEIPT"
        ),
        "claim_boundary": (
            "SYNTHETIC ONLY: operator-captured, operator-assisted execution; "
            "not third-party evidence. LLM autonomy not claimed."
        ),
        "upstream": {
            "repository": OFFICIAL_REPOSITORY,
            "tag": OFFICIAL_TAG,
            "commit": OFFICIAL_COMMIT,
        },
        "task": task,
        "capture_bundle": {
            "schema_version": "remedyfabric.agentteams-capture.v1",
            "capture_tool_sha256": file_digest(CAPTURE_TOOL),
            "source_tree_sha256": source_tree_digest(ROOT),
            "team_manifest_sha256": file_digest(TEAM_MANIFEST),
            "image_lock_sha256": file_digest(IMAGE_LOCK),
            "challenge_nonce": nonce,
            "run_id": run_id,
            "task_digest": task_digest,
            "started_at_utc": "2026-08-13T00:00:00Z",
            "finished_at_utc": "2026-08-13T00:01:00Z",
        },
        "runtime_capture": {
            "engine_version_status": 200,
            "engine_version_export": engine_export,
            "engine_version_export_digest": canonical_digest(engine_export),
            "image_inspect_exports": image_exports,
            "container_inspect_exports": container_exports,
        },
        "components": components,
        "trace": trace,
        "worker_tool_receipts": [
            *recovery_receipts,
            cloud_receipt,
            *control_receipts.values(),
            release_receipt,
        ],
        "skill_invocations": [
            {
                "skill": "remedyfabric-recovery",
                "skill_version": "0.1.0",
                "status": "completed",
                "actor_id": receipt["actor_id"],
                "event_id": receipt["event_id"],
                "execution_id": receipt["execution_id"],
                "input": recovery_inputs[receipt["actor_id"]],
                "input_digest": canonical_digest(recovery_inputs[receipt["actor_id"]]),
                "output": recovery_outputs[receipt["actor_id"]],
                "output_digest": canonical_digest(recovery_outputs[receipt["actor_id"]]),
                "candidate_digest": candidate_digest,
            }
            for receipt in recovery_receipts
        ],
        "terminal_decision": {
            "decision": "release",
            "verified": True,
            "event_id": trace[-2]["event_id"],
            "decision_receipt_digest": decision_receipt,
        },
    }

    evidence["matrix_authenticated_exports"] = {
        "whoami": [
            {
                "actor_id": component["actor_id"],
                "request_path": "/_matrix/client/v3/account/whoami",
                "status_code": 200,
                "response": {"user_id": component["matrix_id"]},
                "response_digest": canonical_digest({"user_id": component["matrix_id"]}),
            }
            for component in components
        ],
        "events": [],
    }

    acl_request = {
        "method": "GET",
        "path": "/api/v1/managers",
        "challenge_nonce": nonce,
    }
    acl_request["request_digest"] = canonical_digest(acl_request)
    acl_response = {"status_code": 403, "error": "authorization denied"}
    acl_exec = {
        "ContainerID": component_by_actor["rf-proposer-a"]["container_id"],
        "Running": False,
        "ExitCode": 0,
    }
    evidence["acl_probes"] = [
        {
            "actor_role": "worker",
            "actor_id": "rf-proposer-a",
            "actor_matrix_id": component_by_actor["rf-proposer-a"]["matrix_id"],
            "container_id": component_by_actor["rf-proposer-a"]["container_id"],
            "attempted_action": "GET /api/v1/managers",
            "expected": "deny",
            "observed": "authorization denied",
            "status_code": 403,
            "allowed": False,
            "challenge_nonce": nonce,
            "authenticated_request": acl_request,
            "response": acl_response,
            "response_digest": canonical_digest(acl_response),
            "docker_exec_export": acl_exec,
            "docker_exec_export_digest": canonical_digest(acl_exec),
        }
    ]

    model_digest = "b" * 64
    ollama_version = {"version": "synthetic-0.11.0"}
    ollama_show = {"model_info_digest": model_digest, "fixture": True}
    gateway_request = {"model": "gpt-oss:20b", "prompt": "synthetic-bound-probe"}
    gateway_response = {"message": "synthetic-response", "done": True}
    gateway = {
        "status_code": 200,
        "run_id": run_id,
        "challenge_nonce": nonce,
        "request": gateway_request,
        "request_digest": canonical_digest(gateway_request),
        "response": gateway_response,
        "response_digest": canonical_digest(gateway_response),
    }
    evidence["provider"] = {
        "external_network": False,
        "cost_usd": 0,
        "commercial_api_used": False,
        "official_gateway_http_status": 200,
        "model_capture": {
            "tag": "gpt-oss:20b",
            "digest": model_digest,
            "parameter_size": "20B",
            "quantization": "MXFP4",
            "license": "synthetic-fixture-metadata",
        },
        "ollama_version_export": ollama_version,
        "ollama_version_export_digest": canonical_digest(ollama_version),
        "ollama_show_export": ollama_show,
        "ollama_show_export_digest": canonical_digest(ollama_show),
        "gateway_probe": gateway,
    }
    evidence["alibaba_cloud_skill"] = {
        "package_verified": True,
        "assigned_to_worker": True,
        "cloud_api_invoked": False,
        "invocation": {
            "skill": "alibabacloud-resourcecenter-search",
            "status": "blocked_before_cloud_api",
            "reason_code": "missing_credentials",
            "credential_present": False,
            "request_sent": False,
            "cost_usd": 0,
            "actor_id": "rf-verifier",
            "event_id": cloud_receipt["event_id"],
            "execution_id": cloud_receipt["execution_id"],
        },
    }
    evidence["shared_context"] = {
        "schema_version": "remedyfabric.shared-context.v1",
        "run_id": run_id,
        "initial_state_digest": canonical_digest({"run_id": run_id, "task": task}),
        "transitions": [],
        "final_state_digest": "",
    }
    _rebind_trace(evidence)
    return evidence


class AgentTeamsEvidenceTests(unittest.TestCase):
    def test_redacts_nested_secrets_and_bearer_values(self) -> None:
        source = {
            "api_key": "sk-live",
            "nested": {"password": "secret", "message": "Bearer ey.test.value"},
        }
        redacted = redact_public(source)
        self.assertEqual(redacted["api_key"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["password"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["message"], "Bearer [REDACTED]")

    def test_synthetic_shape_fixture_passes_validator(self) -> None:
        evidence = valid_evidence()
        self.assertIn("SYNTHETIC VALIDATOR FIXTURE ONLY", evidence["fixture_notice"])
        self.assertEqual(validate_live_evidence(evidence, allow_synthetic_fixture=True), [])

    def test_production_validator_rejects_synthetic_fixture(self) -> None:
        evidence = valid_evidence()
        failures = validate_live_evidence(evidence)
        self.assertIn("production live evidence provenance is missing or synthetic", failures)
        in_memory = write_public_evidence(Path("unused"), evidence)
        self.assertFalse(live_evidence_is_valid(in_memory))

    def test_missing_runtime_capture_fails_closed(self) -> None:
        evidence = valid_evidence()
        evidence.pop("runtime_capture")
        failures = validate_live_evidence(evidence, allow_synthetic_fixture=True)
        self.assertIn("Docker Engine version export is invalid", failures)
        self.assertIn("official embedded Controller container is not captured as running", failures)

    def test_authenticated_matrix_export_tamper_fails_closed(self) -> None:
        evidence = valid_evidence()
        export = evidence["matrix_authenticated_exports"]["events"][4]
        export["response"]["content"]["body"] = "synthetic export tamper"
        export["response_digest"] = canonical_digest(export["response"])
        failures = validate_live_evidence(evidence, allow_synthetic_fixture=True)
        self.assertIn("trace is not derived from authenticated Matrix export at 4", failures)

    def test_worker_tool_receipt_tamper_fails_closed(self) -> None:
        evidence = valid_evidence()
        evidence["worker_tool_receipts"][0]["stdout"] = "tampered synthetic stdout"
        failures = validate_live_evidence(evidence, allow_synthetic_fixture=True)
        self.assertTrue(
            any(
                message.startswith("Worker tool execution receipt is invalid")
                for message in failures
            )
        )

    def test_container_runtime_file_binding_tamper_fails_closed(self) -> None:
        evidence = valid_evidence()
        receipt = evidence["worker_tool_receipts"][0]
        receipt["runtime_file_binding"]["files"]["role_helper_sha256"] = "0" * 64
        unsigned = dict(receipt)
        unsigned.pop("receipt_digest")
        unsigned.pop("event_id")
        receipt["receipt_digest"] = canonical_digest(unsigned)
        failures = validate_live_evidence(evidence, allow_synthetic_fixture=True)
        self.assertTrue(
            any(
                message.startswith("Worker tool execution receipt is invalid")
                for message in failures
            )
        )

    def test_worker_sender_adapter_binding_tamper_fails_closed(self) -> None:
        evidence = valid_evidence()
        event = next(
            item
            for item in evidence["matrix_authenticated_exports"]["events"]
            if item["actor_id"] == "rf-proposer-a"
        )
        event["send_capture"]["adapter_file_binding"]["files"]["adapter_sha256"] = "0" * 64
        failures = validate_live_evidence(evidence, allow_synthetic_fixture=True)
        self.assertTrue(
            any(
                message.startswith("Matrix authenticated event export is invalid")
                for message in failures
            )
        )

    def test_cloud_helper_dag_must_consume_both_proposals(self) -> None:
        evidence = valid_evidence()
        receipt = next(
            item
            for item in evidence["worker_tool_receipts"]
            if item["tool"] == "alibabacloud-resourcecenter-search"
        )
        receipt["input"]["input_receipt_digests"].pop()
        receipt["input_sha256"] = canonical_digest(receipt["input"])
        unsigned = dict(receipt)
        unsigned.pop("receipt_digest")
        unsigned.pop("event_id")
        receipt["receipt_digest"] = canonical_digest(unsigned)
        failures = validate_live_evidence(evidence, allow_synthetic_fixture=True)
        self.assertIn("Alibaba Cloud Skill helper did not consume both proposal receipts", failures)

    def test_decision_missing_one_control_receipt_fails_after_rebinding(self) -> None:
        evidence = valid_evidence()
        decision = evidence["trace"][-2]
        protocol = decision["raw_event"]["content"]["com.remedyfabric.protocol"]
        protocol["input_receipt_digests"].pop()
        _rebind_trace(evidence)
        failures = validate_live_evidence(evidence, allow_synthetic_fixture=True)
        self.assertIn("release decision does not consume the exact required receipt set", failures)

    def test_shared_context_hash_chain_tamper_fails_closed(self) -> None:
        evidence = valid_evidence()
        evidence["shared_context"]["transitions"][3]["state_digest"] = "0" * 64
        failures = validate_live_evidence(evidence, allow_synthetic_fixture=True)
        self.assertIn("shared context transition is invalid at 3", failures)

    def test_digest_is_order_independent_for_mappings(self) -> None:
        self.assertEqual(canonical_digest({"a": 1, "b": 2}), canonical_digest({"b": 2, "a": 1}))

    def test_synthetic_fixture_cannot_be_persisted_as_live(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            written = write_public_evidence(path, valid_evidence())
            self.assertFalse(written["validation"]["passed"])
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
