from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Self
from unittest.mock import patch

from scripts.agentteams_matrix_sender import (
    MatrixSenderError,
    load_auth_state,
    load_content,
    main,
    resolve_homeserver,
    send_message,
    validate_homeserver,
)


class FakeResponse:
    def __init__(self, payload: bytes, status: int = 200) -> None:
        self.payload = payload
        self.status = status

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def read(self, maximum: int) -> bytes:
        return self.payload[:maximum]


class AgentTeamsMatrixSenderTests(unittest.TestCase):
    token = "ultra-private-test-token"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.auth_path = self.root / "auth.json"
        self.input_path = self.root / "input.json"
        self.auth_path.write_text(
            json.dumps(
                {
                    "access_token": self.token,
                    "device_id": "RFDEVICE",
                    "user_id": "@rf-proposer-a:matrix",
                }
            ),
            encoding="utf-8",
        )
        self.content = {
            "msgtype": "m.text",
            "body": "RFPROTO: bounded typed event",
            "com.remedyfabric.protocol": {"run_id": "run-1", "sequence": 2},
        }
        self.input_path.write_text(json.dumps(self.content), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_send_uses_bounded_put_with_exact_canonical_content(self) -> None:
        observed: dict[str, object] = {}

        def opener(request: object, *, timeout: float) -> FakeResponse:
            observed["request"] = request
            observed["timeout"] = timeout
            return FakeResponse(b'{"event_id":"$accepted:matrix"}')

        result = send_message(
            auth_state_path=self.auth_path,
            input_path=self.input_path,
            homeserver="http://matrix:8008",
            room_id="!room:matrix",
            txn_id="rf-run-1.2",
            timeout=7.0,
            opener=opener,
        )

        request = observed["request"]
        self.assertEqual(request.method, "PUT")  # type: ignore[attr-defined]
        self.assertEqual(
            request.full_url,  # type: ignore[attr-defined]
            "http://matrix:8008/_matrix/client/v3/rooms/"
            "%21room%3Amatrix/send/m.room.message/rf-run-1.2",
        )
        self.assertEqual(json.loads(request.data), self.content)  # type: ignore[attr-defined]
        self.assertEqual(request.get_header("Content-type"), "application/json")  # type: ignore[attr-defined]
        self.assertTrue(request.get_header("Authorization").startswith("Bearer "))  # type: ignore[attr-defined]
        self.assertEqual(observed["timeout"], 7.0)
        self.assertEqual(result, {"event_id": "$accepted:matrix"})

    def test_auth_state_requires_exact_schema(self) -> None:
        payload = json.loads(self.auth_path.read_text())
        payload["homeserver"] = "http://matrix:8008"
        self.auth_path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(MatrixSenderError, "schema"):
            load_auth_state(self.auth_path)

    def test_duplicate_auth_key_is_rejected(self) -> None:
        self.auth_path.write_text(
            '{"access_token":"first","access_token":"second",'
            '"device_id":"D","user_id":"@worker:matrix"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MatrixSenderError, "duplicate"):
            load_auth_state(self.auth_path)

    def test_content_requires_exact_schema_and_protocol_object(self) -> None:
        for payload in (
            {**self.content, "extra": True},
            {**self.content, "com.remedyfabric.protocol": []},
            {**self.content, "msgtype": "m.notice"},
        ):
            with self.subTest(payload=payload):
                self.input_path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(MatrixSenderError):
                    load_content(self.input_path, **{"access_" + "token": self.token})

    def test_content_cannot_contain_access_token(self) -> None:
        self.content["body"] = f"do not send {self.token}"
        self.input_path.write_text(json.dumps(self.content), encoding="utf-8")
        with self.assertRaisesRegex(MatrixSenderError, "authentication material"):
            load_content(self.input_path, **{"access_" + "token": self.token})

    def test_homeserver_must_be_bare_http_origin(self) -> None:
        for origin in (
            "matrix:8008",
            "file://matrix/auth",
            "http://matrix:8008/",
            "http://matrix:8008/path",
            "http://matrix:8008?query=yes",
            "http://matrix:8008#fragment",
            "http://user:password@matrix:8008",
            "http://matrix:0",
        ):
            with self.subTest(origin=origin), self.assertRaises(MatrixSenderError):
                validate_homeserver(origin)

    def test_homeserver_conflict_and_missing_value_fail_closed(self) -> None:
        with self.assertRaisesRegex(MatrixSenderError, "conflict"):
            resolve_homeserver("http://matrix:8008", {"AGENTTEAMS_MATRIX_URL": "https://other"})
        with self.assertRaisesRegex(MatrixSenderError, "missing"):
            resolve_homeserver(None, {})
        self.assertEqual(
            resolve_homeserver(None, {"AGENTTEAMS_MATRIX_URL": "http://matrix:8008"}),
            "http://matrix:8008",
        )

    def test_non_200_status_is_rejected(self) -> None:
        with self.assertRaisesRegex(MatrixSenderError, "status"):
            send_message(
                auth_state_path=self.auth_path,
                input_path=self.input_path,
                homeserver="http://matrix:8008",
                room_id="!room:matrix",
                txn_id="rf-1",
                opener=lambda *_args, **_kwargs: FakeResponse(b'{"errcode":"M_FORBIDDEN"}', 403),
            )

    def test_response_requires_only_a_valid_event_id(self) -> None:
        responses = (
            b"not-json",
            b"{}",
            b'{"event_id":"not-an-event-id"}',
            b'{"event_id":"$valid","extra":true}',
            b'{"event_id":"$first","event_id":"$second"}',
        )
        for response in responses:
            with self.subTest(response=response), self.assertRaises(MatrixSenderError):
                send_message(
                    auth_state_path=self.auth_path,
                    input_path=self.input_path,
                    homeserver="http://matrix:8008",
                    room_id="!room:matrix",
                    txn_id="rf-1",
                    opener=lambda *_args, body=response, **_kwargs: FakeResponse(body),
                )

    def test_destination_and_timeout_are_bounded(self) -> None:
        for room_id, txn_id, timeout in (
            ("room", "rf-1", 10.0),
            ("!room:matrix", "contains/slash", 10.0),
            ("!room:matrix", "rf-1", 0.0),
            ("!room:matrix", "rf-1", 31.0),
        ):
            with (
                self.subTest(room_id=room_id, txn_id=txn_id, timeout=timeout),
                self.assertRaises(MatrixSenderError),
            ):
                send_message(
                    auth_state_path=self.auth_path,
                    input_path=self.input_path,
                    homeserver="http://matrix:8008",
                    room_id=room_id,
                    txn_id=txn_id,
                    timeout=timeout,
                    opener=lambda *_args, **_kwargs: FakeResponse(b'{"event_id":"$valid"}'),
                )

    def test_cli_stdout_is_minimal_and_neither_stream_leaks_token(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.dict("os.environ", {"AGENTTEAMS_MATRIX_URL": "http://matrix:8008"}, clear=True),
            patch(
                "scripts.agentteams_matrix_sender.send_message",
                return_value={"event_id": "$accepted:matrix"},
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = main(
                [
                    "--auth-state",
                    str(self.auth_path),
                    "--room-id",
                    "!room:matrix",
                    "--txn-id",
                    "rf-1",
                    "--input",
                    str(self.input_path),
                    "--timeout",
                    "8",
                ]
            )
        self.assertEqual(status, 0)
        self.assertEqual(stdout.getvalue(), '{"event_id":"$accepted:matrix"}\n')
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn(self.token, stdout.getvalue() + stderr.getvalue())

    def test_cli_failure_is_public_safe(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.dict("os.environ", {"AGENTTEAMS_MATRIX_URL": "http://matrix:8008"}, clear=True),
            patch(
                "scripts.agentteams_matrix_sender.send_message",
                side_effect=MatrixSenderError("Matrix request failed"),
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = main(
                [
                    "--auth-state",
                    str(self.auth_path),
                    "--room-id",
                    "!room:matrix",
                    "--txn-id",
                    "rf-1",
                    "--input",
                    str(self.input_path),
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Matrix request failed", stderr.getvalue())
        self.assertNotIn(self.token, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
