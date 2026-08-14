#!/usr/bin/env python3
"""Send one typed RemedyFabric event as an official AgentTeams Worker.

The adapter reads a deliberately minimal Matrix authentication state, performs
one bounded PUT, and prints only the accepted Matrix event id.  It never logs
credentials or response bodies.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

AUTH_KEYS = frozenset({"access_token", "device_id", "user_id"})
CONTENT_KEYS = frozenset({"msgtype", "body", "com.remedyfabric.protocol"})
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_TIMEOUT_SECONDS = 30.0
MAX_AUTH_BYTES = 64 * 1024
MAX_INPUT_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
TXN_ID_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
EVENT_ID_PATTERN = re.compile(r"^\$[\x21-\x7e]{1,254}$")


class MatrixSenderError(RuntimeError):
    """A public-safe, fail-closed sender error."""


def _reject_constant(_: str) -> None:
    raise MatrixSenderError("JSON contains a non-finite number")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise MatrixSenderError("JSON contains a duplicate key")
        output[key] = value
    return output


def _read_json(path: Path, *, maximum_bytes: int, label: str) -> Any:
    try:
        raw = path.read_bytes()
    except OSError:
        raise MatrixSenderError(f"{label} could not be read") from None
    if not raw or len(raw) > maximum_bytes:
        raise MatrixSenderError(f"{label} size is invalid")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MatrixSenderError(f"{label} is not valid JSON") from None


def load_auth_state(path: Path) -> dict[str, str]:
    payload = _read_json(path, maximum_bytes=MAX_AUTH_BYTES, label="auth state")
    if not isinstance(payload, dict) or frozenset(payload) != AUTH_KEYS:
        raise MatrixSenderError("auth state schema is invalid")
    if any(not isinstance(payload[key], str) or not payload[key] for key in AUTH_KEYS):
        raise MatrixSenderError("auth state values are invalid")
    matrix_credential = payload["access_token"]
    if (
        len(matrix_credential) < 8
        or len(matrix_credential) > 8192
        or any(character.isspace() for character in matrix_credential)
    ):
        raise MatrixSenderError("auth state values are invalid")
    if not re.fullmatch(r"@[A-Za-z0-9._=\-/]+:[^\s:]+(?::\d+)?", payload["user_id"]):
        raise MatrixSenderError("auth state values are invalid")
    if len(payload["device_id"]) > 255 or any(
        character.isspace() for character in payload["device_id"]
    ):
        raise MatrixSenderError("auth state values are invalid")
    return {key: payload[key] for key in sorted(AUTH_KEYS)}


def load_content(path: Path, *, access_token: str) -> dict[str, Any]:
    payload = _read_json(path, maximum_bytes=MAX_INPUT_BYTES, label="message input")
    if not isinstance(payload, dict) or frozenset(payload) != CONTENT_KEYS:
        raise MatrixSenderError("message input schema is invalid")
    if payload["msgtype"] != "m.text" or not isinstance(payload["body"], str):
        raise MatrixSenderError("message input values are invalid")
    if not payload["body"] or "\x00" in payload["body"]:
        raise MatrixSenderError("message input values are invalid")
    protocol = payload["com.remedyfabric.protocol"]
    if not isinstance(protocol, dict) or not protocol:
        raise MatrixSenderError("message input values are invalid")
    canonical = canonical_json(payload)
    if access_token.encode("utf-8") in canonical:
        raise MatrixSenderError("message input contains authentication material")
    return payload


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def validate_homeserver(origin: str) -> str:
    if not isinstance(origin, str) or not origin or origin != origin.strip():
        raise MatrixSenderError("Matrix homeserver origin is invalid")
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError:
        raise MatrixSenderError("Matrix homeserver origin is invalid") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port == 0
    ):
        raise MatrixSenderError("Matrix homeserver origin is invalid")
    return origin


def resolve_homeserver(explicit: str | None, environment: Mapping[str, str]) -> str:
    configured = environment.get("AGENTTEAMS_MATRIX_URL")
    if explicit and configured and explicit != configured:
        raise MatrixSenderError("Matrix homeserver origins conflict")
    selected = explicit or configured
    if selected is None:
        raise MatrixSenderError("Matrix homeserver origin is missing")
    return validate_homeserver(selected)


def validate_timeout(timeout: float) -> float:
    if not isinstance(timeout, (float, int)) or not 0.1 <= float(timeout) <= MAX_TIMEOUT_SECONDS:
        raise MatrixSenderError("timeout is outside the bounded range")
    return float(timeout)


def _endpoint(origin: str, room_id: str, txn_id: str) -> str:
    if (
        not isinstance(room_id, str)
        or not re.fullmatch(r"![^\s:]{1,127}:[^\s:]+(?::\d+)?", room_id)
        or not TXN_ID_PATTERN.fullmatch(txn_id)
    ):
        raise MatrixSenderError("Matrix destination is invalid")
    room = quote(room_id, safe="")
    transaction = quote(txn_id, safe="")
    return f"{origin}/_matrix/client/v3/rooms/{room}/send/m.room.message/{transaction}"


def send_message(
    *,
    auth_state_path: Path,
    input_path: Path,
    homeserver: str,
    room_id: str,
    txn_id: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> dict[str, str]:
    auth = load_auth_state(auth_state_path)
    content = load_content(input_path, access_token=auth["access_token"])
    endpoint = _endpoint(validate_homeserver(homeserver), room_id, txn_id)
    bounded_timeout = validate_timeout(timeout)
    request = urllib.request.Request(
        endpoint,
        data=canonical_json(content),
        headers={
            "Authorization": f"Bearer {auth['access_token']}",
            "Content-Type": "application/json",
        },
        method="PUT",
    )
    try:
        response = opener(request, timeout=bounded_timeout)
        with response:
            status = response.getcode()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, urllib.error.URLError, TimeoutError, http.client.HTTPException):
        raise MatrixSenderError("Matrix request failed") from None
    except (AttributeError, TypeError, ValueError):
        raise MatrixSenderError("Matrix response could not be read") from None
    if status != 200:
        raise MatrixSenderError("Matrix response status was rejected")
    if not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise MatrixSenderError("Matrix response size is invalid")
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MatrixSenderError("Matrix response is not valid JSON") from None
    if (
        not isinstance(payload, dict)
        or frozenset(payload) != {"event_id"}
        or not isinstance(payload["event_id"], str)
        or not EVENT_ID_PATTERN.fullmatch(payload["event_id"])
        or auth["access_token"] in payload["event_id"]
    ):
        raise MatrixSenderError("Matrix response schema is invalid")
    return {"event_id": payload["event_id"]}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--auth-state", required=True, type=Path)
    parser.add_argument("--room-id", required=True)
    parser.add_argument("--txn-id", required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--homeserver", help="explicit alternative to AGENTTEAMS_MATRIX_URL")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        homeserver = resolve_homeserver(args.homeserver, os.environ)
        result = send_message(
            auth_state_path=args.auth_state,
            input_path=args.input,
            homeserver=homeserver,
            room_id=args.room_id,
            txn_id=args.txn_id,
            timeout=args.timeout,
        )
    except MatrixSenderError as error:
        print(f"agentteams matrix send failed: {error}", file=sys.stderr)
        return 2
    sys.stdout.write(canonical_json(result).decode("ascii") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
