#!/usr/bin/env python3
"""Dependency-free consistency checks for Agent Pontifex live-session artifacts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "agent-pontifex-live-protocol" / "src" / "lib.rs"
TYPESPEC = ROOT / "contracts" / "live-session" / "live-session.tsp"
PROTO = ROOT / "contracts" / "live-session" / "live-session.proto"
SCHEMA = ROOT / "contracts" / "live-session" / "live-session.schema.json"
SESSION = ROOT / "conformance" / "live-session-session.json"
ENVELOPE = ROOT / "conformance" / "live-session-envelope.json"

PROTOCOL = "agent-pontifex.live"
PAYLOAD_KINDS = (
    "message",
    "proposal",
    "decision",
    "tool_request",
    "tool_result",
    "approval_request",
    "approval_decision",
    "work_status",
    "handoff",
    "tracker_update",
    "error",
)
EXPECTED_PROVIDER_MODELS = {
    ("openai", "gpt-5.6-sol"),
    ("anthropic", "claude-opus-5"),
    ("google", "gemini-3.1-pro-preview"),
    ("xai", "grok-4.6"),
}
FORBIDDEN_FIELDS = {
    "chain_of_thought",
    "hidden_reasoning",
    "reasoning_tokens",
    "raw_prompt",
    "private_trace",
}


def fail(message: str) -> None:
    raise AssertionError(message)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def collect_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(key)
            keys.update(collect_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(collect_keys(child))
    return keys


def strip_rust_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//.*", "", text)


def strip_typespec_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//.*", "", text)


def strip_proto_comments(text: str) -> str:
    return re.sub(r"//.*", "", text)


def assert_closed_schema_objects(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        if value.get("type") == "object" and "properties" in value:
            if value.get("additionalProperties") is not False:
                fail(f"schema object {path} must set additionalProperties=false")
        for key, child in value.items():
            assert_closed_schema_objects(child, f"{path}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_closed_schema_objects(child, f"{path}/{index}")


def main() -> int:
    rust = RUST.read_text(encoding="utf-8")
    typespec = TYPESPEC.read_text(encoding="utf-8")
    proto = PROTO.read_text(encoding="utf-8")
    schema = load_json(SCHEMA)
    session = load_json(SESSION)
    envelope = load_json(ENVELOPE)

    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("live-session schema must declare Draft 2020-12")
    schema_protocols = {
        node.get("const")
        for node in schema["$defs"]["live_envelope"]["properties"].values()
        if isinstance(node, dict) and node.get("const") == PROTOCOL
    }
    if PROTOCOL not in rust or PROTOCOL not in typespec or schema_protocols != {PROTOCOL}:
        fail("protocol identity is not synchronized across Rust, TypeSpec, and JSON Schema")
    if "package agent_pontifex.live.v1;" not in proto:
        fail("Protobuf package must remain agent_pontifex.live.v1")

    assert_closed_schema_objects(schema)
    schema_keys = collect_keys(schema)
    forbidden_schema = sorted(FORBIDDEN_FIELDS.intersection(schema_keys))
    if forbidden_schema:
        fail(f"hidden-reasoning fields leaked into JSON Schema: {forbidden_schema}")

    rust_code = strip_rust_comments(rust)
    typespec_code = strip_typespec_comments(typespec)
    proto_code = strip_proto_comments(proto)
    for field in sorted(FORBIDDEN_FIELDS):
        if re.search(rf"\bpub\s+{re.escape(field)}\s*:", rust_code):
            fail(f"hidden-reasoning field leaked into Rust: {field}")
        if re.search(rf"\b{re.escape(field)}\??\s*:", typespec_code):
            fail(f"hidden-reasoning field leaked into TypeSpec: {field}")
        if re.search(rf"\b{re.escape(field)}\s*=", proto_code):
            fail(f"hidden-reasoning field leaked into Protobuf: {field}")

    payload_variants = schema["$defs"]["live_payload"]["oneOf"]
    schema_kinds = {
        variant["properties"]["kind"]["const"] for variant in payload_variants
    }
    if schema_kinds != set(PAYLOAD_KINDS):
        fail(f"JSON Schema payload kinds drifted: {sorted(schema_kinds)}")
    for kind in PAYLOAD_KINDS:
        if f'kind: "{kind}";' not in typespec:
            fail(f"TypeSpec is missing payload kind {kind}")
        rust_variant = "".join(part.title() for part in kind.split("_"))
        if not re.search(rf"\b{rust_variant}\s*\{{", rust_code):
            fail(f"Rust is missing payload variant {rust_variant}")

    for frame_name in ("client_frame", "server_frame"):
        for variant in schema["$defs"][frame_name]["oneOf"]:
            properties = variant["properties"]
            required = variant["required"]
            if "type" not in properties or "type" not in required or "kind" in properties:
                fail(f"{frame_name} must use the `type` discriminator")
    if "client_event_id" in schema["$defs"]["live_envelope"]["properties"]:
        fail("server envelopes must not retain the client-only event identifier")

    if session.get("schema_version") != 1 or session.get("protocol") != PROTOCOL:
        fail("session fixture has the wrong protocol identity")
    provider_models = {
        (
            participant["identity"]["provider"],
            participant["identity"]["model"],
        )
        for participant in session["participants"]
    }
    if provider_models != EXPECTED_PROVIDER_MODELS:
        fail(
            "session fixture must cover the four resolved provider/model identities: "
            f"{sorted(provider_models)}"
        )
    participant_ids = [
        participant["identity"]["participant_id"]
        for participant in session["participants"]
    ]
    if len(participant_ids) != len(set(participant_ids)):
        fail("session fixture contains duplicate participant identities")
    if session["created_by"] not in participant_ids:
        fail("session fixture creator must be a participant")

    if envelope.get("schema_version") != 1 or envelope.get("protocol") != PROTOCOL:
        fail("envelope fixture has the wrong protocol identity")
    if not 1 <= envelope.get("seq", 0) <= 9_007_199_254_740_991:
        fail("envelope fixture sequence is outside the JSON-safe range")
    if not 16 <= len(envelope.get("idempotency_key", "")) <= 128:
        fail("envelope fixture idempotency key is outside the contract bounds")
    if envelope["payload"].get("kind") not in schema_kinds:
        fail("envelope fixture uses an unknown payload kind")

    print(
        "live-session contracts: PASS "
        f"({len(PAYLOAD_KINDS)} payloads, {len(session['participants'])} providers, "
        "closed JSON objects, no hidden-reasoning fields)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"live-session contracts: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
