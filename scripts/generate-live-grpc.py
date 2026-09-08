#!/usr/bin/env python3
"""Generate and verify the live-session gRPC service projection."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TYPESPEC = ROOT / "contracts" / "live-session" / "live-session.tsp"
SCHEMA = ROOT / "contracts" / "live-session" / "live-session.schema.json"
PROTO = ROOT / "contracts" / "live-session" / "live-session.proto"
CONFIG = ROOT / "contracts" / "live-session" / "grpc-projection.json"
LOCK = ROOT / "contracts" / "live-session" / "protobuf.lock.json"
MANIFEST = ROOT / "generated" / "live-session" / "grpc-manifest.json"

BEGIN = "// BEGIN GENERATED GRPC SERVICE — scripts/generate-live-grpc.py"
END = "// END GENERATED GRPC SERVICE"


class ProjectionError(ValueError):
    """The peer authorities cannot produce the requested gRPC projection."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def git_blob_sha(text: str) -> str:
    body = text.encode("utf-8")
    header = f"blob {len(body)}\0".encode("utf-8")
    return hashlib.sha1(header + body).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ProjectionError(f"{path}: expected a JSON object")
    return value


def interface_body(text: str, name: str) -> str:
    match = re.search(
        rf"\binterface\s+{re.escape(name)}\s*\{{(?P<body>[\s\S]*?)\n\}}",
        text,
    )
    if match is None:
        raise ProjectionError(f"TypeSpec interface {name!r} is missing")
    return match.group("body")


def require_operation(
    text: str,
    *,
    interface: str,
    operation: str,
    input_type: str,
    output_type: str,
) -> None:
    body = interface_body(text, interface)
    pattern = (
        rf"\b{re.escape(operation)}\s*\(\s*frame\s*:\s*"
        rf"{re.escape(input_type)}\s*\)\s*:\s*{re.escape(output_type)}\s*;"
    )
    if re.search(pattern, body) is None:
        raise ProjectionError(
            f"TypeSpec {interface}.{operation} must be "
            f"(frame: {input_type}): {output_type}"
        )


def message_fields(proto: str, name: str) -> dict[str, int]:
    match = re.search(
        rf"\bmessage\s+{re.escape(name)}\s*\{{(?P<body>[\s\S]*?)\n\}}",
        proto,
    )
    if match is None:
        raise ProjectionError(f"Protobuf message {name!r} is missing")
    return {
        field_name: int(field_number)
        for field_name, field_number in re.findall(
            r"(?m)^\s*(?:optional\s+|repeated\s+)?"
            r"[A-Za-z_][A-Za-z0-9_.<>]*\s+"
            r"([a-z_][a-z0-9_]*)\s*=\s*(\d+)\s*;",
            match.group("body"),
        )
    }


def service_block(config: dict[str, Any]) -> str:
    service = config.get("service")
    methods = config.get("methods")
    if not isinstance(service, str) or not re.fullmatch(r"[A-Z][A-Za-z0-9]*", service):
        raise ProjectionError("grpc-projection.json has an invalid service name")
    if not isinstance(methods, list) or not methods:
        raise ProjectionError("grpc-projection.json must contain at least one method")
    lines = [BEGIN, f"service {service} {{"]
    for method in methods:
        if not isinstance(method, dict):
            raise ProjectionError("gRPC methods must be objects")
        rpc = method.get("rpc")
        input_type = method.get("input")
        output_type = method.get("output")
        stream = method.get("stream")
        if not all(
            isinstance(value, str)
            for value in (rpc, input_type, output_type, stream)
        ):
            raise ProjectionError("gRPC method fields must be strings")
        if stream not in {"none", "in", "out", "duplex"}:
            raise ProjectionError(f"unsupported gRPC stream mode {stream!r}")
        request = f"stream {input_type}" if stream in {"in", "duplex"} else input_type
        response = f"stream {output_type}" if stream in {"out", "duplex"} else output_type
        lines.append(f"  rpc {rpc}({request}) returns ({response});")
    lines.extend(["}", END])
    return "\n".join(lines)


def project_proto(proto: str, block: str) -> str:
    pattern = re.compile(
        rf"(?ms)^{re.escape(BEGIN)}\n.*?^{re.escape(END)}\n?"
    )
    replacement = block + "\n"
    if pattern.search(proto):
        return pattern.sub(replacement, proto).rstrip() + "\n"
    return proto.rstrip() + "\n\n" + replacement


def validate_lock(proto: str, config: dict[str, Any], lock: dict[str, Any]) -> None:
    if lock.get("formatVersion") != 1:
        raise ProjectionError("protobuf.lock.json formatVersion must be 1")
    locked_messages = lock.get("messages")
    if not isinstance(locked_messages, dict) or not locked_messages:
        raise ProjectionError("protobuf.lock.json must lock critical messages")
    for message, expected_fields in locked_messages.items():
        if not isinstance(expected_fields, dict):
            raise ProjectionError(f"lock entry for {message} must be an object")
        actual = message_fields(proto, message)
        if actual != expected_fields:
            raise ProjectionError(
                f"{message} field-number drift: {actual!r} != {expected_fields!r}"
            )
    service = config["service"]
    locked_services = lock.get("services")
    if not isinstance(locked_services, dict):
        raise ProjectionError("protobuf.lock.json must lock services")
    locked_methods = locked_services.get(service)
    configured_methods = config.get("methods")
    if not isinstance(locked_methods, list) or not isinstance(configured_methods, list):
        raise ProjectionError(f"{service} service lock must contain a method list")
    wire_keys = ("rpc", "input", "output", "stream", "operation")
    locked_wire = [
        {key: method.get(key) for key in wire_keys}
        for method in locked_methods
        if isinstance(method, dict)
    ]
    configured_wire = [
        {key: method.get(key) for key in wire_keys}
        for method in configured_methods
        if isinstance(method, dict)
    ]
    if locked_wire != configured_wire or len(locked_wire) != len(locked_methods):
        raise ProjectionError(
            f"{service} service lock {locked_wire!r} does not match "
            f"projection config {configured_wire!r}"
        )


def build_manifest(
    typespec_text: str,
    schema_text: str,
    base_proto_text: str,
    projected_proto_text: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    return {
        "formatVersion": 1,
        "authorityInputs": {
            "typeSpec": {
                "path": "contracts/live-session/live-session.tsp",
                "gitBlobSha": git_blob_sha(typespec_text),
                "role": "human-authored-peer-authority",
            },
            "jsonSchema": {
                "path": "contracts/live-session/live-session.schema.json",
                "gitBlobSha": git_blob_sha(schema_text),
                "role": "human-authored-peer-authority",
            },
        },
        "projectionInputs": {
            "protobufMessages": {
                "path": "contracts/live-session/live-session.proto",
                "gitBlobShaBeforeServiceProjection": git_blob_sha(base_proto_text),
            },
            "grpcProjection": {
                "path": "contracts/live-session/grpc-projection.json",
                "sha256": hashlib.sha256(
                    canonical_json(config).encode("utf-8")
                ).hexdigest(),
            },
        },
        "output": {
            "path": "contracts/live-session/live-session.proto",
            "gitBlobSha": git_blob_sha(projected_proto_text),
            "package": config["package"],
            "service": config["service"],
            "methods": config["methods"],
        },
        "semanticValidatorRequiredAfterDecode": True,
        "hiddenReasoningExcluded": True,
    }


def run(*, write: bool) -> None:
    typespec_text = TYPESPEC.read_text(encoding="utf-8")
    schema_text = SCHEMA.read_text(encoding="utf-8")
    proto_text = PROTO.read_text(encoding="utf-8")
    config = load_json(CONFIG)
    lock = load_json(LOCK)
    schema = json.loads(schema_text)

    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise ProjectionError("live-session JSON Schema must remain Draft 2020-12")
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict):
        raise ProjectionError("live-session JSON Schema must contain $defs")

    if config.get("formatVersion") != 1:
        raise ProjectionError("grpc-projection.json formatVersion must be 1")
    if config.get("package") != "agent_pontifex.live.v1":
        raise ProjectionError("gRPC package must remain agent_pontifex.live.v1")

    for method in config["methods"]:
        input_type = method["input"]
        output_type = method["output"]
        require_operation(
            typespec_text,
            interface=config["sourceInterface"],
            operation=method["operation"],
            input_type=input_type,
            output_type=output_type,
        )
        for schema_name in method["jsonSchemaDefs"]:
            if schema_name not in definitions:
                raise ProjectionError(f"JSON Schema definition {schema_name!r} is missing")
        message_fields(proto_text, input_type)
        message_fields(proto_text, output_type)

    block = service_block(config)
    projected = project_proto(proto_text, block)
    validate_lock(projected, config, lock)

    base_proto = re.sub(
        rf"(?ms)\n*^{re.escape(BEGIN)}\n.*?^{re.escape(END)}\n?",
        "\n",
        proto_text,
    ).rstrip() + "\n"
    manifest = build_manifest(
        typespec_text, schema_text, base_proto, projected, config
    )
    manifest_text = canonical_json(manifest)

    if write:
        PROTO.write_text(projected, encoding="utf-8")
        MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST.write_text(manifest_text, encoding="utf-8")
        return

    if projected != proto_text:
        raise ProjectionError(
            "live-session.proto is stale; run scripts/generate-live-grpc.py --write"
        )
    if not MANIFEST.exists() or MANIFEST.read_text(encoding="utf-8") != manifest_text:
        raise ProjectionError(
            "gRPC manifest is stale; run scripts/generate-live-grpc.py --write"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    run(write=args.write)
    print("live-session gRPC projection: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, OSError, ProjectionError, json.JSONDecodeError) as error:
        print(f"live-session gRPC projection: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
