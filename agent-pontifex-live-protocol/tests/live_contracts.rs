//! Dependency-free consistency checks for the checked-in live-session artifacts.
//!
//! Supersedes `scripts/check-live-contracts.py`. The Rust source, TypeSpec,
//! Protobuf, JSON Schema, and conformance fixtures are embedded at compile time
//! so any change to them rebuilds and re-runs these checks.

use serde_json::Value;
use std::collections::BTreeSet;

const RUST: &str = include_str!("../src/lib.rs");
const TYPESPEC: &str = include_str!("../../contracts/live-session/live-session.tsp");
const PROTO: &str = include_str!("../../contracts/live-session/live-session.proto");
const SCHEMA: &str = include_str!("../../contracts/live-session/live-session.schema.json");
const SESSION: &str = include_str!("../../conformance/live-session-session.json");
const ENVELOPE: &str = include_str!("../../conformance/live-session-envelope.json");

const PROTOCOL: &str = "agent-pontifex.live";
const DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";
const PAYLOAD_KINDS: [&str; 11] = [
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
];
const EXPECTED_PROVIDER_MODELS: [(&str, &str); 4] = [
    ("openai", "gpt-5.6-sol"),
    ("anthropic", "claude-opus-5"),
    ("google", "gemini-3.1-pro-preview"),
    ("xai", "grok-4.6"),
];
const FORBIDDEN_FIELDS: [&str; 5] = [
    "chain_of_thought",
    "hidden_reasoning",
    "reasoning_tokens",
    "raw_prompt",
    "private_trace",
];
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn schema() -> Value {
    serde_json::from_str(SCHEMA).expect("live-session schema is valid JSON")
}

fn defs(schema: &Value) -> &serde_json::Map<String, Value> {
    schema["$defs"]
        .as_object()
        .expect("live-session schema must contain $defs")
}

/// Follow `#/$defs/<name>` references so named variants are checked like inline ones.
fn resolve_local_ref<'a>(schema: &'a Value, mut node: &'a Value) -> &'a Value {
    let mut seen = BTreeSet::new();
    while let Some(reference) = node.get("$ref") {
        let reference = reference
            .as_str()
            .unwrap_or_else(|| panic!("schema reference {reference} must be a string"));
        let name = reference
            .strip_prefix("#/$defs/")
            .unwrap_or_else(|| panic!("unsupported schema reference {reference:?}"));
        assert!(
            seen.insert(reference.to_string()),
            "cyclic schema reference {reference:?}"
        );
        node = defs(schema)
            .get(name)
            .unwrap_or_else(|| panic!("schema reference {reference:?} does not resolve"));
    }
    node
}

fn one_of_variants<'a>(schema: &'a Value, def_name: &str) -> Vec<&'a Value> {
    defs(schema)
        .get(def_name)
        .and_then(|definition| definition["oneOf"].as_array())
        .unwrap_or_else(|| panic!("$defs/{def_name} must be a oneOf union"))
        .iter()
        .map(|variant| resolve_local_ref(schema, variant))
        .collect()
}

fn collect_keys(value: &Value, keys: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                keys.insert(key.clone());
                collect_keys(child, keys);
            }
        }
        Value::Array(items) => items.iter().for_each(|child| collect_keys(child, keys)),
        _ => {}
    }
}

fn assert_closed_schema_objects(value: &Value, path: &str) {
    match value {
        Value::Object(map) => {
            if map.get("type").and_then(Value::as_str) == Some("object")
                && map.contains_key("properties")
            {
                // Either Draft 2020-12 closing keyword keeps the object closed.
                let closed = map.get("additionalProperties") == Some(&Value::Bool(false))
                    || map.get("unevaluatedProperties") == Some(&Value::Bool(false));
                assert!(
                    closed,
                    "schema object {path} must set additionalProperties=false \
                     or unevaluatedProperties=false"
                );
            }
            for (key, child) in map {
                assert_closed_schema_objects(child, &format!("{path}/{key}"));
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                assert_closed_schema_objects(child, &format!("{path}/{index}"));
            }
        }
        _ => {}
    }
}

/// Remove `/* ... */` block comments and `//` line comments (Rust and TypeSpec).
fn strip_c_style_comments(text: &str) -> String {
    let mut without_blocks = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("/*") {
        without_blocks.push_str(&rest[..start]);
        match rest[start + 2..].find("*/") {
            Some(end) => rest = &rest[start + 2 + end + 2..],
            None => {
                rest = "";
                break;
            }
        }
    }
    without_blocks.push_str(rest);
    strip_line_comments(&without_blocks)
}

/// Remove `//` line comments (Protobuf).
fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|line| line.find("//").map_or(line, |index| &line[..index]))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Byte offsets where `word` occurs with identifier boundaries on both sides.
fn word_positions(text: &str, word: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    text.match_indices(word)
        .map(|(index, _)| index)
        .filter(|&index| {
            let before_ok = index == 0 || !is_ident_byte(bytes[index - 1]);
            let end = index + word.len();
            let after_ok = end == bytes.len() || !is_ident_byte(bytes[end]);
            before_ok && after_ok
        })
        .collect()
}

/// Rust: `pub <field>:`
fn rust_declares_pub_field(code: &str, field: &str) -> bool {
    word_positions(code, field).into_iter().any(|index| {
        let before = &code[..index];
        let trimmed = before.trim_end();
        let had_space = trimmed.len() < before.len();
        let after = code[index + field.len()..].trim_start();
        had_space
            && trimmed.ends_with("pub")
            && {
                let pub_start = trimmed.len() - 3;
                pub_start == 0 || !is_ident_byte(trimmed.as_bytes()[pub_start - 1])
            }
            && after.starts_with(':')
    })
}

/// TypeSpec: `<field>:` or `<field>?:`
fn typespec_declares_field(code: &str, field: &str) -> bool {
    word_positions(code, field).into_iter().any(|index| {
        let after = &code[index + field.len()..];
        let after = after.strip_prefix('?').unwrap_or(after);
        after.trim_start().starts_with(':')
    })
}

/// Protobuf: `<field> =`
fn proto_declares_field(code: &str, field: &str) -> bool {
    word_positions(code, field)
        .into_iter()
        .any(|index| code[index + field.len()..].trim_start().starts_with('='))
}

/// Rust: `<Variant> {`
fn rust_declares_struct_variant(code: &str, variant: &str) -> bool {
    word_positions(code, variant)
        .into_iter()
        .any(|index| code[index + variant.len()..].trim_start().starts_with('{'))
}

fn pascal_case(snake: &str) -> String {
    snake
        .split('_')
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |first| {
                first
                    .to_uppercase()
                    .chain(chars.flat_map(char::to_lowercase))
                    .collect()
            })
        })
        .collect()
}

#[test]
fn schema_declares_draft_2020_12_and_protocol_identity() {
    let schema = schema();
    assert_eq!(
        schema["$schema"], DRAFT_2020_12,
        "live-session schema must declare Draft 2020-12"
    );
    let envelope = resolve_local_ref(&schema, &defs(&schema)["live_envelope"]);
    let schema_protocols: BTreeSet<&str> = envelope["properties"]
        .as_object()
        .expect("live_envelope must declare properties")
        .values()
        .map(|node| resolve_local_ref(&schema, node))
        .filter_map(|node| node.get("const").and_then(Value::as_str))
        .filter(|value| *value == PROTOCOL)
        .collect();
    assert!(
        RUST.contains(PROTOCOL)
            && TYPESPEC.contains(PROTOCOL)
            && schema_protocols == BTreeSet::from([PROTOCOL]),
        "protocol identity is not synchronized across Rust, TypeSpec, and JSON Schema"
    );
    assert!(
        PROTO.contains("package agent_pontifex.live.v1;"),
        "Protobuf package must remain agent_pontifex.live.v1"
    );
}

#[test]
fn schema_objects_are_closed() {
    assert_closed_schema_objects(&schema(), "$");
}

#[test]
fn hidden_reasoning_fields_are_absent_from_every_representation() {
    let mut schema_keys = BTreeSet::new();
    collect_keys(&schema(), &mut schema_keys);
    let rust_code = strip_c_style_comments(RUST);
    let typespec_code = strip_c_style_comments(TYPESPEC);
    let proto_code = strip_line_comments(PROTO);
    for field in FORBIDDEN_FIELDS {
        assert!(
            !schema_keys.contains(field),
            "hidden-reasoning field leaked into JSON Schema: {field}"
        );
        assert!(
            !rust_declares_pub_field(&rust_code, field),
            "hidden-reasoning field leaked into Rust: {field}"
        );
        assert!(
            !typespec_declares_field(&typespec_code, field),
            "hidden-reasoning field leaked into TypeSpec: {field}"
        );
        assert!(
            !proto_declares_field(&proto_code, field),
            "hidden-reasoning field leaked into Protobuf: {field}"
        );
    }
}

#[test]
fn payload_kinds_match_across_schema_typespec_and_rust() {
    let schema = schema();
    let schema_kinds: BTreeSet<&str> = one_of_variants(&schema, "live_payload")
        .into_iter()
        .map(|variant| {
            resolve_local_ref(&schema, &variant["properties"]["kind"])["const"]
                .as_str()
                .expect("every payload variant must declare a const kind")
        })
        .collect();
    assert_eq!(
        schema_kinds,
        BTreeSet::from(PAYLOAD_KINDS),
        "JSON Schema payload kinds drifted"
    );
    let rust_code = strip_c_style_comments(RUST);
    for kind in PAYLOAD_KINDS {
        assert!(
            TYPESPEC.contains(&format!("kind: \"{kind}\";")),
            "TypeSpec is missing payload kind {kind}"
        );
        let variant = pascal_case(kind);
        assert!(
            rust_declares_struct_variant(&rust_code, &variant),
            "Rust is missing payload variant {variant}"
        );
    }
}

#[test]
fn frames_use_the_type_discriminator() {
    let schema = schema();
    for frame_name in ["client_frame", "server_frame"] {
        for variant in one_of_variants(&schema, frame_name) {
            let properties = variant["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("{frame_name} variants must declare properties"));
            let required_type = variant["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|name| name == "type"));
            assert!(
                properties.contains_key("type")
                    && required_type
                    && !properties.contains_key("kind"),
                "{frame_name} must use the `type` discriminator"
            );
        }
    }
    let envelope = resolve_local_ref(&schema, &defs(&schema)["live_envelope"]);
    assert!(
        envelope["properties"].get("client_event_id").is_none(),
        "server envelopes must not retain the client-only event identifier"
    );
}

#[test]
fn conformance_fixtures_match_contract_expectations() {
    let schema = schema();
    let session: Value = serde_json::from_str(SESSION).expect("session fixture is valid JSON");
    let envelope: Value = serde_json::from_str(ENVELOPE).expect("envelope fixture is valid JSON");

    assert!(
        session["schema_version"] == 1 && session["protocol"] == PROTOCOL,
        "session fixture has the wrong protocol identity"
    );
    let participants = session["participants"]
        .as_array()
        .expect("session fixture must list participants");
    let provider_models: BTreeSet<(&str, &str)> = participants
        .iter()
        .map(|participant| {
            let identity = &participant["identity"];
            (
                identity["provider"].as_str().expect("provider is a string"),
                identity["model"].as_str().expect("model is a string"),
            )
        })
        .collect();
    assert_eq!(
        provider_models,
        BTreeSet::from(EXPECTED_PROVIDER_MODELS),
        "session fixture must cover the four resolved provider/model identities"
    );
    let participant_ids: Vec<&str> = participants
        .iter()
        .map(|participant| {
            participant["identity"]["participant_id"]
                .as_str()
                .expect("participant_id is a string")
        })
        .collect();
    let unique_ids: BTreeSet<&str> = participant_ids.iter().copied().collect();
    assert_eq!(
        unique_ids.len(),
        participant_ids.len(),
        "session fixture contains duplicate participant identities"
    );
    let created_by = session["created_by"]
        .as_str()
        .expect("created_by is a string");
    assert!(
        unique_ids.contains(created_by),
        "session fixture creator must be a participant"
    );

    assert!(
        envelope["schema_version"] == 1 && envelope["protocol"] == PROTOCOL,
        "envelope fixture has the wrong protocol identity"
    );
    let seq = envelope["seq"].as_u64().unwrap_or(0);
    assert!(
        (1..=MAX_SAFE_INTEGER).contains(&seq),
        "envelope fixture sequence is outside the JSON-safe range"
    );
    let idempotency_key_len = envelope["idempotency_key"].as_str().map_or(0, str::len);
    assert!(
        (16..=128).contains(&idempotency_key_len),
        "envelope fixture idempotency key is outside the contract bounds"
    );
    let schema_kinds: BTreeSet<&str> = one_of_variants(&schema, "live_payload")
        .into_iter()
        .filter_map(|variant| {
            resolve_local_ref(&schema, &variant["properties"]["kind"])["const"].as_str()
        })
        .collect();
    let fixture_kind = envelope["payload"]["kind"].as_str().unwrap_or_default();
    assert!(
        schema_kinds.contains(fixture_kind),
        "envelope fixture uses an unknown payload kind"
    );
}

#[test]
fn text_scanners_detect_the_shapes_they_guard() {
    // Negative controls so a scanner regression cannot silently pass the checks above.
    assert!(rust_declares_pub_field(
        "struct A {\n    pub raw_prompt: String,\n}",
        "raw_prompt"
    ));
    assert!(!rust_declares_pub_field(
        "struct A { pub raw_prompt_len: u8 }",
        "raw_prompt"
    ));
    assert!(typespec_declares_field(
        "model A { private_trace?: string; }",
        "private_trace"
    ));
    assert!(proto_declares_field(
        "message A { string hidden_reasoning = 3; }",
        "hidden_reasoning"
    ));
    assert!(rust_declares_struct_variant(
        "enum P { ToolRequest {\n a: u8 } }",
        "ToolRequest"
    ));
    assert_eq!(pascal_case("approval_decision"), "ApprovalDecision");
    assert_eq!(
        strip_c_style_comments("a /* pub raw_prompt: x */ b // pub raw_prompt: y\nc"),
        "a  b \nc"
    );
    let mut open = serde_json::json!({"type": "object", "properties": {}});
    assert!(std::panic::catch_unwind(|| assert_closed_schema_objects(&open, "$")).is_err());
    open["unevaluatedProperties"] = Value::Bool(false);
    assert_closed_schema_objects(&open, "$");
}
