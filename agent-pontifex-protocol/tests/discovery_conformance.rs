use agent_pontifex_protocol::{
    ProtocolVersionRange, ServiceDescriptor, ServiceKind, CURRENT_PROTOCOL_MAJOR,
};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

const FIXTURES: &[(&str, ServiceKind, bool)] = &[
    ("bridge.json", ServiceKind::Bridge, false),
    ("coordinator.json", ServiceKind::Coordinator, false),
    ("fiducia-bridge.json", ServiceKind::Bridge, true),
    ("fiducia-coordinator.json", ServiceKind::Coordinator, true),
];

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../conformance")
        .join(name)
}

fn load(name: &str) -> (ServiceDescriptor, Value) {
    let raw = fs::read_to_string(fixture_path(name)).expect("read discovery fixture");
    let value: Value = serde_json::from_str(&raw).expect("parse fixture JSON");
    let descriptor = serde_json::from_value(value.clone()).expect("parse service descriptor");
    (descriptor, value)
}

fn assert_public_safe(value: &Value) {
    fn visit(value: &Value, depth: usize, nodes: &mut usize) {
        assert!(depth <= 12, "discovery metadata is nested too deeply");
        *nodes += 1;
        assert!(
            *nodes <= 2_048,
            "discovery metadata contains too many nodes"
        );

        match value {
            Value::Object(object) => {
                for (key, nested) in object {
                    let lower = key.to_ascii_lowercase();
                    for forbidden in [
                        "access_token",
                        "api_key",
                        "authorization",
                        "bearer",
                        "cookie",
                        "credential",
                        "password",
                        "refresh_token",
                        "secret",
                        "session",
                    ] {
                        assert!(
                            !lower.contains(forbidden),
                            "discovery metadata contains credential-shaped key {key}",
                        );
                    }
                    visit(nested, depth + 1, nodes);
                }
            }
            Value::Array(values) => {
                for nested in values {
                    visit(nested, depth + 1, nodes);
                }
            }
            Value::String(text) => {
                assert!(text.len() <= 1_024, "discovery string is too large");
                assert!(
                    !text.chars().any(char::is_control),
                    "discovery string contains control characters",
                );
            }
            _ => {}
        }
    }

    let mut nodes = 0;
    visit(value, 0, &mut nodes);
}

#[test]
fn discovery_profiles_negotiate_and_remain_public_safe() {
    for (name, kind, fiducia_profile) in FIXTURES {
        let (descriptor, raw) = load(name);
        assert_eq!(
            descriptor
                .validate_for(*kind, ProtocolVersionRange::current())
                .expect("fixture must negotiate"),
            CURRENT_PROTOCOL_MAJOR,
        );
        assert_public_safe(&raw);

        let mut sorted = descriptor.capabilities.clone();
        sorted.sort();
        assert_eq!(
            descriptor.capabilities, sorted,
            "{name} is not deterministic"
        );

        if *fiducia_profile {
            assert!(!descriptor.extensions.is_empty(), "{name} needs extensions");
            assert!(
                descriptor
                    .extensions
                    .keys()
                    .all(|key| key.starts_with("fiducia.")),
                "{name} leaked a non-Fiducia extension",
            );
        } else {
            assert!(
                descriptor.extensions.is_empty(),
                "community profile {name} must be vendor-neutral",
            );
        }
    }
}
