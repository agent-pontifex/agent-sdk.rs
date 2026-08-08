use agent_pontifex_attestation::{
    canonical_json, validate_independent_artifact_set, ArtifactExpectation, ArtifactProducer,
    ArtifactSubject, ArtifactTrustPolicy, DistinctAuthorityField, SignatureAlgorithm,
    SignedArtifactEnvelope, TrustedArtifactKey, ValidationError, ARTIFACT_SCHEMA_VERSION,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const POLICY_DIGEST: &str =
    "9999999999999999999999999999999999999999999999999999999999999999";
const REVISION_DIGEST: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn subject() -> ArtifactSubject {
    ArtifactSubject {
        kind: "linear_issue".to_string(),
        id: "DEN-2877".to_string(),
        revision_digest: REVISION_DIGEST.to_string(),
    }
}

fn public_key_pem(body: &str) -> String {
    format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----")
}

fn trusted_key(
    role: &str,
    provider: &str,
    trust_domain: &str,
    task_type: &str,
    public_key_body: &str,
) -> TrustedArtifactKey {
    TrustedArtifactKey {
        algorithm: SignatureAlgorithm::Ed25519,
        public_key_pem: public_key_pem(public_key_body),
        roles: vec![role.to_string()],
        provider: provider.to_string(),
        trust_domain: trust_domain.to_string(),
        task_types: vec![task_type.to_string()],
    }
}

fn trust_policy() -> ArtifactTrustPolicy {
    ArtifactTrustPolicy::strict(
        vec!["chatgpt".to_string(), "claude".to_string()],
        BTreeMap::from([
            (
                "openai-opinion-2026-08".to_string(),
                trusted_key(
                    "chatgpt",
                    "openai",
                    "openai-opinion-worker",
                    "linear_opinion_chatgpt",
                    "MCowBQYDK2VwAyEA111111111111111111111111111111111111111=",
                ),
            ),
            (
                "anthropic-opinion-2026-08".to_string(),
                trusted_key(
                    "claude",
                    "anthropic",
                    "anthropic-opinion-worker",
                    "linear_opinion_claude",
                    "MCowBQYDK2VwAyEA222222222222222222222222222222222222222=",
                ),
            ),
        ]),
    )
}

fn envelope(role: &str) -> SignedArtifactEnvelope {
    let chatgpt = role == "chatgpt";
    let payload = json!({
        "blockers": [],
        "confidence": 0.999,
        "evidence": ["fixture:exact-revision"],
        "issue_id": "DEN-2877",
        "recommendation": "pending",
        "revision_digest": REVISION_DIGEST,
        "summary": "Bounded independent opinion."
    });
    let mut artifact = SignedArtifactEnvelope {
        schema_version: ARTIFACT_SCHEMA_VERSION.to_string(),
        role: role.to_string(),
        provider: if chatgpt { "openai" } else { "anthropic" }.to_string(),
        subject: subject(),
        policy_digest: POLICY_DIGEST.to_string(),
        producer: ArtifactProducer {
            key_id: if chatgpt {
                "openai-opinion-2026-08"
            } else {
                "anthropic-opinion-2026-08"
            }
            .to_string(),
            trust_domain: if chatgpt {
                "openai-opinion-worker"
            } else {
                "anthropic-opinion-worker"
            }
            .to_string(),
            worker_id: if chatgpt {
                "openai-worker-17"
            } else {
                "anthropic-worker-23"
            }
            .to_string(),
            job_id: if chatgpt {
                "openai-job-17"
            } else {
                "anthropic-job-23"
            }
            .to_string(),
            task_type: if chatgpt {
                "linear_opinion_chatgpt"
            } else {
                "linear_opinion_claude"
            }
            .to_string(),
        },
        issued_at: "2026-08-08T19:00:00.000Z".to_string(),
        expires_at: "2026-08-08T19:10:00.000Z".to_string(),
        payload_hash: String::new(),
        payload,
        signature: "Abcdefghijklmnopqrstuvwxyz_0123456789-Abcdefghijklmnopqrstuvwxyz_0123456789"
            .to_string(),
    };
    artifact.payload_hash = artifact.canonical_payload_hash().unwrap();
    artifact
}

fn expectation() -> ArtifactExpectation {
    ArtifactExpectation {
        subject: subject(),
        policy_digest: POLICY_DIGEST.to_string(),
    }
}

fn expect_code<T>(result: Result<T, ValidationError>, code: &str) {
    let error = result.err().expect("expected validation failure");
    assert_eq!(error.code(), code);
}

#[test]
fn canonical_json_recursively_sorts_objects() {
    let first: Value = serde_json::from_str(r#"{"z":1,"a":{"y":2,"x":3}}"#).unwrap();
    let second: Value = serde_json::from_str(r#"{"a":{"x":3,"y":2},"z":1}"#).unwrap();
    assert_eq!(
        canonical_json(&first).unwrap(),
        r#"{"a":{"x":3,"y":2},"z":1}"#
    );
    assert_eq!(canonical_json(&first).unwrap(), canonical_json(&second).unwrap());
}

#[test]
fn envelope_validates_hash_and_emits_signature_free_canonical_bytes() {
    let artifact = envelope("chatgpt");
    artifact.validate_transport().unwrap();
    let unsigned = artifact.unsigned_canonical_json().unwrap();
    assert!(!unsigned.contains("\"signature\""));
    assert!(unsigned.contains("\"payload_hash\""));
    assert!(unsigned.starts_with("{\"expires_at\":"));
}

#[test]
fn independently_routed_required_roles_validate_as_transport_only() {
    let result = validate_independent_artifact_set(
        &[envelope("chatgpt"), envelope("claude")],
        &trust_policy(),
        &expectation(),
    )
    .unwrap();
    assert_eq!(result.by_role.len(), 2);
    assert_eq!(result.by_role["chatgpt"].provider, "openai");
    assert_eq!(result.by_role["claude"].provider, "anthropic");
}

#[test]
fn duplicate_authority_fields_fail_closed() {
    let chatgpt = envelope("chatgpt");
    let mut claude = envelope("claude");
    claude.producer.worker_id = chatgpt.producer.worker_id.clone();
    expect_code(
        validate_independent_artifact_set(
            &[chatgpt, claude],
            &trust_policy(),
            &expectation(),
        ),
        "independence_violation",
    );

    let mut policy = trust_policy();
    policy.distinct_authority_fields = vec![DistinctAuthorityField::KeyId];
    let chatgpt = envelope("chatgpt");
    let mut claude = envelope("claude");
    claude.producer.key_id = chatgpt.producer.key_id.clone();
    expect_code(
        validate_independent_artifact_set(&[chatgpt, claude], &policy, &expectation()),
        "unauthorized_role",
    );
}

#[test]
fn trust_policy_rejects_key_aliases_multi_role_keys_and_private_keys() {
    let mut aliases = trust_policy();
    let chatgpt_pem = aliases.keys["openai-opinion-2026-08"]
        .public_key_pem
        .clone();
    aliases
        .keys
        .get_mut("anthropic-opinion-2026-08")
        .unwrap()
        .public_key_pem = chatgpt_pem;
    expect_code(aliases.validate(), "invalid_trust_policy");

    let mut multi_role = trust_policy();
    multi_role
        .keys
        .get_mut("openai-opinion-2026-08")
        .unwrap()
        .roles
        .push("claude".to_string());
    expect_code(multi_role.validate(), "invalid_trust_policy");

    let mut private_key = trust_policy();
    private_key
        .keys
        .get_mut("openai-opinion-2026-08")
        .unwrap()
        .public_key_pem =
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----".to_string();
    expect_code(private_key.validate(), "invalid_trust_policy");
}

#[test]
fn trusted_key_metadata_anchors_provider_domain_role_and_task() {
    let mut provider_swap = envelope("chatgpt");
    provider_swap.provider = "anthropic".to_string();
    expect_code(
        validate_independent_artifact_set(
            &[provider_swap, envelope("claude")],
            &trust_policy(),
            &expectation(),
        ),
        "provider_mismatch",
    );

    let mut wrong_domain = envelope("chatgpt");
    wrong_domain.producer.trust_domain = "anthropic-opinion-worker".to_string();
    expect_code(
        validate_independent_artifact_set(
            &[wrong_domain, envelope("claude")],
            &trust_policy(),
            &expectation(),
        ),
        "trust_domain_mismatch",
    );

    let mut wrong_task = envelope("chatgpt");
    wrong_task.producer.task_type = "linear_opinion_claude".to_string();
    expect_code(
        validate_independent_artifact_set(
            &[wrong_task, envelope("claude")],
            &trust_policy(),
            &expectation(),
        ),
        "task_type_mismatch",
    );
}

#[test]
fn exact_subject_policy_and_payload_hash_are_required() {
    let mut wrong_subject = expectation();
    wrong_subject.subject.revision_digest =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .to_string();
    expect_code(
        validate_independent_artifact_set(
            &[envelope("chatgpt"), envelope("claude")],
            &trust_policy(),
            &wrong_subject,
        ),
        "subject_mismatch",
    );

    let mut wrong_policy = expectation();
    wrong_policy.policy_digest =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_string();
    expect_code(
        validate_independent_artifact_set(
            &[envelope("chatgpt"), envelope("claude")],
            &trust_policy(),
            &wrong_policy,
        ),
        "policy_mismatch",
    );

    let mut tampered = envelope("chatgpt");
    tampered.payload["summary"] = json!("changed after hashing");
    expect_code(tampered.validate_transport(), "payload_hash_mismatch");
}

#[test]
fn secret_and_hidden_reasoning_keys_are_rejected_recursively() {
    for key in ["authorization", "private-key", "chain_of_thought"] {
        let mut artifact = envelope("chatgpt");
        let mut nested = Map::new();
        nested.insert(
            key.to_string(),
            Value::String("must not cross the artifact boundary".to_string()),
        );
        artifact.payload["nested"] = Value::Object(nested);
        artifact.payload_hash = artifact.canonical_payload_hash().unwrap();
        expect_code(
            validate_independent_artifact_set(
                &[artifact, envelope("claude")],
                &trust_policy(),
                &expectation(),
            ),
            "forbidden_payload_key",
        );
    }
}

#[test]
fn malformed_signature_schema_and_unknown_fields_fail_closed() {
    let mut malformed_signature = envelope("chatgpt");
    malformed_signature.signature = "not padded=".to_string();
    expect_code(
        malformed_signature.validate_transport(),
        "invalid_signature_encoding",
    );

    let mut unknown = serde_json::to_value(envelope("chatgpt")).unwrap();
    unknown["public_key_pem"] = json!(public_key_pem("AAAA"));
    assert!(serde_json::from_value::<SignedArtifactEnvelope>(unknown).is_err());

    let mut wrong_schema = envelope("chatgpt");
    wrong_schema.schema_version = "reconciliation.attestation.v2".to_string();
    expect_code(wrong_schema.validate_transport(), "unsupported_schema");
}
