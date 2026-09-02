#![forbid(unsafe_code)]

//! Vendor-neutral signed-result artifact transport contracts for Agent Pontifex.
//!
//! This crate validates bounded artifact shapes, canonical payload hashes,
//! external trust-routing metadata, exact subject/policy bindings, and producer
//! independence. It deliberately does **not** perform cryptographic signature
//! verification or authorize side effects. A downstream finalizer must verify
//! each signature with the externally configured public key, validate time and
//! revocation policy, re-fetch current product state, and apply compare-and-set
//! rules before mutating GitHub, Linear, or any other system.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

pub const ARTIFACT_SCHEMA_VERSION: &str = "reconciliation.attestation.v1";
pub const TRUST_POLICY_SCHEMA_VERSION: &str = "reconciliation.trust-policy.v1";

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_PUBLIC_KEY_BYTES: usize = 16 * 1024;
const MAX_SIGNATURE_BYTES: usize = 4096;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_ARRAY_ITEMS: usize = 128;
const MAX_OBJECT_KEYS: usize = 128;
const MAX_DEPTH: usize = 16;
const MAX_REQUIRED_ROLES: usize = 32;
const MAX_TRUSTED_KEYS: usize = 128;
const FORBIDDEN_PAYLOAD_KEYS: &[&str] = &[
    "authorization",
    "cookie",
    "credentials",
    "password",
    "secret",
    "token",
    "api_key",
    "access_key",
    "secret_access_key",
    "private_key",
    "chain_of_thought",
    "reasoning_trace",
    "raw_provider_response",
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSubject {
    pub kind: String,
    pub id: String,
    pub revision_digest: String,
}

impl ArtifactSubject {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_identifier(&self.kind, "subject.kind")?;
        validate_bounded_text(&self.id, "subject.id", 512)?;
        validate_digest(&self.revision_digest, "subject.revision_digest")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactProducer {
    pub key_id: String,
    pub trust_domain: String,
    pub worker_id: String,
    pub job_id: String,
    pub task_type: String,
}

impl ArtifactProducer {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_bounded_text(&self.key_id, "producer.key_id", 512)?;
        validate_bounded_text(&self.trust_domain, "producer.trust_domain", 512)?;
        validate_bounded_text(&self.worker_id, "producer.worker_id", 512)?;
        validate_bounded_text(&self.job_id, "producer.job_id", 512)?;
        validate_bounded_text(&self.task_type, "producer.task_type", 512)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedArtifactEnvelope {
    pub schema_version: String,
    pub role: String,
    pub provider: String,
    pub subject: ArtifactSubject,
    pub policy_digest: String,
    pub producer: ArtifactProducer,
    pub issued_at: String,
    pub expires_at: String,
    pub payload_hash: String,
    pub payload: Value,
    pub signature: String,
}

impl SignedArtifactEnvelope {
    /// Validates transport shape and the canonical payload hash.
    ///
    /// Success is not cryptographic verification and is not mutation authority.
    pub fn validate_transport(&self) -> Result<(), ValidationError> {
        if self.schema_version != ARTIFACT_SCHEMA_VERSION {
            return Err(ValidationError::new(
                "unsupported_schema",
                "unsupported signed artifact schema version",
            ));
        }
        validate_identifier(&self.role, "role")?;
        validate_identifier(&self.provider, "provider")?;
        self.subject.validate()?;
        validate_digest(&self.policy_digest, "policy_digest")?;
        self.producer.validate()?;
        validate_timestamp(&self.issued_at, "issued_at")?;
        validate_timestamp(&self.expires_at, "expires_at")?;
        if self.issued_at == self.expires_at {
            return Err(ValidationError::new(
                "invalid_time_window",
                "artifact issuance and expiration must differ",
            ));
        }
        validate_digest(&self.payload_hash, "payload_hash")?;
        validate_value(&self.payload, 0)?;
        let canonical_payload = canonical_json(&self.payload)?;
        if canonical_payload.len() > MAX_PAYLOAD_BYTES {
            return Err(ValidationError::new(
                "payload_too_large",
                "artifact payload exceeds the maximum canonical size",
            ));
        }
        let actual_hash = sha256_hex(canonical_payload.as_bytes());
        if actual_hash != self.payload_hash {
            return Err(ValidationError::new(
                "payload_hash_mismatch",
                "artifact payload hash does not match its canonical payload",
            ));
        }
        validate_base64url(&self.signature, "signature")
    }

    pub fn canonical_payload_hash(&self) -> Result<String, ValidationError> {
        let canonical_payload = canonical_json(&self.payload)?;
        Ok(sha256_hex(canonical_payload.as_bytes()))
    }

    /// Returns the exact canonical JSON bytes that an implementation signs.
    ///
    /// The `signature` property is removed and all object keys are sorted
    /// recursively. Callers must still select and enforce a concrete signature
    /// algorithm through the external trust policy.
    pub fn unsigned_canonical_json(&self) -> Result<String, ValidationError> {
        let mut value = serde_json::to_value(self).map_err(|error| {
            ValidationError::new(
                "serialization_failure",
                format!("failed to serialize signed artifact: {error}"),
            )
        })?;
        let object = value.as_object_mut().ok_or_else(|| {
            ValidationError::new(
                "serialization_failure",
                "signed artifact did not serialize as an object",
            )
        })?;
        object.remove("signature");
        canonical_json(&value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedArtifactKey {
    pub public_key_pem: String,
    pub roles: Vec<String>,
    pub provider: String,
    pub trust_domain: String,
    pub task_types: Vec<String>,
}

impl TrustedArtifactKey {
    fn validate(&self, key_id: &str) -> Result<(), ValidationError> {
        validate_bounded_text(key_id, "trusted key id", 512)?;
        validate_public_key_pem(&self.public_key_pem, key_id)?;
        validate_identifier(&self.provider, "trusted key provider")?;
        validate_bounded_text(&self.trust_domain, "trusted key trust_domain", 512)?;
        validate_unique_identifiers(&self.roles, "trusted key roles", MAX_REQUIRED_ROLES)?;
        validate_unique_bounded_strings(&self.task_types, "trusted key task_types", 128, 512)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DistinctProducerField {
    KeyId,
    TrustDomain,
    WorkerId,
    JobId,
    TaskType,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactTrustPolicy {
    pub schema_version: String,
    pub required_roles: Vec<String>,
    pub keys: BTreeMap<String, TrustedArtifactKey>,
    pub distinct_producer_fields: Vec<DistinctProducerField>,
}

impl ArtifactTrustPolicy {
    pub fn strict(required_roles: Vec<String>, keys: BTreeMap<String, TrustedArtifactKey>) -> Self {
        Self {
            schema_version: TRUST_POLICY_SCHEMA_VERSION.to_string(),
            required_roles,
            keys,
            distinct_producer_fields: default_distinct_producer_fields(),
        }
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != TRUST_POLICY_SCHEMA_VERSION {
            return Err(ValidationError::new(
                "invalid_trust_policy",
                "unsupported artifact trust-policy schema version",
            ));
        }
        validate_unique_identifiers(&self.required_roles, "required_roles", MAX_REQUIRED_ROLES)?;
        if self.keys.is_empty() || self.keys.len() > MAX_TRUSTED_KEYS {
            return Err(ValidationError::new(
                "invalid_trust_policy",
                "trust policy must contain between 1 and 128 keys",
            ));
        }
        if self.distinct_producer_fields.is_empty() {
            return Err(ValidationError::new(
                "invalid_trust_policy",
                "trust policy must require at least one distinct producer field",
            ));
        }
        let distinct_fields: BTreeSet<_> = self.distinct_producer_fields.iter().copied().collect();
        if distinct_fields.len() != self.distinct_producer_fields.len() {
            return Err(ValidationError::new(
                "invalid_trust_policy",
                "distinct producer fields must not contain duplicates",
            ));
        }

        let required_roles: BTreeSet<&str> =
            self.required_roles.iter().map(String::as_str).collect();
        let mut public_keys = BTreeSet::new();
        let mut covered_roles = BTreeSet::new();
        for (key_id, key) in &self.keys {
            key.validate(key_id)?;
            let normalized_public_key = normalize_pem(&key.public_key_pem);
            if !public_keys.insert(normalized_public_key) {
                return Err(ValidationError::new(
                    "invalid_trust_policy",
                    "distinct key IDs must not alias the same public key",
                ));
            }
            covered_roles.extend(
                key.roles
                    .iter()
                    .map(String::as_str)
                    .filter(|role| required_roles.contains(role)),
            );
        }
        if covered_roles != required_roles {
            return Err(ValidationError::new(
                "invalid_trust_policy",
                "every required role must be authorized by a trusted key",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactExpectation {
    pub subject: ArtifactSubject,
    pub policy_digest: String,
}

impl ArtifactExpectation {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.subject.validate()?;
        validate_digest(&self.policy_digest, "expected policy_digest")
    }
}

/// A structurally and trust-routing validated artifact set.
///
/// This type intentionally does not claim that signatures, expiry, revocation,
/// leases, or product state have been verified. It must not be used as direct
/// side-effect authorization.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedTransportArtifactSet {
    pub subject: ArtifactSubject,
    pub policy_digest: String,
    pub by_role: BTreeMap<String, SignedArtifactEnvelope>,
}

pub fn validate_independent_artifact_set(
    artifacts: &[SignedArtifactEnvelope],
    trust_policy: &ArtifactTrustPolicy,
    expectation: &ArtifactExpectation,
) -> Result<ValidatedTransportArtifactSet, ValidationError> {
    trust_policy.validate()?;
    expectation.validate()?;
    if artifacts.len() != trust_policy.required_roles.len() {
        return Err(ValidationError::new(
            "role_set_mismatch",
            "artifact count must exactly match the required role count",
        ));
    }

    let required_roles: BTreeSet<&str> = trust_policy
        .required_roles
        .iter()
        .map(String::as_str)
        .collect();
    let forbidden_keys: BTreeSet<String> = FORBIDDEN_PAYLOAD_KEYS
        .iter()
        .map(|key| normalize_payload_key(key))
        .collect();
    let mut by_role = BTreeMap::new();

    for artifact in artifacts {
        artifact.validate_transport()?;
        if artifact.subject != expectation.subject {
            return Err(ValidationError::new(
                "subject_mismatch",
                "artifact subject does not match the finalizer expectation",
            ));
        }
        if artifact.policy_digest != expectation.policy_digest {
            return Err(ValidationError::new(
                "policy_mismatch",
                "artifact policy digest does not match the finalizer expectation",
            ));
        }
        if !required_roles.contains(artifact.role.as_str()) {
            return Err(ValidationError::new(
                "role_set_mismatch",
                format!("unexpected artifact role: {}", artifact.role),
            ));
        }
        validate_forbidden_payload_keys(&artifact.payload, &forbidden_keys)?;

        let key = trust_policy
            .keys
            .get(&artifact.producer.key_id)
            .ok_or_else(|| {
                ValidationError::new(
                    "untrusted_key",
                    format!("artifact key is not trusted: {}", artifact.producer.key_id),
                )
            })?;
        if !key.roles.iter().any(|role| role == &artifact.role) {
            return Err(ValidationError::new(
                "unauthorized_role",
                "trusted key is not authorized for the artifact role",
            ));
        }
        if key.provider != artifact.provider {
            return Err(ValidationError::new(
                "provider_mismatch",
                "artifact provider does not match trusted key metadata",
            ));
        }
        if key.trust_domain != artifact.producer.trust_domain {
            return Err(ValidationError::new(
                "trust_domain_mismatch",
                "artifact trust domain does not match trusted key metadata",
            ));
        }
        if !key
            .task_types
            .iter()
            .any(|task_type| task_type == &artifact.producer.task_type)
        {
            return Err(ValidationError::new(
                "task_type_mismatch",
                "artifact task type is not authorized for the trusted key",
            ));
        }
        if by_role
            .insert(artifact.role.clone(), artifact.clone())
            .is_some()
        {
            return Err(ValidationError::new(
                "role_set_mismatch",
                "artifact roles must not contain duplicates",
            ));
        }
    }

    if by_role.len() != required_roles.len()
        || required_roles
            .iter()
            .any(|role| !by_role.contains_key(*role))
    {
        return Err(ValidationError::new(
            "role_set_mismatch",
            "artifact set is missing a required role",
        ));
    }

    for field in &trust_policy.distinct_producer_fields {
        let mut seen = BTreeSet::new();
        for artifact in by_role.values() {
            let value = producer_field(artifact, *field);
            if !seen.insert(value) {
                return Err(ValidationError::new(
                    "independence_violation",
                    format!("required producer field is duplicated: {field:?}"),
                ));
            }
        }
    }

    Ok(ValidatedTransportArtifactSet {
        subject: expectation.subject.clone(),
        policy_digest: expectation.policy_digest.clone(),
        by_role,
    })
}

pub fn canonical_json(value: &Value) -> Result<String, ValidationError> {
    serde_json::to_string(&canonicalize(value.clone())).map_err(|error| {
        ValidationError::new(
            "serialization_failure",
            format!("failed to serialize canonical JSON: {error}"),
        )
    })
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(object) => {
            let mut entries: Vec<_> = object.into_iter().collect();
            entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            let mut canonical = Map::new();
            for (key, value) in entries {
                canonical.insert(key, canonicalize(value));
            }
            Value::Object(canonical)
        }
        primitive => primitive,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

fn producer_field(artifact: &SignedArtifactEnvelope, field: DistinctProducerField) -> &str {
    match field {
        DistinctProducerField::KeyId => &artifact.producer.key_id,
        DistinctProducerField::TrustDomain => &artifact.producer.trust_domain,
        DistinctProducerField::WorkerId => &artifact.producer.worker_id,
        DistinctProducerField::JobId => &artifact.producer.job_id,
        DistinctProducerField::TaskType => &artifact.producer.task_type,
    }
}

fn validate_identifier(value: &str, label: &str) -> Result<(), ValidationError> {
    validate_bounded_text(value, label, MAX_IDENTIFIER_BYTES)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
    }) {
        return Err(ValidationError::new(
            "invalid_identifier",
            format!("{label} must use lowercase ASCII identifier characters"),
        ));
    }
    Ok(())
}

fn validate_bounded_text(
    value: &str,
    label: &str,
    maximum_bytes: usize,
) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        return Err(ValidationError::new(
            "invalid_text",
            format!("{label} must be non-empty, bounded, and free of control characters"),
        ));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), ValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ValidationError::new(
            "invalid_digest",
            format!("{label} must be a lowercase SHA-256 digest"),
        ));
    }
    Ok(())
}

fn validate_timestamp(value: &str, label: &str) -> Result<(), ValidationError> {
    validate_bounded_text(value, label, 64)?;
    if value.len() < 20 || !value.contains('T') || !value.ends_with('Z') {
        return Err(ValidationError::new(
            "invalid_timestamp",
            format!("{label} must be a canonical UTC timestamp"),
        ));
    }
    Ok(())
}

fn validate_base64url(value: &str, label: &str) -> Result<(), ValidationError> {
    if value.len() < 16
        || value.len() > MAX_SIGNATURE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ValidationError::new(
            "invalid_signature_encoding",
            format!("{label} must use bounded unpadded base64url encoding"),
        ));
    }
    Ok(())
}

fn validate_public_key_pem(value: &str, key_id: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > MAX_PUBLIC_KEY_BYTES
        || value
            .chars()
            .any(|character| character.is_control() && character != '\n')
    {
        return Err(ValidationError::new(
            "invalid_trust_policy",
            format!(
                "trusted key {key_id} must be bounded and contain canonical LF line breaks only"
            ),
        ));
    }
    if value.contains("PRIVATE KEY")
        || !value.starts_with("-----BEGIN PUBLIC KEY-----\n")
        || !value.ends_with("\n-----END PUBLIC KEY-----")
    {
        return Err(ValidationError::new(
            "invalid_trust_policy",
            format!("trusted key {key_id} must contain a public-key PEM only"),
        ));
    }
    let body = value
        .strip_prefix("-----BEGIN PUBLIC KEY-----\n")
        .and_then(|candidate| candidate.strip_suffix("\n-----END PUBLIC KEY-----"))
        .ok_or_else(|| {
            ValidationError::new(
                "invalid_trust_policy",
                format!("trusted key {key_id} has an invalid PEM envelope"),
            )
        })?;
    let compact: String = body
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact.is_empty()
        || !compact
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(ValidationError::new(
            "invalid_trust_policy",
            format!("trusted key {key_id} has an invalid PEM body"),
        ));
    }
    Ok(())
}

fn normalize_pem(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn validate_unique_identifiers(
    values: &[String],
    label: &str,
    maximum_items: usize,
) -> Result<(), ValidationError> {
    if values.is_empty() || values.len() > maximum_items {
        return Err(ValidationError::new(
            "invalid_trust_policy",
            format!("{label} must contain between 1 and {maximum_items} entries"),
        ));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_identifier(value, label)?;
        if !seen.insert(value.as_str()) {
            return Err(ValidationError::new(
                "invalid_trust_policy",
                format!("{label} must not contain duplicates"),
            ));
        }
    }
    Ok(())
}

fn validate_unique_bounded_strings(
    values: &[String],
    label: &str,
    maximum_items: usize,
    maximum_bytes: usize,
) -> Result<(), ValidationError> {
    if values.is_empty() || values.len() > maximum_items {
        return Err(ValidationError::new(
            "invalid_trust_policy",
            format!("{label} must contain between 1 and {maximum_items} entries"),
        ));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_bounded_text(value, label, maximum_bytes)?;
        if !seen.insert(value.as_str()) {
            return Err(ValidationError::new(
                "invalid_trust_policy",
                format!("{label} must not contain duplicates"),
            ));
        }
    }
    Ok(())
}

fn validate_value(value: &Value, depth: usize) -> Result<(), ValidationError> {
    if depth > MAX_DEPTH {
        return Err(ValidationError::new(
            "payload_too_deep",
            "artifact payload exceeds the maximum nesting depth",
        ));
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
        Value::String(text) => {
            if text.len() > MAX_TEXT_BYTES {
                return Err(ValidationError::new(
                    "payload_text_too_large",
                    "artifact payload contains an oversized string",
                ));
            }
            Ok(())
        }
        Value::Array(values) => {
            if values.len() > MAX_ARRAY_ITEMS {
                return Err(ValidationError::new(
                    "payload_array_too_large",
                    "artifact payload contains too many array entries",
                ));
            }
            for child in values {
                validate_value(child, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            if object.len() > MAX_OBJECT_KEYS {
                return Err(ValidationError::new(
                    "payload_object_too_large",
                    "artifact payload contains too many object keys",
                ));
            }
            for (key, child) in object {
                validate_bounded_text(key, "payload object key", 512)?;
                validate_value(child, depth + 1)?;
            }
            Ok(())
        }
    }
}

fn normalize_payload_key(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn validate_forbidden_payload_keys(
    value: &Value,
    forbidden_keys: &BTreeSet<String>,
) -> Result<(), ValidationError> {
    match value {
        Value::Array(values) => {
            for child in values {
                validate_forbidden_payload_keys(child, forbidden_keys)?;
            }
        }
        Value::Object(object) => {
            for (key, child) in object {
                if forbidden_keys.contains(&normalize_payload_key(key)) {
                    return Err(ValidationError::new(
                        "forbidden_payload_key",
                        format!("artifact payload contains forbidden key: {key}"),
                    ));
                }
                validate_forbidden_payload_keys(child, forbidden_keys)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn default_distinct_producer_fields() -> Vec<DistinctProducerField> {
    vec![
        DistinctProducerField::KeyId,
        DistinctProducerField::TrustDomain,
        DistinctProducerField::WorkerId,
        DistinctProducerField::JobId,
        DistinctProducerField::TaskType,
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationError {
    code: &'static str,
    message: String,
}

impl ValidationError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ValidationError {}
