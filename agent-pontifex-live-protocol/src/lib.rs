#![forbid(unsafe_code)]

//! Transport-neutral live-session contracts for Agent Pontifex participants.
//!
//! These types describe externally observable messages, decisions, tool intents,
//! approvals, progress, evidence, and tracker links. They never require or expose
//! hidden chain-of-thought. A bridge transports these frames; a separately
//! authorized finalizer remains responsible for irreversible side effects.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

pub const LIVE_PROTOCOL_ID: &str = "agent-pontifex.live";
pub const LIVE_SCHEMA_VERSION: u16 = 1;
pub const CURRENT_LIVE_PROTOCOL_MAJOR: u16 = 1;
pub const MAX_SAFE_SEQUENCE: u64 = 9_007_199_254_740_991;

const MAX_ID_BYTES: usize = 256;
const MAX_TITLE_BYTES: usize = 1_024;
const MAX_TEXT_BYTES: usize = 1_048_576;
const MAX_JSON_BYTES: usize = 1_048_576;
const MAX_PARTICIPANTS: usize = 64;
const MAX_RECIPIENTS: usize = 64;
const MAX_CAPABILITIES: usize = 256;
const MAX_TRACKER_LINKS: usize = 64;
const MAX_EVIDENCE_REFS: usize = 128;
const MAX_EXTENSIONS: usize = 64;
const MAX_EXTENSION_BYTES: usize = 64 * 1024;
const MIN_IDEMPOTENCY_BYTES: usize = 16;
const MAX_IDEMPOTENCY_BYTES: usize = 128;

pub type Timestamp = String;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantRole {
    Moderator,
    Finalizer,
    Observer,
    #[default]
    Member,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Active,
    Closing,
    Closed,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    Accepted,
    Rejected,
    Deferred,
    Superseded,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolOutcome {
    Succeeded,
    Failed,
    Denied,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOutcome {
    Approved,
    Denied,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkState {
    Planned,
    Claimed,
    Running,
    Blocked,
    AwaitingReview,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderIdentity {
    /// Stable participant identity inside the bridge, not a vendor credential.
    pub participant_id: String,
    /// Provider namespace, such as `openai`, `anthropic`, `xai`, or `local`.
    pub provider: String,
    /// Provider model or local runtime model identifier.
    pub model: String,
    /// Optional adapter/runtime identity, such as `openai-responses-worker`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// Optional deployment instance identifier. It must not contain a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
}

impl ProviderIdentity {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_token(&self.participant_id, "participant_id", MAX_ID_BYTES)?;
        validate_token(&self.provider, "provider", 128)?;
        validate_token(&self.model, "model", MAX_ID_BYTES)?;
        validate_optional_token(&self.runtime, "runtime", MAX_ID_BYTES)?;
        validate_optional_token(&self.instance_id, "instance_id", MAX_ID_BYTES)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Participant {
    pub identity: ProviderIdentity,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub role: ParticipantRole,
    /// Sorted, unique, namespaced capabilities such as `agent.review`.
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub joined_at: Timestamp,
}

impl Participant {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.identity.validate()?;
        validate_optional_text(&self.display_name, "display_name", 512)?;
        validate_capabilities(&self.capabilities)?;
        validate_timestamp(&self.joined_at, "joined_at")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrackerLink {
    /// Namespaced tracker kind, for example `github.issue` or `linear.issue`.
    pub kind: String,
    /// Stable external reference, for example `agent-pontifex/agent-sdk.rs#12`.
    pub reference: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation: Option<String>,
}

impl TrackerLink {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_namespaced_identifier(&self.kind, "tracker kind")?;
        validate_text(&self.reference, "tracker reference", MAX_ID_BYTES)?;
        validate_https_url(&self.url, "tracker url")?;
        validate_optional_token(&self.relation, "tracker relation", 128)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    /// Namespaced evidence kind, for example `github.commit` or `test.report`.
    pub kind: String,
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

impl EvidenceRef {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_namespaced_identifier(&self.kind, "evidence kind")?;
        validate_text(&self.uri, "evidence uri", 2_048)?;
        validate_optional_token(&self.digest, "evidence digest", MAX_ID_BYTES)?;
        if let Some(summary) = &self.summary {
            validate_text(summary, "evidence summary", 4_096)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LiveSession {
    pub schema_version: u16,
    pub protocol: String,
    pub session_id: String,
    /// Existing bridge channel used as the ordered conversation log.
    pub channel: String,
    pub title: String,
    pub state: SessionState,
    pub created_by: String,
    pub created_at: Timestamp,
    #[serde(default)]
    pub participants: Vec<Participant>,
    #[serde(default)]
    pub tracker_links: Vec<TrackerLink>,
    /// Last server-assigned event sequence visible when this view was produced.
    #[serde(default)]
    pub high_water_seq: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

impl LiveSession {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != LIVE_SCHEMA_VERSION || self.protocol != LIVE_PROTOCOL_ID {
            return Err(ValidationError::new("unsupported live-session protocol"));
        }
        validate_token(&self.session_id, "session_id", MAX_ID_BYTES)?;
        validate_token(&self.channel, "channel", MAX_ID_BYTES)?;
        validate_text(&self.title, "title", MAX_TITLE_BYTES)?;
        validate_token(&self.created_by, "created_by", MAX_ID_BYTES)?;
        validate_timestamp(&self.created_at, "created_at")?;
        validate_sequence(self.high_water_seq, true)?;

        if self.participants.is_empty() || self.participants.len() > MAX_PARTICIPANTS {
            return Err(ValidationError::new(format!(
                "participants must contain 1 to {MAX_PARTICIPANTS} entries"
            )));
        }
        let mut participant_ids = BTreeSet::new();
        for participant in &self.participants {
            participant.validate()?;
            if !participant_ids.insert(participant.identity.participant_id.as_str()) {
                return Err(ValidationError::new("duplicate participant_id"));
            }
        }
        if !participant_ids.contains(self.created_by.as_str()) {
            return Err(ValidationError::new(
                "created_by must identify a session participant",
            ));
        }

        if self.tracker_links.len() > MAX_TRACKER_LINKS {
            return Err(ValidationError::new("too many tracker links"));
        }
        for link in &self.tracker_links {
            link.validate()?;
        }
        validate_extensions(&self.extensions)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LivePayload {
    Message {
        content: String,
        #[serde(default = "default_content_type")]
        content_type: String,
    },
    Proposal {
        proposal_id: String,
        summary: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        details: Option<String>,
    },
    Decision {
        proposal_id: String,
        outcome: DecisionOutcome,
        /// Concise, externally shareable decision basis; never hidden reasoning.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decision_basis: Option<String>,
    },
    ToolRequest {
        request_id: String,
        tool: String,
        action: String,
        capability: String,
        #[serde(default)]
        arguments: Value,
        #[serde(default)]
        requires_approval: bool,
    },
    ToolResult {
        request_id: String,
        outcome: ToolOutcome,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        #[serde(default)]
        evidence: Vec<EvidenceRef>,
    },
    ApprovalRequest {
        approval_id: String,
        subject: String,
        requested_capabilities: Vec<String>,
        expires_at: Timestamp,
    },
    ApprovalDecision {
        approval_id: String,
        outcome: ApprovalOutcome,
        decided_by: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decision_basis: Option<String>,
    },
    WorkStatus {
        work_id: String,
        state: WorkState,
        summary: String,
        /// Progress in basis points, from 0 through 10,000.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        progress_bps: Option<u16>,
        #[serde(default)]
        evidence: Vec<EvidenceRef>,
    },
    Handoff {
        work_id: String,
        to: String,
        summary: String,
        #[serde(default)]
        context_refs: Vec<String>,
    },
    TrackerUpdate {
        link: TrackerLink,
        summary: String,
    },
    Error {
        code: String,
        message: String,
        #[serde(default)]
        retryable: bool,
    },
}

fn default_content_type() -> String {
    "text/plain".to_string()
}

impl LivePayload {
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Message {
                content,
                content_type,
            } => {
                validate_text(content, "message content", MAX_TEXT_BYTES)?;
                validate_token(content_type, "content_type", 128)
            }
            Self::Proposal {
                proposal_id,
                summary,
                details,
            } => {
                validate_token(proposal_id, "proposal_id", MAX_ID_BYTES)?;
                validate_text(summary, "proposal summary", 16_384)?;
                if let Some(details) = details {
                    validate_text(details, "proposal details", MAX_TEXT_BYTES)?;
                }
                Ok(())
            }
            Self::Decision {
                proposal_id,
                decision_basis,
                ..
            } => {
                validate_token(proposal_id, "proposal_id", MAX_ID_BYTES)?;
                validate_optional_shareable_text(decision_basis, "decision_basis")
            }
            Self::ToolRequest {
                request_id,
                tool,
                action,
                capability,
                arguments,
                ..
            } => {
                validate_token(request_id, "request_id", MAX_ID_BYTES)?;
                validate_namespaced_identifier(tool, "tool")?;
                validate_token(action, "tool action", MAX_ID_BYTES)?;
                validate_namespaced_identifier(capability, "tool capability")?;
                validate_json(arguments, "tool arguments")
            }
            Self::ToolResult {
                request_id,
                outcome,
                result,
                error,
                evidence,
            } => {
                validate_token(request_id, "request_id", MAX_ID_BYTES)?;
                if let Some(result) = result {
                    validate_json(result, "tool result")?;
                }
                if let Some(error) = error {
                    validate_text(error, "tool error", 16_384)?;
                }
                if matches!(outcome, ToolOutcome::Failed) && error.is_none() {
                    return Err(ValidationError::new(
                        "failed tool results require a bounded error",
                    ));
                }
                validate_evidence(evidence)
            }
            Self::ApprovalRequest {
                approval_id,
                subject,
                requested_capabilities,
                expires_at,
            } => {
                validate_token(approval_id, "approval_id", MAX_ID_BYTES)?;
                validate_text(subject, "approval subject", 16_384)?;
                if requested_capabilities.is_empty() {
                    return Err(ValidationError::new(
                        "approval requests require at least one capability",
                    ));
                }
                validate_capabilities(requested_capabilities)?;
                validate_timestamp(expires_at, "expires_at")
            }
            Self::ApprovalDecision {
                approval_id,
                decided_by,
                decision_basis,
                ..
            } => {
                validate_token(approval_id, "approval_id", MAX_ID_BYTES)?;
                validate_token(decided_by, "decided_by", MAX_ID_BYTES)?;
                validate_optional_shareable_text(decision_basis, "decision_basis")
            }
            Self::WorkStatus {
                work_id,
                summary,
                progress_bps,
                evidence,
                ..
            } => {
                validate_token(work_id, "work_id", MAX_ID_BYTES)?;
                validate_text(summary, "work summary", 16_384)?;
                if progress_bps.is_some_and(|value| value > 10_000) {
                    return Err(ValidationError::new(
                        "progress_bps must be between 0 and 10000",
                    ));
                }
                validate_evidence(evidence)
            }
            Self::Handoff {
                work_id,
                to,
                summary,
                context_refs,
            } => {
                validate_token(work_id, "work_id", MAX_ID_BYTES)?;
                validate_token(to, "handoff recipient", MAX_ID_BYTES)?;
                validate_text(summary, "handoff summary", 16_384)?;
                if context_refs.len() > 128 {
                    return Err(ValidationError::new("too many handoff context refs"));
                }
                let mut seen = BTreeSet::new();
                for context_ref in context_refs {
                    validate_token(context_ref, "context ref", MAX_ID_BYTES)?;
                    if !seen.insert(context_ref) {
                        return Err(ValidationError::new("duplicate handoff context ref"));
                    }
                }
                Ok(())
            }
            Self::TrackerUpdate { link, summary } => {
                link.validate()?;
                validate_text(summary, "tracker update summary", 16_384)
            }
            Self::Error { code, message, .. } => {
                validate_namespaced_identifier(code, "error code")?;
                validate_text(message, "error message", 16_384)
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublishEvent {
    pub client_event_id: String,
    pub session_id: String,
    pub channel: String,
    pub sender: String,
    #[serde(default)]
    pub recipients: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causation_id: Option<String>,
    /// Required for exactly-once acceptance within the finalizer's retention window.
    pub idempotency_key: String,
    pub payload: LivePayload,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

impl PublishEvent {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_token(&self.client_event_id, "client_event_id", MAX_ID_BYTES)?;
        validate_token(&self.session_id, "session_id", MAX_ID_BYTES)?;
        validate_token(&self.channel, "channel", MAX_ID_BYTES)?;
        validate_token(&self.sender, "sender", MAX_ID_BYTES)?;
        validate_recipients(&self.recipients)?;
        validate_optional_token(&self.correlation_id, "correlation_id", MAX_ID_BYTES)?;
        validate_optional_token(&self.causation_id, "causation_id", MAX_ID_BYTES)?;
        validate_idempotency_key(&self.idempotency_key)?;
        self.payload.validate()?;
        validate_extensions(&self.extensions)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LiveEnvelope {
    pub schema_version: u16,
    pub protocol: String,
    pub event_id: String,
    pub session_id: String,
    pub channel: String,
    /// Monotonic, server-assigned sequence scoped to the session channel.
    pub seq: u64,
    pub sender: String,
    #[serde(default)]
    pub recipients: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causation_id: Option<String>,
    pub idempotency_key: String,
    pub created_at: Timestamp,
    pub payload: LivePayload,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

impl LiveEnvelope {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != LIVE_SCHEMA_VERSION || self.protocol != LIVE_PROTOCOL_ID {
            return Err(ValidationError::new("unsupported live envelope protocol"));
        }
        validate_token(&self.event_id, "event_id", MAX_ID_BYTES)?;
        validate_token(&self.session_id, "session_id", MAX_ID_BYTES)?;
        validate_token(&self.channel, "channel", MAX_ID_BYTES)?;
        validate_sequence(self.seq, false)?;
        validate_token(&self.sender, "sender", MAX_ID_BYTES)?;
        validate_recipients(&self.recipients)?;
        validate_optional_token(&self.correlation_id, "correlation_id", MAX_ID_BYTES)?;
        validate_optional_token(&self.causation_id, "causation_id", MAX_ID_BYTES)?;
        validate_idempotency_key(&self.idempotency_key)?;
        validate_timestamp(&self.created_at, "created_at")?;
        self.payload.validate()?;
        validate_extensions(&self.extensions)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResumeCursor {
    #[serde(default)]
    pub after_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<String>,
}

impl ResumeCursor {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_sequence(self.after_seq, true)?;
        validate_optional_token(&self.last_event_id, "last_event_id", MAX_ID_BYTES)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientFrame {
    Hello {
        participant: ProviderIdentity,
        session_id: String,
        #[serde(default)]
        capabilities: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resume: Option<ResumeCursor>,
    },
    Publish {
        event: PublishEvent,
    },
    Ack {
        session_id: String,
        through_seq: u64,
    },
    Ping {
        nonce: String,
    },
    Leave {
        session_id: String,
        participant_id: String,
    },
}

impl ClientFrame {
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Hello {
                participant,
                session_id,
                capabilities,
                resume,
            } => {
                participant.validate()?;
                validate_token(session_id, "session_id", MAX_ID_BYTES)?;
                validate_capabilities(capabilities)?;
                if let Some(resume) = resume {
                    resume.validate()?;
                }
                Ok(())
            }
            Self::Publish { event } => event.validate(),
            Self::Ack {
                session_id,
                through_seq,
            } => {
                validate_token(session_id, "session_id", MAX_ID_BYTES)?;
                validate_sequence(*through_seq, false)
            }
            Self::Ping { nonce } => validate_token(nonce, "ping nonce", MAX_ID_BYTES),
            Self::Leave {
                session_id,
                participant_id,
            } => {
                validate_token(session_id, "session_id", MAX_ID_BYTES)?;
                validate_token(participant_id, "participant_id", MAX_ID_BYTES)
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    Welcome {
        session: LiveSession,
        replay_from_seq: u64,
    },
    Event {
        event: LiveEnvelope,
    },
    Accepted {
        client_event_id: String,
        event_id: String,
        seq: u64,
        #[serde(default)]
        replayed: bool,
    },
    Lagged {
        session_id: String,
        expected_after_seq: u64,
        high_water_seq: u64,
        recovery_uri: String,
    },
    Pong {
        nonce: String,
        at: Timestamp,
    },
    Error {
        code: String,
        message: String,
        #[serde(default)]
        retryable: bool,
    },
}

impl ServerFrame {
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Welcome {
                session,
                replay_from_seq,
            } => {
                session.validate()?;
                validate_sequence(*replay_from_seq, true)
            }
            Self::Event { event } => event.validate(),
            Self::Accepted {
                client_event_id,
                event_id,
                seq,
                ..
            } => {
                validate_token(client_event_id, "client_event_id", MAX_ID_BYTES)?;
                validate_token(event_id, "event_id", MAX_ID_BYTES)?;
                validate_sequence(*seq, false)
            }
            Self::Lagged {
                session_id,
                expected_after_seq,
                high_water_seq,
                recovery_uri,
            } => {
                validate_token(session_id, "session_id", MAX_ID_BYTES)?;
                validate_sequence(*expected_after_seq, true)?;
                validate_sequence(*high_water_seq, true)?;
                if expected_after_seq > high_water_seq {
                    return Err(ValidationError::new(
                        "lag recovery cursor exceeds the high-water sequence",
                    ));
                }
                validate_text(recovery_uri, "recovery_uri", 2_048)
            }
            Self::Pong { nonce, at } => {
                validate_token(nonce, "pong nonce", MAX_ID_BYTES)?;
                validate_timestamp(at, "pong timestamp")
            }
            Self::Error { code, message, .. } => {
                validate_namespaced_identifier(code, "error code")?;
                validate_text(message, "error message", 16_384)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationError {
    message: String,
}

impl ValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ValidationError {}

fn validate_evidence(evidence: &[EvidenceRef]) -> Result<(), ValidationError> {
    if evidence.len() > MAX_EVIDENCE_REFS {
        return Err(ValidationError::new("too many evidence references"));
    }
    for reference in evidence {
        reference.validate()?;
    }
    Ok(())
}

fn validate_recipients(recipients: &[String]) -> Result<(), ValidationError> {
    if recipients.len() > MAX_RECIPIENTS {
        return Err(ValidationError::new("too many event recipients"));
    }
    let mut seen = BTreeSet::new();
    for recipient in recipients {
        validate_token(recipient, "recipient", MAX_ID_BYTES)?;
        if !seen.insert(recipient.as_str()) {
            return Err(ValidationError::new("duplicate event recipient"));
        }
    }
    Ok(())
}

fn validate_capabilities(capabilities: &[String]) -> Result<(), ValidationError> {
    if capabilities.len() > MAX_CAPABILITIES {
        return Err(ValidationError::new("too many capabilities"));
    }
    let mut previous: Option<&str> = None;
    for capability in capabilities {
        validate_namespaced_identifier(capability, "capability")?;
        if previous.is_some_and(|value| value >= capability.as_str()) {
            return Err(ValidationError::new(
                "capabilities must be sorted and unique",
            ));
        }
        previous = Some(capability);
    }
    Ok(())
}

fn validate_extensions(extensions: &BTreeMap<String, Value>) -> Result<(), ValidationError> {
    if extensions.len() > MAX_EXTENSIONS {
        return Err(ValidationError::new("too many extensions"));
    }
    for (name, value) in extensions {
        validate_namespaced_identifier(name, "extension")?;
        let bytes = serde_json::to_vec(value)
            .map_err(|_| ValidationError::new("extension is not serializable"))?;
        if bytes.len() > MAX_EXTENSION_BYTES {
            return Err(ValidationError::new("extension value is too large"));
        }
    }
    Ok(())
}

fn validate_json(value: &Value, field: &str) -> Result<(), ValidationError> {
    let size = serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX);
    if size > MAX_JSON_BYTES {
        return Err(ValidationError::new(format!(
            "{field} exceeds {MAX_JSON_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_sequence(value: u64, allow_zero: bool) -> Result<(), ValidationError> {
    if (!allow_zero && value == 0) || value > MAX_SAFE_SEQUENCE {
        return Err(ValidationError::new(
            "sequence must be a JSON-safe integer in the permitted range",
        ));
    }
    Ok(())
}

fn validate_timestamp(value: &str, field: &str) -> Result<(), ValidationError> {
    validate_text(value, field, 64)?;
    if !value.contains('T') || !value.ends_with('Z') {
        return Err(ValidationError::new(format!(
            "{field} must be an RFC 3339 UTC timestamp"
        )));
    }
    Ok(())
}

fn validate_idempotency_key(value: &str) -> Result<(), ValidationError> {
    if value.len() < MIN_IDEMPOTENCY_BYTES || value.len() > MAX_IDEMPOTENCY_BYTES {
        return Err(ValidationError::new(format!(
            "idempotency_key must contain {MIN_IDEMPOTENCY_BYTES} to {MAX_IDEMPOTENCY_BYTES} bytes"
        )));
    }
    if !value.bytes().all(is_token_byte) {
        return Err(ValidationError::new(
            "idempotency_key contains unsupported characters",
        ));
    }
    Ok(())
}

fn validate_namespaced_identifier(value: &str, field: &str) -> Result<(), ValidationError> {
    validate_token(value, field, MAX_ID_BYTES)?;
    if !value.contains('.') {
        return Err(ValidationError::new(format!(
            "{field} must use a namespace"
        )));
    }
    Ok(())
}

fn validate_optional_token(
    value: &Option<String>,
    field: &str,
    max_bytes: usize,
) -> Result<(), ValidationError> {
    if let Some(value) = value {
        validate_token(value, field, max_bytes)?;
    }
    Ok(())
}

fn validate_token(value: &str, field: &str, max_bytes: usize) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > max_bytes {
        return Err(ValidationError::new(format!(
            "{field} must contain 1 to {max_bytes} bytes"
        )));
    }
    if !value.bytes().all(is_token_byte) {
        return Err(ValidationError::new(format!(
            "{field} contains unsupported characters"
        )));
    }
    Ok(())
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-_.:/@+".contains(&byte)
}

fn validate_text(value: &str, field: &str, max_bytes: usize) -> Result<(), ValidationError> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(ValidationError::new(format!(
            "{field} must contain 1 to {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn validate_optional_text(
    value: &str,
    field: &str,
    max_bytes: usize,
) -> Result<(), ValidationError> {
    if value.len() > max_bytes {
        return Err(ValidationError::new(format!(
            "{field} exceeds {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn validate_optional_shareable_text(
    value: &Option<String>,
    field: &str,
) -> Result<(), ValidationError> {
    if let Some(value) = value {
        validate_text(value, field, 16_384)?;
    }
    Ok(())
}

fn validate_https_url(value: &str, field: &str) -> Result<(), ValidationError> {
    validate_text(value, field, 2_048)?;
    if !value.starts_with("https://") || value.contains('@') {
        return Err(ValidationError::new(format!(
            "{field} must be an HTTPS URL without user information"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn participant(id: &str, provider: &str, model: &str) -> Participant {
        Participant {
            identity: ProviderIdentity {
                participant_id: id.to_string(),
                provider: provider.to_string(),
                model: model.to_string(),
                runtime: Some(format!("{provider}-worker")),
                instance_id: None,
            },
            display_name: id.to_string(),
            role: ParticipantRole::Member,
            capabilities: vec!["agent.chat".to_string(), "agent.review".to_string()],
            joined_at: "2026-09-01T16:00:00Z".to_string(),
        }
    }

    #[test]
    fn chatgpt_claude_and_grok_share_one_valid_session() {
        let session = LiveSession {
            schema_version: LIVE_SCHEMA_VERSION,
            protocol: LIVE_PROTOCOL_ID.to_string(),
            session_id: "session-pmap-intake".to_string(),
            channel: "workflow-pmap-intake".to_string(),
            title: "Review PMAP intake rollout".to_string(),
            state: SessionState::Active,
            created_by: "chatgpt".to_string(),
            created_at: "2026-09-01T16:00:00Z".to_string(),
            participants: vec![
                participant("chatgpt", "openai", "gpt"),
                participant("claude", "anthropic", "claude"),
                participant("grok", "xai", "grok"),
            ],
            tracker_links: vec![TrackerLink {
                kind: "linear.issue".to_string(),
                reference: "DEN-1873".to_string(),
                url: "https://linear.app/example/issue/DEN-1873".to_string(),
                relation: Some("tracks".to_string()),
            }],
            high_water_seq: 0,
            extensions: BTreeMap::new(),
        };
        session.validate().unwrap();

        let encoded = serde_json::to_value(&session).unwrap();
        let decoded: LiveSession = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, session);
    }

    #[test]
    fn publish_and_accepted_frames_encode_replay_identity() {
        let publish = ClientFrame::Publish {
            event: PublishEvent {
                client_event_id: "client-event-0001".to_string(),
                session_id: "session-pmap-intake".to_string(),
                channel: "workflow-pmap-intake".to_string(),
                sender: "claude".to_string(),
                recipients: vec!["chatgpt".to_string(), "grok".to_string()],
                correlation_id: Some("review-round-1".to_string()),
                causation_id: None,
                idempotency_key: "claude-review-round-0001".to_string(),
                payload: LivePayload::Proposal {
                    proposal_id: "proposal-0001".to_string(),
                    summary: "Keep Cloudflare activation disabled until TLS and canaries pass."
                        .to_string(),
                    details: None,
                },
                extensions: BTreeMap::new(),
            },
        };
        publish.validate().unwrap();

        let accepted = ServerFrame::Accepted {
            client_event_id: "client-event-0001".to_string(),
            event_id: "event-0000000001".to_string(),
            seq: 1,
            replayed: true,
        };
        accepted.validate().unwrap();
        let value = serde_json::to_value(accepted).unwrap();
        assert_eq!(value["type"], "accepted");
        assert_eq!(value["replayed"], true);
    }

    #[test]
    fn tool_intent_does_not_become_write_authority() {
        let request = LivePayload::ToolRequest {
            request_id: "tool-request-0001".to_string(),
            tool: "github.pull-request".to_string(),
            action: "merge".to_string(),
            capability: "github.pull-request.merge".to_string(),
            arguments: json!({"repository":"agent-pontifex/agent-sdk.rs","number":12}),
            requires_approval: true,
        };
        request.validate().unwrap();

        let invalid_approval = LivePayload::ApprovalRequest {
            approval_id: "approval-0001".to_string(),
            subject: "Merge pull request 12".to_string(),
            requested_capabilities: Vec::new(),
            expires_at: "2026-09-01T17:00:00Z".to_string(),
        };
        assert!(invalid_approval.validate().is_err());
    }

    #[test]
    fn validation_rejects_duplicate_recipients_and_unsafe_sequences() {
        let mut event = PublishEvent {
            client_event_id: "client-event-0002".to_string(),
            session_id: "session-pmap-intake".to_string(),
            channel: "workflow-pmap-intake".to_string(),
            sender: "grok".to_string(),
            recipients: vec!["claude".to_string(), "claude".to_string()],
            correlation_id: None,
            causation_id: None,
            idempotency_key: "grok-review-round-0002".to_string(),
            payload: LivePayload::Message {
                content: "Review complete.".to_string(),
                content_type: "text/plain".to_string(),
            },
            extensions: BTreeMap::new(),
        };
        assert!(event.validate().is_err());
        event.recipients.pop();
        event.validate().unwrap();

        let envelope = LiveEnvelope {
            schema_version: LIVE_SCHEMA_VERSION,
            protocol: LIVE_PROTOCOL_ID.to_string(),
            event_id: "event-unsafe".to_string(),
            session_id: event.session_id.clone(),
            channel: event.channel.clone(),
            seq: MAX_SAFE_SEQUENCE + 1,
            sender: event.sender.clone(),
            recipients: event.recipients.clone(),
            correlation_id: None,
            causation_id: None,
            idempotency_key: event.idempotency_key.clone(),
            created_at: "2026-09-01T16:05:00Z".to_string(),
            payload: event.payload,
            extensions: BTreeMap::new(),
        };
        assert!(envelope.validate().is_err());
    }

    #[test]
    fn conformance_fixtures_validate_and_omit_hidden_reasoning_fields() {
        let session: LiveSession =
            serde_json::from_str(include_str!("../../conformance/live-session-session.json"))
                .unwrap();
        session.validate().unwrap();

        let envelope: LiveEnvelope =
            serde_json::from_str(include_str!("../../conformance/live-session-envelope.json"))
                .unwrap();
        envelope.validate().unwrap();

        let encoded = serde_json::to_string(&envelope).unwrap();
        for forbidden in ["chain_of_thought", "hidden_reasoning", "reasoning_tokens"] {
            assert!(!encoded.contains(forbidden));
        }
    }
}
