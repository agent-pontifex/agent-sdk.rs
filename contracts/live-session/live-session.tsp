import "@typespec/json-schema";

using TypeSpec.JsonSchema;

/**
 * Agent Pontifex Live Session v1.
 *
 * This contract contains only externally observable collaboration records. It
 * never asks a model or adapter to disclose hidden chain-of-thought.
 *
 * Wire property names are snake_case. Declaration names are PascalCase; they
 * are not wire names. contracts/live-session/tjsv-declaration-mapping.json
 * pairs each declaration with its snake_case JSON Schema `$defs` peer.
 */
namespace AgentPontifex.Live.V1;

/** Opaque identifier restricted to URL- and log-safe ASCII. */
@minLength(1)
@maxLength(256)
@pattern("^[A-Za-z0-9_.:/@+\\-]+$")
scalar Token extends string;

/** Token bounded to 128 bytes: provider namespaces, content types, relations. */
@minLength(1)
@maxLength(128)
@pattern("^[A-Za-z0-9_.:/@+\\-]+$")
scalar ShortToken extends string;

/** Namespaced identifier such as `agent.review`, `github.commit`, or `bridge.lagged`. */
@minLength(3)
@maxLength(256)
@pattern("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_.:/@+\\-]+$")
scalar NamespacedIdentifier extends string;

/** RFC 3339 UTC timestamp. */
@minLength(1)
@maxLength(64)
@format("date-time")
@pattern("Z$")
scalar Timestamp extends string;

@minLength(16)
@maxLength(128)
@pattern("^[A-Za-z0-9_.:/@+\\-]+$")
scalar IdempotencyKey extends string;

/** JSON-safe sequence cursor; zero means "before the first event". */
@minValue(0)
@maxValue(9007199254740991)
scalar Sequence extends safeint;

/** Server-assigned event position; the first event is 1. */
@minValue(1)
@maxValue(9007199254740991)
scalar PositiveSequence extends safeint;

@minLength(1)
@maxLength(1048576)
scalar BoundedText extends string;

/** Concise, externally shareable text. */
@minLength(1)
@maxLength(16384)
scalar ShareableText extends string;

/** Sorted, unique, namespaced capabilities. Sort order is enforced by the Rust validator. */
@maxItems(256)
@uniqueItems
model Capabilities is NamespacedIdentifier[];

/** Namespaced extension members, for example `vendor.feature`. */
@maxProperties(64)
@extension("propertyNames", #{ type: "string", pattern: "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_.-]+$" })
model Extensions is Record<unknown>;

enum ParticipantRole {
  moderator,
  finalizer,
  observer,
  member,
}

enum SessionState {
  active,
  closing,
  closed,
}

enum DecisionOutcome {
  accepted,
  rejected,
  deferred,
  superseded,
}

enum ToolOutcome {
  succeeded,
  failed,
  denied,
  cancelled,
}

enum ApprovalOutcome {
  approved,
  denied,
  expired,
  revoked,
}

enum WorkState {
  planned,
  claimed,
  running,
  blocked,
  awaiting_review,
  completed,
  failed,
  cancelled,
}

model ProviderIdentity {
  participant_id: Token;
  provider: ShortToken;
  `model`: Token;
  runtime?: Token;
  instance_id?: Token;
}

model Participant {
  identity: ProviderIdentity;
  @maxLength(512) display_name?: string;
  role?: ParticipantRole;
  capabilities?: Capabilities;
  joined_at: Timestamp;
}

model TrackerLink {
  kind: NamespacedIdentifier;
  @minLength(1) @maxLength(256) reference: string;
  @minLength(9) @maxLength(2048) @pattern("^https://[^@]+$") url: string;
  relation?: ShortToken;
}

model EvidenceRef {
  kind: NamespacedIdentifier;
  @minLength(1) @maxLength(2048) uri: string;
  digest?: Token;
  @minLength(1) @maxLength(4096) summary?: string;
}

model LiveSession {
  schema_version: 1;
  protocol: "agent-pontifex.live";
  session_id: Token;
  channel: Token;
  @minLength(1) @maxLength(1024) title: string;
  state: SessionState;
  created_by: Token;
  created_at: Timestamp;
  @minItems(1) @maxItems(64) participants: Participant[];
  @maxItems(64) tracker_links?: TrackerLink[];
  high_water_seq?: Sequence;
  extensions?: Extensions;
}

model MessagePayload {
  kind: "message";
  content: BoundedText;
  content_type?: ShortToken;
}

model ProposalPayload {
  kind: "proposal";
  proposal_id: Token;
  summary: ShareableText;
  details?: BoundedText;
}

model DecisionPayload {
  kind: "decision";
  proposal_id: Token;
  outcome: DecisionOutcome;
  /** Concise, externally shareable basis; never hidden reasoning. */
  decision_basis?: ShareableText;
}

model ToolRequestPayload {
  kind: "tool_request";
  request_id: Token;
  tool: NamespacedIdentifier;
  action: Token;
  capability: NamespacedIdentifier;
  arguments?: unknown;
  requires_approval?: boolean;
}

model ToolResultPayload {
  kind: "tool_result";
  request_id: Token;
  outcome: ToolOutcome;
  result?: unknown;
  error?: ShareableText;
  @maxItems(128) evidence?: EvidenceRef[];
}

model ApprovalRequestPayload {
  kind: "approval_request";
  approval_id: Token;
  subject: ShareableText;
  @minItems(1) requested_capabilities: Capabilities;
  expires_at: Timestamp;
}

model ApprovalDecisionPayload {
  kind: "approval_decision";
  approval_id: Token;
  outcome: ApprovalOutcome;
  decided_by: Token;
  decision_basis?: ShareableText;
}

model WorkStatusPayload {
  kind: "work_status";
  work_id: Token;
  state: WorkState;
  summary: ShareableText;
  /** Progress in basis points, from 0 through 10,000. */
  @maxValue(10000) progress_bps?: uint16;
  @maxItems(128) evidence?: EvidenceRef[];
}

model HandoffPayload {
  kind: "handoff";
  work_id: Token;
  to: Token;
  summary: ShareableText;
  @maxItems(128) @uniqueItems context_refs?: Token[];
}

model TrackerUpdatePayload {
  kind: "tracker_update";
  link: TrackerLink;
  summary: ShareableText;
}

model ErrorPayload {
  kind: "error";
  code: NamespacedIdentifier;
  message: ShareableText;
  retryable?: boolean;
}

/** Payload variants are mutually exclusive, discriminated by the `kind` constant. */
@oneOf
union LivePayload {
  MessagePayload,
  ProposalPayload,
  DecisionPayload,
  ToolRequestPayload,
  ToolResultPayload,
  ApprovalRequestPayload,
  ApprovalDecisionPayload,
  WorkStatusPayload,
  HandoffPayload,
  TrackerUpdatePayload,
  ErrorPayload,
}

model PublishEvent {
  client_event_id: Token;
  session_id: Token;
  channel: Token;
  sender: Token;
  @maxItems(64) @uniqueItems recipients?: Token[];
  correlation_id?: Token;
  causation_id?: Token;
  idempotency_key: IdempotencyKey;
  payload: LivePayload;
  extensions?: Extensions;
}

model LiveEnvelope {
  schema_version: 1;
  protocol: "agent-pontifex.live";
  event_id: Token;
  session_id: Token;
  channel: Token;
  seq: PositiveSequence;
  sender: Token;
  @maxItems(64) @uniqueItems recipients?: Token[];
  correlation_id?: Token;
  causation_id?: Token;
  idempotency_key: IdempotencyKey;
  created_at: Timestamp;
  payload: LivePayload;
  extensions?: Extensions;
}

model ResumeCursor {
  after_seq?: Sequence;
  last_event_id?: Token;
}

model HelloFrame {
  type: "hello";
  participant: ProviderIdentity;
  session_id: Token;
  capabilities?: Capabilities;
  resume?: ResumeCursor;
}

model PublishFrame {
  type: "publish";
  event: PublishEvent;
}

model AckFrame {
  type: "ack";
  session_id: Token;
  through_seq: PositiveSequence;
}

model PingFrame {
  type: "ping";
  nonce: Token;
}

model LeaveFrame {
  type: "leave";
  session_id: Token;
  participant_id: Token;
}

/** Client frames are mutually exclusive, discriminated by the `type` constant. */
@oneOf
union ClientFrame {
  HelloFrame,
  PublishFrame,
  AckFrame,
  PingFrame,
  LeaveFrame,
}

model WelcomeFrame {
  type: "welcome";
  session: LiveSession;
  replay_from_seq: Sequence;
}

model EventFrame {
  type: "event";
  event: LiveEnvelope;
}

model AcceptedFrame {
  type: "accepted";
  client_event_id: Token;
  event_id: Token;
  seq: PositiveSequence;
  replayed?: boolean;
}

model LaggedFrame {
  type: "lagged";
  session_id: Token;
  expected_after_seq: Sequence;
  high_water_seq: Sequence;
  @minLength(1) @maxLength(2048) recovery_uri: string;
}

model PongFrame {
  type: "pong";
  nonce: Token;
  at: Timestamp;
}

model ServerErrorFrame {
  type: "error";
  code: NamespacedIdentifier;
  message: ShareableText;
  retryable?: boolean;
}

/** Server frames are mutually exclusive, discriminated by the `type` constant. */
@oneOf
union ServerFrame {
  WelcomeFrame,
  EventFrame,
  AcceptedFrame,
  LaggedFrame,
  PongFrame,
  ServerErrorFrame,
}

/**
 * Logical transport operation projected into the gRPC service. The streaming
 * mode is transport-specific metadata in grpc-projection.json; the peer
 * authorities continue to own the ClientFrame and ServerFrame shapes.
 */
interface LiveSessionTransport {
  connect(frame: ClientFrame): ServerFrame;
}
