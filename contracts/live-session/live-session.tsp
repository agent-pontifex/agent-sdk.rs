/**
 * Agent Pontifex Live Session v1.
 *
 * This contract contains only externally observable collaboration records. It
 * never asks a model or adapter to disclose hidden chain-of-thought.
 */
namespace AgentPontifex.Live.V1;

alias Timestamp = string;
alias JsonValue = unknown;
alias Extensions = Record<JsonValue>;

@minLength(1)
@maxLength(256)
@pattern("^[A-Za-z0-9_.:/@+\\-]+$")
scalar Token extends string;

@minLength(16)
@maxLength(128)
@pattern("^[A-Za-z0-9_.:/@+\\-]+$")
scalar IdempotencyKey extends string;

@minValue(0)
@maxValue(9007199254740991)
scalar Sequence extends safeint;

@minLength(1)
@maxLength(1048576)
scalar BoundedText extends string;

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
  provider: Token;
  model: Token;
  runtime?: Token;
  instance_id?: Token;
}

model Participant {
  identity: ProviderIdentity;
  display_name?: string;
  role?: ParticipantRole;
  capabilities?: Token[];
  joined_at: Timestamp;
}

model TrackerLink {
  kind: Token;
  reference: string;
  url: string;
  relation?: Token;
}

model EvidenceRef {
  kind: Token;
  uri: string;
  digest?: Token;
  summary?: string;
}

model LiveSession {
  schema_version: 1;
  protocol: "agent-pontifex.live";
  session_id: Token;
  channel: Token;
  title: string;
  state: SessionState;
  created_by: Token;
  created_at: Timestamp;
  participants: Participant[];
  tracker_links?: TrackerLink[];
  high_water_seq?: Sequence;
  extensions?: Extensions;
}

model MessagePayload {
  kind: "message";
  content: BoundedText;
  content_type?: Token;
}

model ProposalPayload {
  kind: "proposal";
  proposal_id: Token;
  summary: string;
  details?: BoundedText;
}

model DecisionPayload {
  kind: "decision";
  proposal_id: Token;
  outcome: DecisionOutcome;
  /** Concise, externally shareable basis; never hidden reasoning. */
  decision_basis?: string;
}

model ToolRequestPayload {
  kind: "tool_request";
  request_id: Token;
  tool: Token;
  action: Token;
  capability: Token;
  arguments?: JsonValue;
  requires_approval?: boolean;
}

model ToolResultPayload {
  kind: "tool_result";
  request_id: Token;
  outcome: ToolOutcome;
  result?: JsonValue;
  error?: string;
  evidence?: EvidenceRef[];
}

model ApprovalRequestPayload {
  kind: "approval_request";
  approval_id: Token;
  subject: string;
  requested_capabilities: Token[];
  expires_at: Timestamp;
}

model ApprovalDecisionPayload {
  kind: "approval_decision";
  approval_id: Token;
  outcome: ApprovalOutcome;
  decided_by: Token;
  decision_basis?: string;
}

model WorkStatusPayload {
  kind: "work_status";
  work_id: Token;
  state: WorkState;
  summary: string;
  progress_bps?: uint16;
  evidence?: EvidenceRef[];
}

model HandoffPayload {
  kind: "handoff";
  work_id: Token;
  to: Token;
  summary: string;
  context_refs?: Token[];
}

model TrackerUpdatePayload {
  kind: "tracker_update";
  link: TrackerLink;
  summary: string;
}

model ErrorPayload {
  kind: "error";
  code: Token;
  message: string;
  retryable?: boolean;
}

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
  recipients?: Token[];
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
  seq: Sequence;
  sender: Token;
  recipients?: Token[];
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
  capabilities?: Token[];
  resume?: ResumeCursor;
}

model PublishFrame {
  type: "publish";
  event: PublishEvent;
}

model AckFrame {
  type: "ack";
  session_id: Token;
  through_seq: Sequence;
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
  seq: Sequence;
  replayed?: boolean;
}

model LaggedFrame {
  type: "lagged";
  session_id: Token;
  expected_after_seq: Sequence;
  high_water_seq: Sequence;
  recovery_uri: string;
}

model PongFrame {
  type: "pong";
  nonce: Token;
  at: Timestamp;
}

model ServerErrorFrame {
  type: "error";
  code: Token;
  message: string;
  retryable?: boolean;
}

union ServerFrame {
  WelcomeFrame,
  EventFrame,
  AcceptedFrame,
  LaggedFrame,
  PongFrame,
  ServerErrorFrame,
}
