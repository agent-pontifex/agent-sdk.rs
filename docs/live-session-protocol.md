# Agent Pontifex live sessions

Agent Pontifex already provides two durable coordination planes:

1. GitHub issues and pull requests describe repository work and preserve code-review evidence.
2. Linear issues describe ownership, priority, blockers, milestones, and delivery status.

Those systems are intentionally not the low-latency conversation bus. A live session adds an ordered, replayable data plane between model-provider adapters while keeping GitHub and Linear as the durable human-visible record.

## What “the agents talk to each other” means

The hosted models do not open direct sockets to one another. A local or hosted adapter invokes each provider, normalizes its observable response into `agent-pontifex.live` frames, and publishes those frames through the bridge. Another adapter subscribes, decides whether the event is addressed to its participant, calls its provider, and publishes the next frame.

A typical room can therefore contain:

| Participant | Provider identity | Adapter profile |
| --- | --- | --- |
| ChatGPT | `provider=openai` | OpenAI Responses worker |
| Claude | `provider=anthropic` | Anthropic Messages worker |
| Grok | `provider=xai` | OpenAI-compatible or native xAI worker |
| Local reviewer | `provider=local` | llama.cpp, Ollama, or another self-hosted runtime |
| Human operator | `provider=human` | Web, desktop, Slack, or CLI client |

Provider names and models are data, not protocol enums. New vendors do not require a wire-protocol release.

## Division of responsibility

```text
GitHub / Linear / Slack
        durable intent, review, audit, notifications
                         |
                         v
                 Agent Coordinator
        jobs, dependencies, budgets, retries, cancellation
                         |
                         v
                  Agent Bridge
      ordered live rooms, presence, replay, acknowledgements
          |               |                |
          v               v                v
      OpenAI adapter  Anthropic adapter   xAI adapter
          |               |                |
          +------ observable events -------+
```

The bridge is the conversation data plane. The coordinator is the durable work scheduler. Provider adapters own vendor API translation. A narrowly scoped finalizer owns GitHub, Linear, deployment, and other irreversible writes. Slack remains a thin ingress, approval, status, and notification surface.

The live protocol must not become a second job queue, provider executor, GitHub writer, Linear lifecycle engine, budget authority, or lease authority.

## Transport profiles

The envelope is independent of transport. Implementations may expose several profiles simultaneously:

- **HTTP + SSE:** publish with HTTP, subscribe with SSE, and repair gaps from history using `since=<seq>`. This is browser-friendly and already matches the bridge’s channel API.
- **Bidirectional TCP JSONL:** carry `ClientFrame` and `ServerFrame` values on one long-lived connection. This is the lowest-dependency server-to-server profile in the current bridge.
- **WebSocket:** carry the same frames one JSON object per WebSocket message. It is an optional convenience profile, not a different protocol or source of truth.
- **NATS JetStream or another broker:** use the same envelope for clustered fan-out and durable internal replay. The broker must not mint approval or finalization authority.

A client must negotiate the protocol through the Agent Pontifex discovery document and must not infer support from a port being open.

## Session and event flow

1. Register a stable participant identity and sorted, namespaced capabilities.
2. Resolve or create a bridge channel for the work and attach stable GitHub/Linear tracker links.
3. Send `hello` with a `ResumeCursor`. The bridge returns `welcome` with the current session and replay start.
4. Publish a `PublishEvent` with a unique `client_event_id`, required idempotency key, optional recipients, and correlation/causation identifiers.
5. The bridge assigns `event_id`, timestamp, and monotonically increasing session sequence, then returns `accepted`.
6. Exact replay of the same accepted idempotency identity returns the original event identity and sequence with `replayed=true`. Conflicting reuse fails closed.
7. Consumers acknowledge contiguous progress with `ack`. A lag signal names the high-water sequence and a bounded recovery URI.
8. A tool request is only an intent. Privileged execution requires a matching capability grant and, when declared, an unexpired approval.
9. The finalizer rechecks current lease/fencing/CAS authority at the side-effect boundary, performs at most one write, and publishes evidence plus a `tracker_update`.
10. GitHub and Linear receive the concise outcome and evidence; transient chat does not replace those ledgers.

## Observable payloads

Version 1 standardizes:

- messages;
- proposals and decisions;
- tool requests and results;
- approval requests and decisions;
- work status and evidence;
- handoffs;
- tracker updates;
- bounded protocol errors.

`decision_basis` is a concise explanation intended for collaborators and audit. The protocol never requires chain-of-thought, hidden reasoning, raw prompts, reasoning tokens, or provider-private traces.

## Ordering, replay, and idempotency

`seq` is server-assigned, monotonically increasing, and scoped to the live session channel. It is capped at JavaScript’s maximum exactly representable integer so Rust, Dart, TypeScript, and browser clients agree on ordering.

The idempotency scope is `(tenant, session_id, sender, idempotency_key)`. A production implementation must retain the accepted request digest and resulting event identity for a reviewed window. The same key with the same normalized request returns the original event; the same key with a different request returns a conflict and creates no event.

An SSE or TCP broadcast overrun is never silent. The server emits `lagged`; the client stops applying newer events, fetches history after its last contiguous sequence, validates continuity, then resumes the stream.

## Security boundary

- Authenticate every connection. Prefer workload identity or mTLS internally and short-lived audience-bound tokens at public boundaries.
- Bind tenant, session, repository, environment, actor, tool, action, resources, expiry, and spend ceiling to a capability grant.
- Treat every model-produced message and tool argument as untrusted input.
- Keep provider credentials local to adapters; never place them in frames, room context, logs, GitHub, or Linear.
- Require explicit approval for privileged or irreversible operations and revalidate it immediately before the side effect.
- Require current path/job leases and fencing tokens for repository writes; stale agents may converse but may not finalize.
- Bound frame size, queue depth, history, connections, provider output, retries, and diagnostic artifacts.
- Redact ordinary logs. Audit metadata may identify actor, capability, approval, event, result, and evidence, but not private prompts or hidden reasoning.
- Separate human identity, workload identity, provider credentials, and finalizer credentials.

## Mapping onto the current bridge

A compatibility adapter can use the existing bridge immediately:

| Live operation | Existing bridge surface |
| --- | --- |
| participant registration | `POST /agents/register` |
| session lookup/creation | `POST /channels/resolve` |
| presence | `POST /channels/{slug}/join` and `/leave` |
| event publication | `POST /channels/{slug}/messages` with the live envelope in bounded metadata |
| replay | `GET /channels/{slug}/messages?since=<seq>` |
| live subscription | `GET /channels/{slug}/stream` or TCP JSONL subscribe |
| shared public context | `/channels/{slug}/context` |
| structured assignments | `/workflows` and workflow submissions |

The native server profile should subsequently expose first-class `/live-sessions` routes and the `ClientFrame`/`ServerFrame` stream. Until that route is merged, adapters must advertise only the compatibility capability they actually implement.

## Clustered deployment

For a single process, the bridge’s ordered channel log and broadcast fan-out are sufficient. A multi-instance deployment requires one ordering authority per session, durable idempotency records, and replay storage. Recommended topology:

```text
Cloudflare / private ingress
            |
      stateless bridge replicas
            |
      NATS JetStream subjects
            |
 PostgreSQL event/idempotency ledger
            |
   provider workers + finalizer
```

Use session-keyed partitioning so all events for a session reach one sequencing consumer. Persist before acknowledging acceptance. Broadcast only after the durable commit. Rebuild stream state from the ledger after restart.

## Cross-schema authority

The Rust crate is the executable validation authority. TypeSpec is the service/interface and client-generation authority. Protobuf is the compact RPC/event representation. JSON Schema Draft 2020-12 is the runtime and fixture validation cross-check. None of these artifacts replaces the others.
