# Agent Pontifex discovery conformance profiles

These fixtures define the portable discovery boundary shared by the public Agent
Pontifex bridge/coordinator and downstream implementations such as Fiducia.

The community profiles advertise only vendor-neutral capabilities. Fiducia
profiles implement the same service and protocol identities, then declare
stronger authority, persistence, review, and fencing behavior through `fiducia.*`
extensions. Credentials, tenant identifiers, mutable runtime state, and deployment
secrets must never appear in a discovery document.

The integration test in `agent-pontifex-protocol/tests/discovery_conformance.rs`
loads every fixture through the public protocol crate, negotiates protocol major
version 1, verifies deterministic capability ordering, enforces vendor namespaces,
and recursively rejects credential-shaped metadata.

Servers may advertise a subset or superset of these optional capabilities, but
must not reinterpret an existing capability or weaken the portable contract.
Breaking field or semantic changes require a new protocol major version.
