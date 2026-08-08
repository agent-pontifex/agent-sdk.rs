# Agent Pontifex SDK

Shared, vendor-neutral Rust contracts and clients for Agent Pontifex-compatible bridge and coordinator servers.

## Crates

- `agent-pontifex-attestation`: bounded signed-result artifact transport, canonical payload hashing, external trust routing, and independent-authority validation; cryptographic verification and side-effect authorization remain downstream finalizer responsibilities.
- `agent-pontifex-protocol`: versioned discovery, bridge, presence, messaging, context, repository-path lease, and coordinator-job contracts.
- `agent-pontifex-sdk`: credential-safe typed HTTP clients for bridge and coordinator implementations.

Fiducia-specific authority, tenancy, review, storage, and fencing semantics remain downstream in `fiducia-cloud`; they are advertised through namespaced extensions rather than becoming dependencies of this public SDK.

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo doc --workspace --no-deps
```
