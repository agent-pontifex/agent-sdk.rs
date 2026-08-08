# Agent Pontifex attestation transport

`agent-pontifex-attestation` defines vendor-neutral, bounded transport and trust-routing contracts for signed worker results.

The crate validates:

- exact subject and revision digests;
- exact policy digests;
- canonical payload hashing;
- role, provider, key, trust-domain, worker, job, and task routing;
- distinct authorities for every required role;
- external public-key metadata;
- bounded payloads and signatures;
- rejection of secret-bearing and hidden-reasoning payload keys.

It deliberately does **not** verify cryptographic signatures, expiration, revocation, coordinator leases, fencing tokens, or current product state. A downstream finalizer must perform those checks with an externally configured trust registry before applying any GitHub, Linear, Cloudflare, storage, or other side effect.

A structurally valid artifact is evidence to inspect, not mutation authority.

```sh
cargo test -p agent-pontifex-attestation
cargo clippy -p agent-pontifex-attestation --all-targets -- -D warnings
cargo doc -p agent-pontifex-attestation --no-deps
```

Related: DEN-1873, DEN-2877, DEN-2823, DEN-2922.
