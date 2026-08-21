# Agent Pontifex platform interoperability

Agent Pontifex owns the vendor-neutral discovery, bridge, coordinator, and
client wire contracts. Integrations strengthen those contracts at explicit
boundaries; they do not silently redefine them.

## Fiducia Cloud

Fiducia is the distributed authority for repository writes that can race across
workers or coordinator replicas. New lease requests use canonical GitHub
`owner/repository` identity and one atomic, sorted, de-duplicated union of
repository-relative paths. A live grant carries the agent identity, a positive
fencing token no larger than `9007199254740991`, and an exact expiry. Renewal
must present the complete original path union, holder, current token, and a
bounded TTL.

The token is authority, not metadata. Immediately before an irreversible
external mutation, the adapter must prove that its token is still current.
Agent Pontifex transports and validates the portable shape; Fiducia mints,
renews, releases, and checks the authority.

## Shared Auth

Shared Auth establishes human operator identity. Agent workload identity,
product tenant/role policy, and repository-write fencing stay at their owning
service boundaries. A service verifies a Shared Auth JWT locally against a
pinned issuer, exact audience, and trusted JWKS. Protected introspection may be
used when immediate revocation is required, but its service credential is
separate from the inspected caller token.

Raw caller bearer material must be consumed at the outer authentication
boundary. It must not be forwarded to inner handlers, adapters, logs, traces,
or downstream calls. Inner service calls use an independently scoped workload
credential.

## Zed packages

Every publishable repository declares a root `.zpkg.toml`. Zed package identity
uses `organization/name`, the repository URL is exact, and release consumers
resolve an immutable source revision or signed artifact. Editable source
composition may use Git submodules, but a Zed lock and any gitlink for the same
dependency must resolve to the same commit.

## Secrets

Only SOPS ciphertext matching `env/enc/*.env.enc` may be tracked. Decrypted
`env/dec/*.env` files are owner-only, ignored build artifacts and may be
materialized through reviewed `just` recipes, a Nix development environment, or
runtime secret injection. Plaintext is never committed, and encrypted
environment bundles are excluded from published packages and runtime images.

The machine-readable form of this contract is
[`conformance/platform-interop.json`](../conformance/platform-interop.json).
