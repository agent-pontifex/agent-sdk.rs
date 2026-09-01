# Live-session contract artifacts

- `live-session.tsp` — TypeSpec source for service/client generation.
- `live-session.proto` — Protobuf representation for compact RPC and event transports.
- `live-session.schema.json` — JSON Schema Draft 2020-12 runtime and fixture cross-check.

The executable Rust validation authority is `agent-pontifex-live-protocol`.
All four representations describe observable collaboration only; none contains a
field for hidden chain-of-thought.
