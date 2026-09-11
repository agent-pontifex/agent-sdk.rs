# Live-session contract artifacts

- `live-session.tsp` — independently authored TypeSpec peer authority for observable collaboration shapes and logical operations.
- `live-session.schema.json` — independently authored JSON Schema Draft 2020-12 peer authority and runtime fixture validator.
- `live-session.proto` — downstream Protobuf/gRPC projection with an append-only compatibility lock.
- `grpc-projection.json` — reviewed transport metadata mapping the TypeSpec operation to duplex gRPC.
- `protobuf.lock.json` — stable critical envelope field numbers and gRPC method identity.
- `../../generated/live-session/grpc-manifest.json` — Git-object provenance for the generated service block.

Run:

```sh
python3 scripts/check-live-contracts.py
python3 scripts/generate-live-grpc.py --check
```

To intentionally regenerate the service block and manifest after reviewing both
authorities and the projection metadata:

```sh
python3 scripts/generate-live-grpc.py --write
```

Successful Protobuf decoding is not authorization and does not replace the
shared semantic validator. Every representation describes externally observable
collaboration only; none contains a field for hidden chain-of-thought.
