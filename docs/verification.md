# Formal Verification

The `verification/` directory contains a Scyther model (`uwc_protocol.spdl`)
of the 4-hop, 12-message NSL-style authentication exchange described in
`docs/protocol.md`. Scyther is used to check standard authentication
properties (e.g. Niagree/Nisynch, aliveness, secrecy of the exchanged
nonces) for the message-flow logic **independent of** the concrete PEECC
implementation used in this codebase.

## Running

On Windows, with Scyther installed and on your `PATH`:

```
cd verification
run_scyther.bat
```

On Linux/macOS, run Scyther directly against the model:

```
scyther-cli verification/uwc_protocol.spdl
```

See `verification/README.md` for details on the four role definitions
(`UWS`, `SUB`, `BUOY`, `SAT`, `BS`) and how they map onto
`uwcn.protocol.authentication.run_ns_authentication`.

## Mapping from code to model

| Scyther role pair   | Messages         | Code                                             |
|----------------------|------------------|---------------------------------------------------|
| `UWS`, `SUB`         | M1, M2, M3       | `authenticate_hop(hop=1, initiator="U1", responder="S1")` |
| `SUB`, `BUOY`        | M4, M5, M6       | `authenticate_hop(hop=2, initiator="S1", responder=buoy)` |
| `BUOY`, `SAT`        | M7, M8, M9       | `authenticate_hop(hop=3, initiator=buoy, responder=satellite)` |
| `SAT`, `BS`          | M10, M11, M12    | `authenticate_hop(hop=4, initiator=satellite, responder="BS")` |
