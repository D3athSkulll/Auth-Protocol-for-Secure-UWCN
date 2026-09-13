# Protocol

The authentication protocol is a 4-hop, 12-message Needham-Schroeder-Lowe
(NSL) style exchange across the deployment path:

```
UWS <-> SUB <-> BUOY <-> SAT <-> BS
```

| Hop | Messages         | Participants     |
|-----|------------------|-------------------|
| 1   | M1, M2, M3       | UWS  <-> SUB       |
| 2   | M4, M5, M6       | SUB  <-> BUOY      |
| 3   | M7, M8, M9       | BUOY <-> SAT       |
| 4   | M10, M11, M12    | SAT  <-> BS        |

Each hop runs the same 3-message pattern:

```
a) initiator -> responder: { tag_a, initiator_ID, fresh_nonce }   pk(responder)
b) responder -> initiator: { tag_b, nonce_i, fresh_nonce_r, responder_ID }  pk(initiator)
c) initiator -> responder: { tag_c, nonce_r }                     pk(responder)
```

- Freshness is checked with a timestamp window (`TSW`, default 5 seconds,
  see `uwcn.protocol.messages.check_timestamp`).
- A session key/id is derived per hop after a successful 3-message exchange
  (`uwcn.protocol.session.new_session`).
- Sensor/environment data (temperature, pressure, velocity, salinity, GPS,
  logs) flows along the same path but is **not** one of the 12 NSL messages
  — it is modeled separately in `uwcn.protocol.session.run_data_flow` to
  avoid overloading M3/M6/M9/M12 with two different meanings.

## Important caveat on the cryptographic backend

`uwcn.crypto.peecc.PEECCBackend` is a **symbolic/simulation abstraction**.
The base paper describes a PEECC 5-dimensional point representation but does
not provide a complete, executable 5-D group law or public-key-encryption
construction. This backend fills that gap with a simple scalar-multiplication
+ XOR-stream envelope purely so the protocol's *message flow and logic* can
be exercised and measured end-to-end. **It must not be treated as
deployable, secure cryptography.**

For a security analysis of the message-flow logic itself (independent of the
underlying primitive's real-world strength), see `verification/` and
`docs/verification.md`.
