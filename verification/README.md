# Formal Verification (Scyther)

`uwc_protocol.spdl` models the 4 independent NSL-style hops of the M1-M12
authentication exchange:

- `uwchop1(UWS, SUB)`   -- M1, M2, M3
- `uwchop2(SUB, BUOY)`  -- M4, M5, M6
- `uwchop3(BUOY, SAT)`  -- M7, M8, M9
- `uwchop4(SAT, BS)`    -- M10, M11, M12

Each protocol block claims:

- `Secret` for both nonces (`Ni`, `Nr`)
- `Niagree` / `Nisynch` for mutual (non-injective) agreement/synchronization

## Requirements

- [Scyther](https://people.cispa.io/cas.cremers/scyther/) installed and
  available as `scyther-cli` (Linux/macOS) or via the Scyther GUI/CLI on
  Windows.

## Running

**Windows:**

```
run_scyther.bat
```

**Linux/macOS:**

```
scyther-cli uwc_protocol.spdl
```

## Interpreting results

Scyther will report, for each of the 8 roles (`I`/`R` x 4 hops), whether the
`Secret` and `Niagree`/`Nisynch` claims hold or whether it found an attack
trace. A clean run (no attacks found) confirms the message-flow logic
itself provides mutual authentication and nonce secrecy under the Dolev-Yao
model, **independent of** the concrete PEECC key-agreement construction used
in the Python simulation — see `docs/protocol.md` for that distinction.
