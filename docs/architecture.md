# Architecture

This repository packages a single research prototype (a PEECC-based UWCN
authentication simulator) into a proper Python package under `src/uwcn/`,
plus thin CLI entry points under `scripts/`.

```
src/uwcn/
├── config.py           # all constants: crypto params, timing, channel,
│                        # energy, topology, message tags, reference figures
│
├── models/              # plain data structures, no behaviour beyond
│   ├── point.py         #   PEECCPoint (5-D coordinate) + canonical encoding
│   ├── entity.py        #   Entity (a UWS/SUB/BUOY/SAT/BS node)
│   ├── message.py       #   MessageRecord, PacketStats
│   └── network.py       #   networkx topology graph builder
│
├── crypto/               # cryptographic building blocks
│   ├── hash.py           #   generic SHA-256 helper (RID/THETA/session IDs)
│   ├── xor.py            #   XOR stream cipher (symbolic PEECC envelope)
│   ├── peecc.py          #   PEECCBackend: keygen, shared-point, encrypt/decrypt
│   └── aes.py            #   independent AES-GCM benchmark (evaluation only)
│
├── protocol/             # the M1-M12 NSL-style exchange
│   ├── initialization.py #   keypair + identity generation for every entity
│   ├── registration.py   #   RID/THETA derivation and link registration
│   ├── messages.py       #   nonces, freshness checks, field encrypt/decrypt
│   ├── authentication.py #   authenticate_hop() and run_ns_authentication()
│   └── session.py        #   session-key bookkeeping + sensor data flow
│
├── simulation/            # the acoustic channel model
│   ├── delay.py           #   Thorp absorption + propagation delay model
│   ├── packet_loss.py     #   loss decision
│   ├── mobility.py        #   bounded random-walk node mobility
│   ├── energy.py          #   per-node battery accounting
│   └── channel.py         #   Channel: combines delay/loss/retry/energy for
│                           #   one message transmission attempt
│
├── evaluation/            # analysis built on top of a completed run
│   ├── metrics.py         #   anomaly detection, comm-cost, energy summary
│   ├── paper_metrics.py   #   reference figures from the base paper / prior work
│   ├── attacks.py         #   replay/freshness attack test
│   ├── scaling.py         #   node-count scaling model + fallback experiment
│   └── comparison.py      #   COMPARISON table helpers (vs. Ref [21]-[25])
│
└── visualization/          # matplotlib figure generation
    ├── topology.py         #   Graph 1: topology + active path
    ├── performance.py      #   Graphs 2/3/4/6: delay/energy/comm/throughput
    ├── comparison.py       #   Graph 5: computational + comm cost vs. prior work
    └── battery.py          #   Graph 7: remaining battery per node
```

## Data flow

1. **`scripts/run_protocol.py`** builds a `PEECCBackend`, initializes and
   registers all entities, creates a `Channel`, and runs one clean M1-M12
   authentication sequence followed by the (protocol-independent) sensor
   data flow.
2. **`scripts/run_experiments.py`** runs the replay/freshness test and a
   5-round resilience experiment that simulates BUOY/SAT unavailability.
3. **`scripts/run_attacks.py`** focuses on attack-oriented evaluation:
   replay test + delay-anomaly detection across several runs.
4. **`scripts/generate_plots.py`** runs a representative session and
   produces all seven `output_*.png` figures under `outputs/figures/`.

Each script is a small, independent composition of the package's functions
— there is no hidden global state; every piece of mutable state (`entities`,
`Channel`, `sessions`) is constructed explicitly and passed around.
