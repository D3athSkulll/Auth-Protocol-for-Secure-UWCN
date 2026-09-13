# authentication-secure-underwater-protocol (UWCN / PEECC)

A modular Python implementation and evaluation harness for a PEECC-based
Underwater Wireless Communication Network (UWCN) authentication protocol,
modeled as a 4-hop Needham-Schroeder-Lowe (NSL) style exchange:

```
UWS <-> SUB <-> BUOY <-> SAT <-> BS
```

This repository was refactored from a single-file research prototype into a
proper package (`src/uwcn`) with clear separation between:

- **models** — plain data structures (points, entities, messages, network topology)
- **crypto** — the PEECC symbolic backend, hashing, XOR stream cipher, AES-GCM benchmark
- **protocol** — initialization, registration, authentication (M1–M12), messaging, sessions
- **simulation** — the acoustic channel model: delay, packet loss, mobility, energy/battery
- **evaluation** — metrics, paper/reference comparisons, attack tests, scaling experiments
- **visualization** — topology, performance, comparison, and battery plots

> **Note:** The PEECC backend here is a symbolic/simulation abstraction used to
> exercise the protocol logic and produce evaluation numbers. It is **not** a
> production cryptographic implementation. See `docs/protocol.md` and
> `verification/README.md` for details and the Scyther model used for formal
> verification of the authentication logic.

## Quick start

```bash
pip install -r requirements.txt
python scripts/run_protocol.py        # single clean M1-M12 authentication run
python scripts/run_experiments.py     # replay test + 5-round fallback experiment
python scripts/run_attacks.py         # attack / anomaly evaluation
python scripts/generate_plots.py      # produce all output_*.png figures
```

Or run everything end to end:

```bash
python scripts/run_protocol.py && \
python scripts/run_experiments.py && \
python scripts/run_attacks.py && \
python scripts/generate_plots.py
```

Figures are written to `outputs/figures/`, and console/summary text can be
redirected into `outputs/logs/`.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — package layout and module responsibilities
- [`docs/protocol.md`](docs/protocol.md) — the 12-message NSL-style protocol
- [`docs/metrics.md`](docs/metrics.md) — evaluation metrics and comparison methodology
- [`docs/verification.md`](docs/verification.md) — formal verification with Scyther

## Testing

```bash
pip install -r requirements.txt
pytest tests/
```

## License

See [LICENSE](LICENSE).
