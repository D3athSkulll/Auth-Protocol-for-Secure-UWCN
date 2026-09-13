# Evaluation Metrics

`uwcn.evaluation` and `uwcn.visualization` compute and plot the following,
all derived from a run of the protocol against the simulated acoustic
channel (`uwcn.simulation.channel.Channel`):

- **Delay** — per-hop and mean end-to-end acoustic delay, modeled with
  Thorp's absorption formula plus propagation time and multipath jitter
  (`uwcn.simulation.delay`). Plotted against a reference figure of 211 ms
  per authentication path.
- **Energy** — per-node battery consumption for TX/RX/auth operations
  (`uwcn.simulation.energy.EnergyModel`), reported both as raw microjoules
  and remaining battery percentage.
- **Communication cost** — total observed ciphertext size (bits) across a
  run, falling back to a 296-bit/message reference figure when no messages
  were recorded (`uwcn.evaluation.metrics.communication_bits`).
- **Anomaly detection** — z-score based outlier detection over the delay
  log, threshold 2.5 by default (`uwcn.evaluation.metrics.detect_anomalies`).
- **Scaling** — how mean path delay, energy, communication cost, and
  authentication throughput scale with an increasing simulated node count
  (`uwcn.evaluation.scaling.scaling_data`).
- **Comparison** — computational cost (ms) and communication overhead
  (bits) against five prior related schemes (`Ref [21]`-`Ref [25]`), plus
  the proposed scheme, sourced from `uwcn.config.COMPARISON`.

## Reproducibility caveat

The reference/comparison figures in `uwcn.evaluation.paper_metrics` and
`uwcn.config.COMPARISON` were carried over from an earlier evaluation
prototype. **They should be independently re-derived or verified against the
original source papers before being used in any publication.**
