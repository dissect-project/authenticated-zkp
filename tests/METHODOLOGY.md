# Methodology: mobile performance tests

Performance of the six implementations on two Android phones, with the same toolchain as the
desktop benchmark (`tests/comparison.py`).

## Setup

**Devices**

| Device | SoC | RAM | Android |
|---|---|---|---|
| Pixel 7a | Google Tensor G2 | 8 GB | 17 |
| Pixel 10 Pro | Google Tensor G5 | 16 GB | 17 |

**Toolchain:** Noir 1.0.0 and Barretenberg 6.0.0 (UltraHonk, ZK, Poseidon2 transcript, as the
`noir-recursive` target), through zkPassport `noir_rs` 1.0.0, in a Flutter app built in release
mode for `aarch64-linux-android`.

**Test data:** only the files in `scenarios/mdl/`:

- **Circuits:** `circuits/<variant>_<scenario>.json`, the 24 compiled circuits.
- **Inputs:** `inputs/inputs_<scenario>.dart`, holder 1's entry for each circuit (`"run": 1`),
  the same values as the desktop benchmark's `Prover.toml`.

## Implementations and scenarios

Six implementations in four scenarios (age, rental, residence, veteran), grouped into two
comparisons:

1. **ISO variations:** base, sha256-iso, sha512-iso, poseidon-iso.
2. **Related work:** base, sha256-iso, longfellow, vega.

## Device conditions

- On battery and not charging, with the battery between 80% and 30%.
- Airplane mode on, battery saver off, no other apps running.
- Screen kept on, with the brightness set by the app to 20%.
- Default CPU governor, with no performance mode.
- Before the session starts, the device rests until its thermal status is
  `THERMAL_STATUS_NONE` and its battery temperature has returned to its resting value.

The app checks these conditions at the start and records any violation during the session.
The room temperature is recorded (21–22 °C).

## Procedure

For each scenario, 100 runs. Each run executes every implementation once, in an order shuffled
for that run (the seed is recorded), with a 0.5 s pause between consecutive proofs. Every proof
is verified right after it is produced. There are no warm-up runs.

All six implementations run in a single session per device. The scenarios run one after the
other, with no cool-down between them.

## Measurements

For every execution:

- **Proof generation time:** witness generation plus proving (Witness + Prove), in ms.
- **Verification time:** proof verification, in ms.
- **Proof validity and size:** the proof size includes the public inputs.
- **Memory:** the process's resident memory (RSS) before the proof, and its peak during the
  proof, sampled every 10 ms.
- **Temperature:** the thermal status (`PowerManager.getCurrentThermalStatus()`) and the battery
  temperature (`BatteryManager.EXTRA_TEMPERATURE`), before and after the proof.

Throughout the session, the thermal headroom (`PowerManager.getThermalHeadroom(0)`), the thermal
status, the battery temperature and the battery level are also sampled every 1 s, since Android
returns `NaN` for the headroom when it is queried more often. Each proof is matched to the last
sample before it starts and to any samples taken during it.

## Analysis

- Mean ± standard deviation and median of the proof generation and verification times, per
  device, implementation and scenario.
- Thermal throttling: proof times are compared between executions with thermal status `NONE`
  and those above it, and plotted against run number to show any drift.
