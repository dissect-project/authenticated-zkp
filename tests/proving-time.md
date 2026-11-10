# Why proving time does not follow the gate count

In `comparison-results.md`, proving time mostly grows with the number of gates, with one clear
exception. `sha512-iso/rental` has fewer gates than `longfellow/rental` (348k against 493k) but
takes longer to prove (5.24 s against 3.67 s). Two effects explain this, and both apply to every
circuit.

## 1. `bb prove` also builds the circuit

`bb prove` does not start from a ready circuit. It first reads Noir's ACIR bytecode and builds the
UltraHonk circuit from it, expanding each ACIR opcode into gates. Only then does it compute the
proof. The reported proving time includes both steps.

Building costs a fixed overhead of about 50 ms, plus an amount that grows with the number of ACIR
**opcodes**, not only with the gates. The two counts can differ greatly:

- **Black-box functions** (SHA-256, ECDSA P-256) are a single opcode each. Barretenberg expands
  them into many gates with its own optimized gadgets.
- **Hash functions written in Noir**, such as SHA-512 from the `sha512` library (Noir has no
  SHA-512 black box), compile to a very large number of small 64-bit operations, one or more
  opcodes each.

`comparison-results.md` reports the construction alone as **Build** (the time of `bb gates`,
which builds the circuit without proving). For the three `rental` circuits whose proof covers a
2¹⁹ trace:

| Circuit | Gates | ACIR opcodes | Build | Prove (total) | Prove − Build |
|---|---:|---:|---:|---:|---:|
| `sha512-iso/rental` | 348,490 | 263,723 | 2.18 s | 5.24 s | ~3.1 s |
| `longfellow/rental` | 492,901 | 103,758 | 0.75 s | 3.67 s | ~2.9 s |
| `vega/rental` | 376,970 | 37,033 | 0.43 s | 2.71 s | ~2.3 s |

Without construction, `sha512-iso` and Longfellow are close, as their sizes suggest. The
subtraction is approximate, because Build is measured in a separate `bb` process. Construction
also grows faster than linearly in this range: `sha512-iso/age` (100k opcodes) builds in 0.41 s,
and `sha512-iso/rental` (264k opcodes) in 2.18 s.

A smaller difference remains after construction (about 3.1, 2.9 and 2.3 s). It was not
investigated further; it presumably comes from the different make-up of the circuits (for example
lookup-heavy 64-bit arithmetic in SHA-512 against black-box gadgets).

## 2. The prover works on a power-of-two trace

UltraHonk pads the circuit to a power of two, and the prover's main cost (commitments and
sumcheck over the padded trace) follows that size, not the exact gate count. `bb prove -v`
reports 19 sumcheck rounds for all three circuits above, i.e. a 2¹⁹ trace. So circuits between
roughly 262k and 524k gates cost about the same, for example:

- `longfellow/age` (447k gates) proves in 3.24 s and `longfellow/rental` (493k) in 3.67 s;
- `vega/age` (318k) proves in 2.43 s and `vega/rental` (377k) in 2.71 s.

Differences in gates within the same power of two therefore overstate differences in proving
time. Crossing a power of two roughly doubles the cost: `sha512-iso/age` (137k gates, 2¹⁸) proves
in 1.59 s.

## What this means for the results

- **Proving time is end-to-end.** It includes building the circuit. A mobile prover also builds
  the circuit from the bytecode for every proof, so this is the cost a holder pays, and it is the
  number to report.
- **Gates and time measure different things.** Gates measure the circuit's size. Proving time also
  depends on how Noir compiles the circuit (black boxes or code) and on the power of two the
  circuit falls in. The report gives both, with the opcode count and the build time, so the two
  can be told apart.
- **SHA-512 is penalized by its implementation, not only by its size.** With a SHA-512 black box
  in Noir and Barretenberg, `sha512-iso` would build much faster. Its proving times reflect the
  current toolchain (nargo 1.0.0-beta.7, bb 0.84.0).
