# Benchmark results

`tests/comparison.py`, 10 runs per circuit, 2026-11-10, Apple M2 (Darwin arm64), nargo version = 1.0.0, bb 6.0.0. Inputs: holder1 of `credentials/` (the same credential in every variant).

## Summary

Gates (`bb gates`) and mean proving time (`bb prove`) per variant and scenario.

| Variant | age | rental | residence | veteran |
| --- | ---: | ---: | ---: | ---: |
| base (predicate only) | 3.2k · 55 ms | 13.6k · 119 ms | 3.3k · 55 ms | 2.9k · 53 ms |
| sha256-iso | 33.9k · 248 ms | 61.8k · 388 ms | 33.9k · 211 ms | 33.9k · 212 ms |
| sha512-iso | 47.1k · 362 ms | 119k · 772 ms | 47.2k · 309 ms | 46.8k · 308 ms |
| poseidon-iso | 14.6k · 152 ms | 30.8k · 225 ms | 14.7k · 140 ms | 14.3k · 139 ms |
| longfellow | 333k · 1.77 s | 373k · 1.92 s | 333k · 1.75 s | 332k · 1.76 s |
| vega | 265k · 1.39 s | 316k · 1.64 s | 265k · 1.41 s | 265k · 1.38 s |

Verification takes 12 to 14 ms (median per circuit) for every circuit.

## Every circuit

Mean ± standard deviation in ms. *Build* is the construction of the circuit from the ACIR bytecode (`bb gates`); *Prove* (`bb prove`) includes it, as a mobile prover builds the circuit for every proof. *Gates* is the `circuit_size` of `bb gates`. Its meaning depends on the Barretenberg version (bb 6 counts a block of about 15,300 rows whenever SHA-256 is used, which bb 0.84 did not), so gates are comparable only within one toolchain. The prover pads the circuit to a power of two, so circuits in the same power of two take similar times.

| Circuit | Gates | ACIR opcodes | Witness | Build | Prove | Verify |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| base/age | 3,222 | 311 | 163.8 ± 3.9 | 8.4 ± 0.1 | 55.1 ± 1.1 | 11.8 ± 0.3 |
| base/rental | 13,605 | 5,854 | 179.2 ± 4.3 | 15.9 ± 0.4 | 118.7 ± 1.0 | 12.3 ± 0.1 |
| base/residence | 3,269 | 281 | 159.7 ± 2.6 | 8.1 ± 0.1 | 55.1 ± 1.3 | 11.7 ± 0.3 |
| base/veteran | 2,935 | 56 | 159.4 ± 0.7 | 8.1 ± 0.1 | 53.3 ± 0.7 | 11.8 ± 0.4 |
| sha256-iso/age | 33,944 | 2,343 | 178.2 ± 14.1 | 26.8 ± 7.7 | 247.8 ± 30.4 | 13.0 ± 0.3 |
| sha256-iso/rental | 61,824 | 14,306 | 202.6 ± 0.5 | 55.1 ± 0.1 | 387.9 ± 8.9 | 12.6 ± 0.3 |
| sha256-iso/residence | 33,944 | 2,333 | 167.8 ± 1.0 | 23.6 ± 0.6 | 211.5 ± 5.5 | 12.5 ± 0.1 |
| sha256-iso/veteran | 33,944 | 2,054 | 168.3 ± 1.5 | 23.3 ± 0.1 | 211.8 ± 10.1 | 12.5 ± 0.2 |
| sha512-iso/age | 47,127 | 27,593 | 394.7 ± 3.6 | 46.9 ± 0.3 | 361.6 ± 7.7 | 13.0 ± 0.1 |
| sha512-iso/rental | 119,499 | 77,205 | 746.4 ± 21.7 | 114.4 ± 4.9 | 772.0 ± 241.0 | 12.9 ± 0.5 |
| sha512-iso/residence | 47,246 | 27,584 | 380.2 ± 3.5 | 44.9 ± 1.0 | 309.5 ± 5.3 | 12.5 ± 0.1 |
| sha512-iso/veteran | 46,790 | 27,304 | 378.6 ± 8.3 | 44.4 ± 0.2 | 308.1 ± 11.2 | 12.4 ± 0.1 |
| poseidon-iso/age | 14,592 | 4,638 | 228.2 ± 5.1 | 23.5 ± 0.4 | 151.5 ± 11.4 | 12.6 ± 0.4 |
| poseidon-iso/rental | 30,758 | 14,357 | 258.0 ± 6.7 | 35.0 ± 0.2 | 225.2 ± 10.0 | 12.5 ± 0.1 |
| poseidon-iso/residence | 14,685 | 4,628 | 225.0 ± 3.1 | 22.9 ± 0.1 | 139.8 ± 0.6 | 12.3 ± 0.1 |
| poseidon-iso/veteran | 14,256 | 4,349 | 223.9 ± 1.5 | 22.8 ± 0.1 | 138.9 ± 1.0 | 12.3 ± 0.1 |
| longfellow/age | 332,638 | 41,298 | 367.2 ± 1.4 | 291.5 ± 4.4 | 1768.6 ± 38.1 | 14.1 ± 0.5 |
| longfellow/rental | 373,416 | 53,222 | 405.4 ± 3.6 | 322.2 ± 5.2 | 1916.1 ± 27.2 | 14.2 ± 0.6 |
| longfellow/residence | 332,581 | 41,288 | 369.7 ± 6.8 | 290.3 ± 4.0 | 1752.5 ± 28.8 | 14.3 ± 0.7 |
| longfellow/veteran | 332,333 | 41,032 | 366.7 ± 1.7 | 289.4 ± 0.5 | 1758.5 ± 36.2 | 13.9 ± 0.6 |
| vega/age | 264,766 | 15,889 | 201.1 ± 1.7 | 194.9 ± 1.2 | 1392.2 ± 16.5 | 12.9 ± 0.1 |
| vega/rental | 316,365 | 31,696 | 245.9 ± 8.3 | 232.6 ± 5.6 | 1637.1 ± 58.0 | 13.1 ± 0.2 |
| vega/residence | 264,809 | 15,973 | 202.0 ± 7.1 | 195.6 ± 3.7 | 1414.1 ± 57.2 | 13.1 ± 0.6 |
| vega/veteran | 264,530 | 15,694 | 199.8 ± 1.4 | 194.8 ± 1.0 | 1377.7 ± 11.7 | 13.1 ± 0.4 |

## Every variant vs base (the cost of authentication)

| Comparison | Scenario | Gates (ref) | Gates | Gates ratio | Prove ms (ref) | Prove ms | Prove ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| sha256-iso vs base | age | 3,222 | 33,944 | 10.54x | 55 | 248 | 4.50x |
| sha256-iso vs base | rental | 13,605 | 61,824 | 4.54x | 119 | 388 | 3.27x |
| sha256-iso vs base | residence | 3,269 | 33,944 | 10.38x | 55 | 211 | 3.84x |
| sha256-iso vs base | veteran | 2,935 | 33,944 | 11.57x | 53 | 212 | 3.97x |
| sha512-iso vs base | age | 3,222 | 47,127 | 14.63x | 55 | 362 | 6.56x |
| sha512-iso vs base | rental | 13,605 | 119,499 | 8.78x | 119 | 772 | 6.50x |
| sha512-iso vs base | residence | 3,269 | 47,246 | 14.45x | 55 | 309 | 5.62x |
| sha512-iso vs base | veteran | 2,935 | 46,790 | 15.94x | 53 | 308 | 5.78x |
| poseidon-iso vs base | age | 3,222 | 14,592 | 4.53x | 55 | 152 | 2.75x |
| poseidon-iso vs base | rental | 13,605 | 30,758 | 2.26x | 119 | 225 | 1.90x |
| poseidon-iso vs base | residence | 3,269 | 14,685 | 4.49x | 55 | 140 | 2.54x |
| poseidon-iso vs base | veteran | 2,935 | 14,256 | 4.86x | 53 | 139 | 2.61x |
| longfellow vs base | age | 3,222 | 332,638 | 103.24x | 55 | 1769 | 32.10x |
| longfellow vs base | rental | 13,605 | 373,416 | 27.45x | 119 | 1916 | 16.14x |
| longfellow vs base | residence | 3,269 | 332,581 | 101.74x | 55 | 1753 | 31.83x |
| longfellow vs base | veteran | 2,935 | 332,333 | 113.23x | 53 | 1758 | 32.97x |
| vega vs base | age | 3,222 | 264,766 | 82.17x | 55 | 1392 | 25.27x |
| vega vs base | rental | 13,605 | 316,365 | 23.25x | 119 | 1637 | 13.79x |
| vega vs base | residence | 3,269 | 264,809 | 81.01x | 55 | 1414 | 25.68x |
| vega vs base | veteran | 2,935 | 264,530 | 90.13x | 53 | 1378 | 25.83x |

## Longfellow vs the ISO-compliant digests

| Comparison | Scenario | Gates (ref) | Gates | Gates ratio | Prove ms (ref) | Prove ms | Prove ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| longfellow vs sha256-iso | age | 33,944 | 332,638 | 9.80x | 248 | 1769 | 7.14x |
| longfellow vs sha256-iso | rental | 61,824 | 373,416 | 6.04x | 388 | 1916 | 4.94x |
| longfellow vs sha256-iso | residence | 33,944 | 332,581 | 9.80x | 211 | 1753 | 8.29x |
| longfellow vs sha256-iso | veteran | 33,944 | 332,333 | 9.79x | 212 | 1758 | 8.30x |
| longfellow vs sha512-iso | age | 47,127 | 332,638 | 7.06x | 362 | 1769 | 4.89x |
| longfellow vs sha512-iso | rental | 119,499 | 373,416 | 3.12x | 772 | 1916 | 2.48x |
| longfellow vs sha512-iso | residence | 47,246 | 332,581 | 7.04x | 309 | 1753 | 5.66x |
| longfellow vs sha512-iso | veteran | 46,790 | 332,333 | 7.10x | 308 | 1758 | 5.71x |

## VegaSC vs Longfellow and sha256-iso

| Comparison | Scenario | Gates (ref) | Gates | Gates ratio | Prove ms (ref) | Prove ms | Prove ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| vega vs longfellow | age | 332,638 | 264,766 | 0.80x | 1769 | 1392 | 0.79x |
| vega vs longfellow | rental | 373,416 | 316,365 | 0.85x | 1916 | 1637 | 0.85x |
| vega vs longfellow | residence | 332,581 | 264,809 | 0.80x | 1753 | 1414 | 0.81x |
| vega vs longfellow | veteran | 332,333 | 264,530 | 0.80x | 1758 | 1378 | 0.78x |
| vega vs sha256-iso | age | 33,944 | 264,766 | 7.80x | 248 | 1392 | 5.62x |
| vega vs sha256-iso | rental | 61,824 | 316,365 | 5.12x | 388 | 1637 | 4.22x |
| vega vs sha256-iso | residence | 33,944 | 264,809 | 7.80x | 211 | 1414 | 6.69x |
| vega vs sha256-iso | veteran | 33,944 | 264,530 | 7.79x | 212 | 1378 | 6.50x |
