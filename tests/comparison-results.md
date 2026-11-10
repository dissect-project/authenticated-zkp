# Benchmark results

`tests/comparison.py`, 10 runs per circuit, 2026-11-10, Apple M2 (Darwin arm64), nargo version = 1.0.0-beta.7, bb v0.84.0. Inputs: holder1 of `credentials/` (the same credential in every variant).

## Summary

Gates (`bb gates`) and mean proving time (`bb prove`) per variant and scenario.

| Variant | age | rental | residence | veteran |
| --- | ---: | ---: | ---: | ---: |
| base (predicate only) | 3.2k · 96 ms | 17.4k · 240 ms | 3.4k · 94 ms | 2.9k · 92 ms |
| sha256-iso | 19.5k · 353 ms | 68.8k · 674 ms | 19.8k · 340 ms | 19.1k · 335 ms |
| sha512-iso | 137k · 1.59 s | 348k · 5.24 s | 138k · 1.57 s | 137k · 1.77 s |
| poseidon-iso | 15.2k · 225 ms | 38.1k · 462 ms | 15.5k · 224 ms | 14.9k · 221 ms |
| longfellow | 447k · 3.24 s | 493k · 3.67 s | 447k · 3.29 s | 447k · 3.34 s |
| vega | 318k · 2.43 s | 377k · 2.70 s | 318k · 2.42 s | 317k · 2.41 s |

Verification takes 36 to 40 ms (median per circuit) for every circuit.

## Every circuit

Mean ± standard deviation in ms. *Build* is the construction of the circuit from the ACIR bytecode (`bb gates`); *Prove* (`bb prove`) includes it. Building grows with the number of ACIR opcodes, not only with the gates: SHA-512 has no black box in Noir and compiles to many small opcodes, so sha512-iso spends a large share of its proving time building the circuit (see `proving-time.md`).

| Circuit | Gates | ACIR opcodes | Witness | Build | Prove | Verify |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| base/age | 3,199 | 311 | 53.3 ± 0.9 | 50.4 ± 4.8 | 96.0 ± 1.8 | 36.3 ± 0.4 |
| base/rental | 17,410 | 7,201 | 89.6 ± 0.9 | 72.9 ± 0.7 | 240.1 ± 6.1 | 36.7 ± 0.2 |
| base/residence | 3,426 | 281 | 52.4 ± 0.4 | 48.5 ± 0.3 | 94.2 ± 0.7 | 36.0 ± 0.1 |
| base/veteran | 2,934 | 56 | 52.3 ± 1.3 | 48.1 ± 0.7 | 92.0 ± 0.9 | 36.1 ± 0.4 |
| sha256-iso/age | 19,497 | 2,651 | 67.0 ± 4.1 | 73.2 ± 5.9 | 353.1 ± 14.0 | 37.4 ± 1.0 |
| sha256-iso/rental | 68,817 | 17,472 | 141.9 ± 1.0 | 144.6 ± 0.9 | 673.7 ± 10.4 | 37.1 ± 0.1 |
| sha256-iso/residence | 19,791 | 2,669 | 66.1 ± 2.3 | 71.0 ± 0.5 | 340.1 ± 8.1 | 37.2 ± 0.6 |
| sha256-iso/veteran | 19,143 | 2,330 | 64.3 ± 0.9 | 70.2 ± 0.4 | 334.6 ± 7.1 | 37.1 ± 0.6 |
| sha512-iso/age | 137,439 | 100,085 | 768.5 ± 11.1 | 407.0 ± 7.9 | 1591.6 ± 45.1 | 37.8 ± 0.5 |
| sha512-iso/rental | 348,490 | 263,723 | 1946.7 ± 49.7 | 2180.5 ± 263.5 | 5237.5 ± 354.4 | 39.4 ± 1.9 |
| sha512-iso/residence | 137,761 | 100,104 | 764.0 ± 5.1 | 405.2 ± 12.0 | 1574.7 ± 56.8 | 37.9 ± 0.5 |
| sha512-iso/veteran | 137,087 | 99,764 | 766.2 ± 36.4 | 433.1 ± 63.6 | 1772.7 ± 85.6 | 38.0 ± 0.7 |
| poseidon-iso/age | 15,230 | 4,945 | 147.3 ± 2.7 | 77.9 ± 0.6 | 225.4 ± 4.0 | 36.8 ± 0.6 |
| poseidon-iso/rental | 38,149 | 17,522 | 219.9 ± 5.6 | 127.8 ± 3.1 | 461.8 ± 19.1 | 37.3 ± 0.5 |
| poseidon-iso/residence | 15,525 | 4,963 | 146.9 ± 4.6 | 78.9 ± 1.4 | 224.1 ± 2.8 | 36.8 ± 0.1 |
| poseidon-iso/veteran | 14,877 | 4,624 | 143.5 ± 1.3 | 77.0 ± 0.6 | 220.9 ± 3.8 | 36.8 ± 0.5 |
| longfellow/age | 446,889 | 88,976 | 637.9 ± 5.3 | 685.3 ± 18.8 | 3238.6 ± 64.6 | 39.0 ± 0.6 |
| longfellow/rental | 492,901 | 103,758 | 717.6 ± 8.0 | 750.8 ± 42.1 | 3669.4 ± 207.3 | 39.4 ± 1.3 |
| longfellow/residence | 446,862 | 88,994 | 670.3 ± 92.0 | 680.6 ± 4.3 | 3285.4 ± 72.6 | 68.2 ± 91.4 |
| longfellow/veteran | 446,588 | 88,702 | 633.9 ± 4.8 | 679.3 ± 13.6 | 3341.5 ± 40.9 | 38.9 ± 0.7 |
| vega/age | 317,541 | 17,792 | 132.1 ± 8.9 | 343.5 ± 9.7 | 2433.2 ± 70.4 | 38.2 ± 1.0 |
| vega/rental | 376,970 | 37,033 | 221.9 ± 1.2 | 429.0 ± 2.3 | 2705.0 ± 37.9 | 38.1 ± 0.7 |
| vega/residence | 317,945 | 17,904 | 128.0 ± 1.4 | 340.4 ± 3.2 | 2421.8 ± 32.2 | 37.8 ± 0.4 |
| vega/veteran | 317,272 | 17,565 | 127.2 ± 1.3 | 338.7 ± 0.7 | 2411.2 ± 29.5 | 37.8 ± 0.5 |

## Every variant vs base (the cost of authentication)

| Comparison | Scenario | Gates (ref) | Gates | Gates ratio | Prove ms (ref) | Prove ms | Prove ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| sha256-iso vs base | age | 3,199 | 19,497 | 6.09x | 96 | 353 | 3.68x |
| sha256-iso vs base | rental | 17,410 | 68,817 | 3.95x | 240 | 674 | 2.81x |
| sha256-iso vs base | residence | 3,426 | 19,791 | 5.78x | 94 | 340 | 3.61x |
| sha256-iso vs base | veteran | 2,934 | 19,143 | 6.52x | 92 | 335 | 3.64x |
| sha512-iso vs base | age | 3,199 | 137,439 | 42.96x | 96 | 1592 | 16.58x |
| sha512-iso vs base | rental | 17,410 | 348,490 | 20.02x | 240 | 5237 | 21.82x |
| sha512-iso vs base | residence | 3,426 | 137,761 | 40.21x | 94 | 1575 | 16.71x |
| sha512-iso vs base | veteran | 2,934 | 137,087 | 46.72x | 92 | 1773 | 19.27x |
| poseidon-iso vs base | age | 3,199 | 15,230 | 4.76x | 96 | 225 | 2.35x |
| poseidon-iso vs base | rental | 17,410 | 38,149 | 2.19x | 240 | 462 | 1.92x |
| poseidon-iso vs base | residence | 3,426 | 15,525 | 4.53x | 94 | 224 | 2.38x |
| poseidon-iso vs base | veteran | 2,934 | 14,877 | 5.07x | 92 | 221 | 2.40x |
| longfellow vs base | age | 3,199 | 446,889 | 139.70x | 96 | 3239 | 33.74x |
| longfellow vs base | rental | 17,410 | 492,901 | 28.31x | 240 | 3669 | 15.28x |
| longfellow vs base | residence | 3,426 | 446,862 | 130.43x | 94 | 3285 | 34.86x |
| longfellow vs base | veteran | 2,934 | 446,588 | 152.21x | 92 | 3341 | 36.32x |
| vega vs base | age | 3,199 | 317,541 | 99.26x | 96 | 2433 | 25.35x |
| vega vs base | rental | 17,410 | 376,970 | 21.65x | 240 | 2705 | 11.27x |
| vega vs base | residence | 3,426 | 317,945 | 92.80x | 94 | 2422 | 25.70x |
| vega vs base | veteran | 2,934 | 317,272 | 108.14x | 92 | 2411 | 26.21x |

## Longfellow vs the ISO-compliant digests

| Comparison | Scenario | Gates (ref) | Gates | Gates ratio | Prove ms (ref) | Prove ms | Prove ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| longfellow vs sha256-iso | age | 19,497 | 446,889 | 22.92x | 353 | 3239 | 9.17x |
| longfellow vs sha256-iso | rental | 68,817 | 492,901 | 7.16x | 674 | 3669 | 5.45x |
| longfellow vs sha256-iso | residence | 19,791 | 446,862 | 22.58x | 340 | 3285 | 9.66x |
| longfellow vs sha256-iso | veteran | 19,143 | 446,588 | 23.33x | 335 | 3341 | 9.99x |
| longfellow vs sha512-iso | age | 137,439 | 446,889 | 3.25x | 1592 | 3239 | 2.03x |
| longfellow vs sha512-iso | rental | 348,490 | 492,901 | 1.41x | 5237 | 3669 | 0.70x |
| longfellow vs sha512-iso | residence | 137,761 | 446,862 | 3.24x | 1575 | 3285 | 2.09x |
| longfellow vs sha512-iso | veteran | 137,087 | 446,588 | 3.26x | 1773 | 3341 | 1.89x |

## VegaSC vs Longfellow and sha256-iso

| Comparison | Scenario | Gates (ref) | Gates | Gates ratio | Prove ms (ref) | Prove ms | Prove ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| vega vs longfellow | age | 446,889 | 317,541 | 0.71x | 3239 | 2433 | 0.75x |
| vega vs longfellow | rental | 492,901 | 376,970 | 0.76x | 3669 | 2705 | 0.74x |
| vega vs longfellow | residence | 446,862 | 317,945 | 0.71x | 3285 | 2422 | 0.74x |
| vega vs longfellow | veteran | 446,588 | 317,272 | 0.71x | 3341 | 2411 | 0.72x |
| vega vs sha256-iso | age | 19,497 | 317,541 | 16.29x | 353 | 2433 | 6.89x |
| vega vs sha256-iso | rental | 68,817 | 376,970 | 5.48x | 674 | 2705 | 4.02x |
| vega vs sha256-iso | residence | 19,791 | 317,945 | 16.07x | 340 | 2422 | 7.12x |
| vega vs sha256-iso | veteran | 19,143 | 317,272 | 16.57x | 335 | 2411 | 7.21x |
