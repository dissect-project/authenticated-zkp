# Benchmark results

`tests/comparison.py`, 10 runs per circuit, 2026-11-12, Apple M2 (Darwin arm64), nargo version = 1.0.0, bb 6.0.0. Inputs: holder1 of `credentials/` (the same credential in every variant).

## Summary

Gates (`bb gates`) and mean proving time (`bb prove`) per variant and scenario.

| Variant | age | rental | residence | veteran |
| --- | ---: | ---: | ---: | ---: |
| base (predicate only) | 3.2k · 55 ms | 13.6k · 119 ms | 3.3k · 55 ms | 2.9k · 53 ms |
| sha256-iso | 33.9k · 222 ms | 61.8k · 389 ms | 33.9k · 220 ms | 33.9k · 220 ms |
| sha512-iso | 47.1k · 312 ms | 120k · 745 ms | 47.2k · 318 ms | 46.8k · 369 ms |
| poseidon-iso | 14.6k · 140 ms | 30.8k · 244 ms | 14.7k · 141 ms | 14.3k · 143 ms |
| longfellow | 333k · 1.84 s | 373k · 2.11 s | 333k · 1.81 s | 332k · 1.86 s |
| vega | 265k · 1.41 s | 316k · 1.70 s | 265k · 1.43 s | 265k · 1.41 s |

Verification takes 11 to 14 ms (median per circuit) for every circuit.

## Every circuit

Mean ± standard deviation in ms. *Build* is the construction of the circuit from the ACIR bytecode (`bb gates`); *Prove* (`bb prove`) includes it, as a mobile prover builds the circuit for every proof. *Gates* is the `circuit_size` of `bb gates`. Its meaning depends on the Barretenberg version (bb 6 counts a block of about 15,300 rows whenever SHA-256 is used, which bb 0.84 did not), so gates are comparable only within one toolchain. The prover pads the circuit to a power of two, so circuits in the same power of two take similar times.

| Circuit | Gates | ACIR opcodes | Witness | Build | Prove | Verify |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| base/age | 3,222 | 311 | 162.3 ± 3.1 | 8.7 ± 0.3 | 55.0 ± 0.6 | 11.9 ± 0.3 |
| base/rental | 13,605 | 5,854 | 177.6 ± 0.8 | 15.7 ± 0.1 | 119.4 ± 1.9 | 12.1 ± 0.1 |
| base/residence | 3,269 | 281 | 158.1 ± 1.7 | 8.1 ± 0.1 | 55.4 ± 1.6 | 11.5 ± 0.1 |
| base/veteran | 2,935 | 56 | 160.9 ± 3.4 | 8.1 ± 0.1 | 53.1 ± 1.0 | 12.0 ± 0.8 |
| sha256-iso/age | 33,944 | 2,343 | 172.7 ± 8.5 | 24.0 ± 0.5 | 221.7 ± 18.8 | 12.9 ± 0.4 |
| sha256-iso/rental | 61,825 | 14,306 | 202.9 ± 1.0 | 55.6 ± 0.8 | 388.9 ± 5.1 | 12.4 ± 0.1 |
| sha256-iso/residence | 33,944 | 2,333 | 172.9 ± 5.9 | 24.3 ± 1.2 | 220.2 ± 12.7 | 12.5 ± 0.4 |
| sha256-iso/veteran | 33,944 | 2,054 | 170.4 ± 5.3 | 24.1 ± 0.9 | 220.2 ± 8.8 | 12.5 ± 0.3 |
| sha512-iso/age | 47,128 | 27,593 | 379.9 ± 3.4 | 45.5 ± 0.3 | 311.9 ± 10.9 | 12.5 ± 0.1 |
| sha512-iso/rental | 119,500 | 77,205 | 763.4 ± 51.2 | 116.3 ± 3.3 | 745.5 ± 66.0 | 12.8 ± 0.4 |
| sha512-iso/residence | 47,247 | 27,584 | 380.7 ± 2.7 | 45.1 ± 0.2 | 318.2 ± 13.5 | 12.5 ± 0.2 |
| sha512-iso/veteran | 46,791 | 27,304 | 386.6 ± 15.1 | 53.6 ± 26.4 | 369.3 ± 150.5 | 12.5 ± 0.6 |
| poseidon-iso/age | 14,594 | 4,638 | 225.6 ± 1.0 | 23.4 ± 0.7 | 139.5 ± 0.8 | 12.4 ± 0.2 |
| poseidon-iso/rental | 30,760 | 14,357 | 271.8 ± 21.3 | 36.1 ± 0.6 | 243.9 ± 29.5 | 13.4 ± 2.3 |
| poseidon-iso/residence | 14,687 | 4,628 | 227.7 ± 4.6 | 23.3 ± 0.4 | 141.1 ± 1.7 | 12.3 ± 0.1 |
| poseidon-iso/veteran | 14,258 | 4,349 | 227.4 ± 3.4 | 23.3 ± 0.8 | 142.9 ± 3.9 | 12.3 ± 0.2 |
| longfellow/age | 332,638 | 41,298 | 369.1 ± 3.0 | 295.2 ± 10.2 | 1835.6 ± 119.2 | 14.2 ± 0.6 |
| longfellow/rental | 373,416 | 53,222 | 409.7 ± 9.6 | 323.0 ± 7.4 | 2109.7 ± 202.3 | 14.5 ± 1.0 |
| longfellow/residence | 332,581 | 41,288 | 369.2 ± 3.2 | 290.8 ± 3.7 | 1809.2 ± 95.5 | 13.9 ± 0.4 |
| longfellow/veteran | 332,333 | 41,032 | 371.2 ± 7.1 | 292.6 ± 8.6 | 1856.4 ± 118.9 | 14.1 ± 0.7 |
| vega/age | 264,766 | 15,889 | 202.4 ± 3.2 | 196.9 ± 4.8 | 1410.3 ± 38.1 | 13.6 ± 1.1 |
| vega/rental | 316,365 | 31,696 | 243.7 ± 2.3 | 234.5 ± 8.3 | 1697.5 ± 82.4 | 13.5 ± 0.9 |
| vega/residence | 264,809 | 15,973 | 203.7 ± 3.6 | 198.0 ± 4.6 | 1433.7 ± 41.5 | 13.4 ± 0.8 |
| vega/veteran | 264,530 | 15,694 | 200.6 ± 1.7 | 195.6 ± 1.5 | 1407.4 ± 40.2 | 13.2 ± 0.7 |

## Every variant vs base (the cost of authentication)

| Comparison | Scenario | Gates (ref) | Gates | Gates ratio | Prove ms (ref) | Prove ms | Prove ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| sha256-iso vs base | age | 3,222 | 33,944 | 10.54x | 55 | 222 | 4.03x |
| sha256-iso vs base | rental | 13,605 | 61,825 | 4.54x | 119 | 389 | 3.26x |
| sha256-iso vs base | residence | 3,269 | 33,944 | 10.38x | 55 | 220 | 3.97x |
| sha256-iso vs base | veteran | 2,935 | 33,944 | 11.57x | 53 | 220 | 4.15x |
| sha512-iso vs base | age | 3,222 | 47,128 | 14.63x | 55 | 312 | 5.67x |
| sha512-iso vs base | rental | 13,605 | 119,500 | 8.78x | 119 | 745 | 6.25x |
| sha512-iso vs base | residence | 3,269 | 47,247 | 14.45x | 55 | 318 | 5.74x |
| sha512-iso vs base | veteran | 2,935 | 46,791 | 15.94x | 53 | 369 | 6.96x |
| poseidon-iso vs base | age | 3,222 | 14,594 | 4.53x | 55 | 140 | 2.54x |
| poseidon-iso vs base | rental | 13,605 | 30,760 | 2.26x | 119 | 244 | 2.04x |
| poseidon-iso vs base | residence | 3,269 | 14,687 | 4.49x | 55 | 141 | 2.54x |
| poseidon-iso vs base | veteran | 2,935 | 14,258 | 4.86x | 53 | 143 | 2.69x |
| longfellow vs base | age | 3,222 | 332,638 | 103.24x | 55 | 1836 | 33.35x |
| longfellow vs base | rental | 13,605 | 373,416 | 27.45x | 119 | 2110 | 17.67x |
| longfellow vs base | residence | 3,269 | 332,581 | 101.74x | 55 | 1809 | 32.64x |
| longfellow vs base | veteran | 2,935 | 332,333 | 113.23x | 53 | 1856 | 34.99x |
| vega vs base | age | 3,222 | 264,766 | 82.17x | 55 | 1410 | 25.63x |
| vega vs base | rental | 13,605 | 316,365 | 23.25x | 119 | 1697 | 14.22x |
| vega vs base | residence | 3,269 | 264,809 | 81.01x | 55 | 1434 | 25.87x |
| vega vs base | veteran | 2,935 | 264,530 | 90.13x | 53 | 1407 | 26.53x |

## Longfellow vs the ISO-compliant digests

| Comparison | Scenario | Gates (ref) | Gates | Gates ratio | Prove ms (ref) | Prove ms | Prove ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| longfellow vs sha256-iso | age | 33,944 | 332,638 | 9.80x | 222 | 1836 | 8.28x |
| longfellow vs sha256-iso | rental | 61,825 | 373,416 | 6.04x | 389 | 2110 | 5.43x |
| longfellow vs sha256-iso | residence | 33,944 | 332,581 | 9.80x | 220 | 1809 | 8.22x |
| longfellow vs sha256-iso | veteran | 33,944 | 332,333 | 9.79x | 220 | 1856 | 8.43x |
| longfellow vs sha512-iso | age | 47,128 | 332,638 | 7.06x | 312 | 1836 | 5.88x |
| longfellow vs sha512-iso | rental | 119,500 | 373,416 | 3.12x | 745 | 2110 | 2.83x |
| longfellow vs sha512-iso | residence | 47,247 | 332,581 | 7.04x | 318 | 1809 | 5.69x |
| longfellow vs sha512-iso | veteran | 46,791 | 332,333 | 7.10x | 369 | 1856 | 5.03x |

## VegaSC vs Longfellow and sha256-iso

| Comparison | Scenario | Gates (ref) | Gates | Gates ratio | Prove ms (ref) | Prove ms | Prove ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| vega vs longfellow | age | 332,638 | 264,766 | 0.80x | 1836 | 1410 | 0.77x |
| vega vs longfellow | rental | 373,416 | 316,365 | 0.85x | 2110 | 1697 | 0.80x |
| vega vs longfellow | residence | 332,581 | 264,809 | 0.80x | 1809 | 1434 | 0.79x |
| vega vs longfellow | veteran | 332,333 | 264,530 | 0.80x | 1856 | 1407 | 0.76x |
| vega vs sha256-iso | age | 33,944 | 264,766 | 7.80x | 222 | 1410 | 6.36x |
| vega vs sha256-iso | rental | 61,825 | 316,365 | 5.12x | 389 | 1697 | 4.37x |
| vega vs sha256-iso | residence | 33,944 | 264,809 | 7.80x | 220 | 1434 | 6.51x |
| vega vs sha256-iso | veteran | 33,944 | 264,530 | 7.79x | 220 | 1407 | 6.39x |
