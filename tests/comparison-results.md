# Benchmark results

`tests/comparison.py`, 10 runs per circuit, 2026-11-12, Apple M2 (Darwin arm64), nargo version = 1.0.0, bb 6.0.0. Inputs: holder1 of `credentials/` (the same credential in every variant).

## Summary

Gates (`bb gates`) and mean proving time (`bb prove`) per variant and scenario. The medians are in the tables below; they differ from the means only where a run was slow.

| Variant | age | rental | residence | veteran |
| --- | ---: | ---: | ---: | ---: |
| base (predicate only) | 3.2k · 55 ms | 13.6k · 119 ms | 3.3k · 55 ms | 2.9k · 54 ms |
| sha256-iso | 33.9k · 218 ms | 61.8k · 398 ms | 33.9k · 216 ms | 33.9k · 217 ms |
| sha512-iso | 47.1k · 316 ms | 120k · 711 ms | 47.2k · 317 ms | 46.8k · 323 ms |
| poseidon-iso | 14.6k · 142 ms | 30.8k · 228 ms | 14.7k · 142 ms | 14.3k · 141 ms |
| longfellow | 333k · 1.81 s | 373k · 2.05 s | 333k · 1.78 s | 332k · 1.77 s |
| vega | 265k · 1.42 s | 316k · 1.67 s | 265k · 1.42 s | 265k · 1.42 s |

Verification takes 12 to 14 ms (median per circuit) for every circuit.

## Every circuit

Times are the mean ± standard deviation in ms, and the median of *Prove*. Each run has four steps:

- **Witness** (`nargo execute`): runs the circuit on the holder's inputs and computes the witness, the values of every wire. It also checks every constraint, so invalid inputs fail here.
- **Build** (`bb gates`): builds the UltraHonk circuit from Noir's ACIR bytecode, with no proof. It is measured on its own to show its share of *Prove*.
- **Prove** (`bb prove`): builds the circuit again and generates the zero-knowledge proof from the witness. It includes *Build*, as a mobile prover builds the circuit for every proof. With *Witness*, this is the holder's cost.
- **Verify** (`bb verify`): checks the proof against the verification key and the public inputs. This is the verifier's cost.

*Gates* is the `circuit_size` of `bb gates`. Its meaning depends on the Barretenberg version (bb 6 counts a block of about 15,300 rows whenever SHA-256 is used, which bb 0.84 did not), so gates are comparable only within one toolchain. The prover pads the circuit to a power of two, so circuits in the same power of two take similar times.

| Circuit | Gates | ACIR opcodes | Witness | Build | Prove | Prove median | Verify |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| base/age | 3,222 | 311 | 161.2 ± 2.1 | 8.5 ± 0.2 | 54.8 ± 1.6 | 54.4 | 11.5 ± 0.1 |
| base/rental | 13,605 | 5,854 | 178.3 ± 1.4 | 15.8 ± 0.1 | 118.7 ± 1.1 | 118.5 | 12.2 ± 0.1 |
| base/residence | 3,269 | 281 | 159.7 ± 2.0 | 8.2 ± 0.1 | 55.1 ± 0.6 | 54.9 | 11.6 ± 0.1 |
| base/veteran | 2,935 | 56 | 159.9 ± 1.9 | 8.3 ± 0.3 | 54.1 ± 2.1 | 53.1 | 11.8 ± 0.6 |
| sha256-iso/age | 33,944 | 2,343 | 170.0 ± 2.4 | 23.8 ± 0.2 | 218.4 ± 8.2 | 215.5 | 12.7 ± 0.4 |
| sha256-iso/rental | 61,825 | 14,306 | 203.1 ± 1.0 | 56.0 ± 1.1 | 397.7 ± 9.4 | 395.4 | 12.5 ± 0.1 |
| sha256-iso/residence | 33,944 | 2,333 | 171.2 ± 4.4 | 23.6 ± 0.1 | 216.2 ± 3.9 | 215.1 | 12.4 ± 0.1 |
| sha256-iso/veteran | 33,944 | 2,054 | 167.9 ± 1.2 | 23.3 ± 0.1 | 217.4 ± 10.2 | 213.0 | 12.5 ± 0.3 |
| sha512-iso/age | 47,128 | 27,593 | 380.0 ± 1.7 | 45.8 ± 1.3 | 316.4 ± 4.5 | 316.8 | 12.6 ± 0.3 |
| sha512-iso/rental | 119,500 | 77,205 | 735.5 ± 6.2 | 115.9 ± 2.8 | 710.6 ± 37.1 | 696.2 | 13.1 ± 0.4 |
| sha512-iso/residence | 47,247 | 27,584 | 382.0 ± 7.6 | 45.6 ± 1.3 | 317.2 ± 5.6 | 316.3 | 12.6 ± 0.5 |
| sha512-iso/veteran | 46,791 | 27,304 | 378.4 ± 4.2 | 45.7 ± 1.9 | 322.9 ± 38.5 | 312.3 | 12.5 ± 0.3 |
| poseidon-iso/age | 14,594 | 4,638 | 227.6 ± 2.1 | 23.4 ± 0.3 | 142.3 ± 1.2 | 141.8 | 12.3 ± 0.1 |
| poseidon-iso/rental | 30,760 | 14,357 | 259.1 ± 3.7 | 36.0 ± 1.1 | 228.3 ± 2.6 | 227.7 | 12.5 ± 0.4 |
| poseidon-iso/residence | 14,687 | 4,628 | 229.5 ± 4.1 | 23.9 ± 1.3 | 142.5 ± 0.9 | 142.2 | 12.4 ± 0.1 |
| poseidon-iso/veteran | 14,258 | 4,349 | 227.7 ± 4.1 | 23.1 ± 0.2 | 140.6 ± 1.2 | 140.1 | 12.4 ± 0.3 |
| longfellow/age | 332,638 | 41,298 | 369.2 ± 5.7 | 291.8 ± 7.9 | 1814.6 ± 77.2 | 1786.6 | 14.2 ± 0.7 |
| longfellow/rental | 373,416 | 53,222 | 404.3 ± 2.3 | 321.4 ± 6.7 | 2054.4 ± 254.3 | 1963.7 | 14.1 ± 0.7 |
| longfellow/residence | 332,581 | 41,288 | 371.3 ± 6.2 | 290.2 ± 2.4 | 1778.5 ± 30.1 | 1772.5 | 14.0 ± 0.7 |
| longfellow/veteran | 332,333 | 41,032 | 370.1 ± 5.9 | 290.3 ± 2.3 | 1771.8 ± 36.5 | 1762.7 | 14.1 ± 0.7 |
| vega/age | 264,766 | 15,889 | 201.4 ± 2.8 | 196.3 ± 2.3 | 1420.0 ± 20.9 | 1417.9 | 13.3 ± 0.7 |
| vega/rental | 316,365 | 31,696 | 243.5 ± 3.0 | 230.9 ± 2.2 | 1666.3 ± 25.5 | 1671.2 | 13.6 ± 0.7 |
| vega/residence | 264,809 | 15,973 | 200.8 ± 1.8 | 196.0 ± 2.9 | 1420.1 ± 22.3 | 1412.3 | 13.4 ± 0.7 |
| vega/veteran | 264,530 | 15,694 | 200.1 ± 1.2 | 195.7 ± 4.1 | 1418.8 ± 31.9 | 1416.4 | 13.1 ± 0.6 |

## Every variant vs base (the cost of authentication)

Prove ms are means; the ratios are of the means and of the medians.

| Comparison | Scenario | Gates (ref) | Gates | Gates ratio | Prove ms (ref) | Prove ms | Prove ratio | Prove ratio (median) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| sha256-iso vs base | age | 3,222 | 33,944 | 10.54x | 55 | 218 | 3.98x | 3.96x |
| sha256-iso vs base | rental | 13,605 | 61,825 | 4.54x | 119 | 398 | 3.35x | 3.34x |
| sha256-iso vs base | residence | 3,269 | 33,944 | 10.38x | 55 | 216 | 3.93x | 3.92x |
| sha256-iso vs base | veteran | 2,935 | 33,944 | 11.57x | 54 | 217 | 4.02x | 4.01x |
| sha512-iso vs base | age | 3,222 | 47,128 | 14.63x | 55 | 316 | 5.77x | 5.83x |
| sha512-iso vs base | rental | 13,605 | 119,500 | 8.78x | 119 | 711 | 5.99x | 5.88x |
| sha512-iso vs base | residence | 3,269 | 47,247 | 14.45x | 55 | 317 | 5.76x | 5.76x |
| sha512-iso vs base | veteran | 2,935 | 46,791 | 15.94x | 54 | 323 | 5.97x | 5.88x |
| poseidon-iso vs base | age | 3,222 | 14,594 | 4.53x | 55 | 142 | 2.60x | 2.61x |
| poseidon-iso vs base | rental | 13,605 | 30,760 | 2.26x | 119 | 228 | 1.92x | 1.92x |
| poseidon-iso vs base | residence | 3,269 | 14,687 | 4.49x | 55 | 142 | 2.59x | 2.59x |
| poseidon-iso vs base | veteran | 2,935 | 14,258 | 4.86x | 54 | 141 | 2.60x | 2.64x |
| longfellow vs base | age | 3,222 | 332,638 | 103.24x | 55 | 1815 | 33.09x | 32.87x |
| longfellow vs base | rental | 13,605 | 373,416 | 27.45x | 119 | 2054 | 17.31x | 16.58x |
| longfellow vs base | residence | 3,269 | 332,581 | 101.74x | 55 | 1778 | 32.30x | 32.26x |
| longfellow vs base | veteran | 2,935 | 332,333 | 113.23x | 54 | 1772 | 32.77x | 33.20x |
| vega vs base | age | 3,222 | 264,766 | 82.17x | 55 | 1420 | 25.89x | 26.08x |
| vega vs base | rental | 13,605 | 316,365 | 23.25x | 119 | 1666 | 14.04x | 14.11x |
| vega vs base | residence | 3,269 | 264,809 | 81.01x | 55 | 1420 | 25.79x | 25.70x |
| vega vs base | veteran | 2,935 | 264,530 | 90.13x | 54 | 1419 | 26.25x | 26.68x |

## Longfellow vs the ISO-compliant digests

Prove ms are means; the ratios are of the means and of the medians.

| Comparison | Scenario | Gates (ref) | Gates | Gates ratio | Prove ms (ref) | Prove ms | Prove ratio | Prove ratio (median) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| longfellow vs sha256-iso | age | 33,944 | 332,638 | 9.80x | 218 | 1815 | 8.31x | 8.29x |
| longfellow vs sha256-iso | rental | 61,825 | 373,416 | 6.04x | 398 | 2054 | 5.17x | 4.97x |
| longfellow vs sha256-iso | residence | 33,944 | 332,581 | 9.80x | 216 | 1778 | 8.23x | 8.24x |
| longfellow vs sha256-iso | veteran | 33,944 | 332,333 | 9.79x | 217 | 1772 | 8.15x | 8.28x |
| longfellow vs sha512-iso | age | 47,128 | 332,638 | 7.06x | 316 | 1815 | 5.74x | 5.64x |
| longfellow vs sha512-iso | rental | 119,500 | 373,416 | 3.12x | 711 | 2054 | 2.89x | 2.82x |
| longfellow vs sha512-iso | residence | 47,247 | 332,581 | 7.04x | 317 | 1778 | 5.61x | 5.60x |
| longfellow vs sha512-iso | veteran | 46,791 | 332,333 | 7.10x | 323 | 1772 | 5.49x | 5.64x |

## VegaSC vs Longfellow and sha256-iso

Prove ms are means; the ratios are of the means and of the medians.

| Comparison | Scenario | Gates (ref) | Gates | Gates ratio | Prove ms (ref) | Prove ms | Prove ratio | Prove ratio (median) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| vega vs longfellow | age | 332,638 | 264,766 | 0.80x | 1815 | 1420 | 0.78x | 0.79x |
| vega vs longfellow | rental | 373,416 | 316,365 | 0.85x | 2054 | 1666 | 0.81x | 0.85x |
| vega vs longfellow | residence | 332,581 | 264,809 | 0.80x | 1778 | 1420 | 0.80x | 0.80x |
| vega vs longfellow | veteran | 332,333 | 264,530 | 0.80x | 1772 | 1419 | 0.80x | 0.80x |
| vega vs sha256-iso | age | 33,944 | 264,766 | 7.80x | 218 | 1420 | 6.50x | 6.58x |
| vega vs sha256-iso | rental | 61,825 | 316,365 | 5.12x | 398 | 1666 | 4.19x | 4.23x |
| vega vs sha256-iso | residence | 33,944 | 264,809 | 7.80x | 216 | 1420 | 6.57x | 6.57x |
| vega vs sha256-iso | veteran | 33,944 | 264,530 | 7.79x | 217 | 1419 | 6.53x | 6.65x |
