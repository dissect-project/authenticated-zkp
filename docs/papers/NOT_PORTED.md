# Why Crescent and VegaMC are not ported

Each variant in this repository ports the **relation** a paper proves, as a single Noir circuit
proven with UltraHonk. All variants share one backend, so a comparison between them measures their
relations only. A scheme fits this approach when its relation can be written as one circuit and
its contribution does not depend on its own proof system.

- **Longfellow** (`longfellow.pdf`) is ported in `implementations/longfellow`.
- **VegaSC** (`vega.pdf`, Fig. 9a) is ported in `implementations/vega`.
- **Crescent** (`crescent.pdf`) and **VegaMC** (`vega.pdf`, §4.2) are not ported, for the reasons
  below.

## Crescent

Crescent is not one relation proven once. It is a pipeline of several proof systems:

1. **Prepare.** One expensive Groth16 proof per credential. The circuit verifies the credential
   (for mDL: SHA-256, ECDSA P-256 with emulated arithmetic, about 2.6M R1CS constraints) and
   outputs the attributes. The attributes are exposed through a Pedersen vector commitment
   (LegoSNARK style).
2. **Show.** For each presentation, the Groth16 proof is rerandomized and the commitment is
   reused. Predicates are proven over the committed attributes outside the circuit:
   - Σ-proofs of knowledge of the committed values;
   - BFGW range proofs, for example that the credential is not expired or that age > 18;
   - DLEQ proofs that bind the session data.
3. **Device binding.** A separate sub-prover proves the ECDSA signature with Spartan over T-256.
   It is linked to the Groth16 commitment through commitments to the device key.

These pieces do not translate to Noir and UltraHonk:

- **Unlinkability.** Crescent gets it from rerandomizing Groth16 proofs, and UltraHonk proofs
  cannot be rerandomized. A Noir version would produce a fresh proof per presentation, which is
  just a credential-verification circuit plus a predicate. That is the relation every variant here
  already proves, not Crescent.
- **Commitment interfaces.** The Show predicates and the device-binding proof are proven over
  Pedersen commitments, with Σ-protocols and range proofs outside the circuit. Inside one circuit
  they would turn into ordinary constraints, and Crescent's design (a committed-input interface
  between sub-provers) would disappear.
- **Device binding.** Its efficiency comes from choosing the curve, T-256, so that P-256
  arithmetic is native. Over BN254 that choice does not exist.

In short, almost all of Crescent's contribution is in the proof systems and how they are
connected. Its circuit is a standard verification of the credential, which the other variants
already cover. A "Crescent" variant here would not match what the paper presents, so we cite
Crescent's own measurements (Crescent §5; Vega Fig. 10) instead of porting it.

## VegaMC

VegaMC proves **the same relation** as VegaSC: field extraction, `validUntil`, the item digest,
the predicate and the two ECDSA signatures. The two variants differ only in arithmetization and
backend (Vega §2, §4.2, Figs. 2, 4, 5):

| | VegaSC | VegaMC |
|---|---|---|
| SHA-256 over the MSO | Unrolled in one circuit (Fig. 3) | ℓ step circuits, each one compression at a public index (Fig. 4), plus a binding gadget in the core circuit (Fig. 5) |
| Connecting circuits | Not needed | Blocks and intermediate digests are stored in a witness segment shared through Hyrax commitments (split-committed R1CS) |
| Proving | SplitSpartan | The step instances are folded with SplitNeutronNova, then the folded step and the core are proven with SplitSpartan |

Its gains in Vega Fig. 10 (1920-byte MSO, 1 thread) are these:

| | VegaSC | VegaMC |
|---|---|---|
| Setup | 726 ms | 210 ms |
| Online prove | 325 ms | 237 ms |
| Verify | 127 ms | 57 ms |
| Proving and verifying keys | 6588 kB | 464 kB |

All of these gains come from **folding**: only one step circuit is set up, committed to and proven,
whatever the number of blocks. None of this carries over:

- **Nothing new to port.** The relation is identical, so `implementations/vega` already
  represents both variants at the level this repository compares.
- **UltraHonk has no folding.** In Noir there are two options:
  - Unroll SHA-256 in one circuit, which is exactly VegaSC.
  - Prove each block separately and aggregate the proofs with recursive verification. Each
    aggregation step verifies an UltraHonk proof inside a circuit, which costs far more than the
    single compression it replaces. This would be slower than VegaSC, the opposite of the paper's
    result.
- **No shared witness segment.** The circuits would have to agree on the blocks and digests some
  other way:
  - as public inputs, which reveals the MSO length and breaks length hiding;
  - or through an in-circuit hash commitment, which adds cost.
- **The setup and key-size gains are Spartan-specific.** UltraHonk uses a universal setup, and
  computing a verification key is already cheap, so VegaMC's 92% setup reduction has nothing to
  improve here.

VegaMC is therefore treated as VegaSC's relation with a folding backend. When its figures are
needed, they are cited from Vega Fig. 10. See also `implementations/vega/README.md`, "Departures
that come from the backend".
