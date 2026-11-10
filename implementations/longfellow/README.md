# Longfellow port

A Noir port of the mdoc presentation relation of Longfellow-zk (Frigo & shelat, *Anonymous
Credentials from ECDSA*, IACR CiC 3(1), Algorithm 10), proven with UltraHonk like every other
variant in this repository. What is ported is the **relation** the paper proves, not its proof
system. `../../docs/papers/PORTED.md` covers both ports and every departure in detail.

```
longfellow/
├── lib/src/lib.nr      # verify_mdoc: SHA-256, in-circuit CBOR parsing, ECDSA (Algorithm 10)
├── age/ int/ nationality/ str/
│   ├── src/main.nr     # verify_mdoc + the scenario predicate
│   ├── Prover.toml
│   └── inputs_longfellow_*.dart
├── generate.py         # builds a signed credential and writes Prover.toml / Dart inputs
└── test_soundness.py   # attacks the circuit must reject
```

## Relation (Algorithm 10)

Public inputs:

- the issuer key `PK_issuer`;
- the `elementIdentifier`;
- the CBOR-encoded `SessionTranscript` `tr`;
- `now`;
- the predicate's public input.

Private inputs:

- the issuer-signed bytes and their length;
- both signatures;
- the item fields;
- the offset of each MSO field;
- the device-signed message.

| Step | `lib/src/lib.nr` |
|---|---|
| `e1 = SHA256(MSO)`, `p256.verify(sig_issuer, e1, PK_issuer)` | SHA-256 over the COSE `Sig_structure` of the MSO (at most 2231 bytes, 35 blocks) and the issuer's signature |
| MSO parsing (§4.3) | Every token of the MSO with its parent container and key/value position; the MSO must be one CBOR map ending at the signed length |
| `h2 = MSO[valueDigests][org.iso.18013.5.1][digestID]` | The namespace is a key of `MSO[valueDigests]`. The digest entry is a key of that namespace's map, its key is the item's `digestID`, and its value is a 32-byte bstr. |
| `h2 = SHA256(item)` | `IssuerSignedItemBytes(digestID, random, elementIdentifier, elementValue)`, built and hashed with `../../iso/lib` |
| `(pk_dx, pk_dy) = MSO[deviceKeyInfo][deviceKey][-2, -3]` | `deviceKey` is a key of `MSO[deviceKeyInfo]`; the coordinates are read from its COSE key |
| `validFrom < now < validUntil` | Both are keys of `MSO[validityInfo]` |
| `p256.verify(sig_device, H(tr ‖ hdr), (pk_dx, pk_dy))` | The device-signed `Sig_structure(DeviceAuthenticationBytes)` is rebuilt around the public `tr` |

The circuit also checks that `docType = org.iso.18013.5.1.mDL` and `digestAlgorithm = SHA-256`
are top-level MSO keys. Every field must lie inside the hashed bytes.

## Parsing

The paper parses the MSO in the circuit: a tokenizer marks every token start (Algorithm 6), and
tree addresses locate each token (Algorithm 8). The port computes the same information in a way
that suits UltraHonk:

- **Tokenizer.** Starting at the MSO, the circuit reads each token's head byte, computes its
  length from lookup tables, and jumps to the next token, until it reaches the signed length.
  A field offset is valid only if it is one of the token starts, which an unconstrained hint
  finds and the circuit checks.
- **Positions.** A stack of open containers (children left, offset) gives each token its parent
  and whether it is a map key. A container that is the last child of its parent replaces the
  parent on the stack, so four entries suffice for any standard MSO.
- **Paths.** A path such as `MSO[validityInfo][validUntil]` holds when all of the following do:
  - the `validUntil` key's parent is a map;
  - the token just before that map is the key `validityInfo`;
  - that key's parent is the MSO's root map;
  - both tokens are keys.

The parse is bounded by 256 tokens; the test MSOs have about 130. Walking per token rather than
per byte keeps the circuit at 440k gates for `int`, 34k fewer than the earlier per-byte tokenizer,
which did not track positions.

## Departures

The port departs from the paper in two ways:

- **Backend.** UltraHonk over BN254 replaces the paper's sumcheck + Ligero with two fields; ECDSA
  uses Noir's P-256 black box; the parser walks tokens instead of using parallel-prefix scans.
- **Relation.** The attribute value stays private behind a predicate, whereas Algorithm 10
  discloses it. The item preimage is ISO's `IssuerSignedItemBytes`.

See `PORTED.md` for both.

## Usage

```
python3 generate.py int 7 5             # age_in_years = 7, proven > 5
python3 generate.py age 01/01/2000 21/07/2025 18
python3 generate.py nationality PT,ES,--,--,-- PT
python3 generate.py str "<57-byte address>" "<10 bytes>"
# --dart FILE RUN also appends the inputs to a Dart inputs list
```

## Soundness tests

`python3 test_soundness.py` builds fresh credentials and checks that the circuit rejects:

- an attribute digest, a device key or a `validUntil` appended after the signed bytes;
- an item whose `digestID` differs from the MSO entry it points to;
- fields at the right bytes but the wrong path. The issuer signs, under another top-level map
  (`status`), an attribute digest under a key `org.iso.18013.5.1`, a later `validUntil`, or the
  attacker's `deviceKey`. With the path checks removed, the circuit accepts all three.

It also checks that an MSO with a 2-byte-length string is accepted.
`../vega/test_soundness.py` runs this circuit too, on the witnesses that break Vega's
well-formedness assumption. VegaSC accepts them; this circuit rejects them.
