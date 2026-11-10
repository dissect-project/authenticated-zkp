# VegaSC port

A Noir port of the single-circuit mdoc relation of Vega (Kaviani & Setty, *Vega: Low-Latency
Zero-Knowledge Proofs over Existing Credentials*, IEEE S&P 2026; IACR ePrint 2025/2094), proven
with UltraHonk like every other variant in this repository. As with the Longfellow port
(`../longfellow`), what is ported is the **relation** the paper proves, not its proof system.

```
vega/
├── lib/src/lib.nr      # SHA256_SC (Fig. 3), ExtractFields (Fig. 7), verify_mdoc (Fig. 9a)
├── age/ rental/ residence/ veteran/
│   ├── src/main.nr     # verify_mdoc + the scenario predicate
│   ├── Prover.toml
│   └── inputs_vega_*.dart
└── test_soundness.py   # attacks the circuit must reject, and Vega's parsing assumption
```

## Relation (Figure 9a)

Public: issuer key `Q_I`, device digest `H_dev`, today's date, the `elementIdentifier` and the
predicate's public inputs. Private: the issuer-signed bytes, `(addr, vals)`, the one-hot
selectors, both signatures and the `IssuerSignedItemBytes` as issued.

| Step | Paper | `lib/src/lib.nr` |
|---|---|---|
| 1 | `ExtractFields(MSO, addr, vals)`: lookup, prefix, contiguity (Fig. 7) | `extract_fields`: `signed[addr[i]] == vals[i]` with `addr[i] < len` (UltraHonk ROM lookups), prefixes of Fig. 8, consecutive addresses per field |
| 2 | `(Y, M, D) < validUntil` | `full_date_to_u64(today) < tdate_to_u64(validUntil)`, today taken as midnight |
| 3 | `SHA256_SC(preimage) = MSO[valueDigests][ns][birth_date]` | `item_digest` (SHA256_SC over IssuerSignedItemBytes, parsed as issued) `==` the digest extracted in step 1 |
| 4 | `age ≥ τ` | the scenario predicate, on the `elementValue` of the item (`../iso/common/lib/src/predicates.nr`, shared by every variant) |
| 5 | `H_MSO ← SHA256_SC(MSO)` | `sha256_sc(signed, signed_len, b_mso)`: 35 compressions, padding checked at `d = Σ j·b_j`, digest `Σ b_j H_{j+1}` |
| 6 | `ECDSAVerify` with `Q_I` and with the extracted device key over `H_dev` | `std::ecdsa_secp256r1::verify_signature`, twice |

Like the paper, the circuit does not parse the MSO as CBOR and checks neither `validFrom`,
`docType` nor `digestAlgorithm`.

## Same credentials as Longfellow

The inputs come from the mDLs issued by pyMDOC-CBOR in `../../credentials`, the same credentials,
issuer signatures, items and device signatures as the Longfellow port
(`credentials/generate.py vega`). The size bound is the same: 35 SHA-256 blocks, so at most 2231
signed bytes (the test credentials have 1559 to 1595). Vega's device signs a public digest (the
paper's mock device signs a verifier nonce). Here `H_dev` is the SHA-256 of the device-signed
`Sig_structure(DeviceAuthenticationBytes)` of the in-person session. The verifier, who knows the
session, computes it outside the circuit, while Longfellow rebuilds it inside the circuit.

## Choices the paper leaves open

Microsoft's public repository (`github.com/Microsoft/vega-prover`) contains the proof system and a
plain SHA-256 benchmark, but not the mDL circuit, so these follow the paper and ISO/IEC 18013-5:

- **Signed message.** Fig. 9a hashes "the MSO". The issuer's ECDSA signature is over the COSE
  `Sig_structure` that wraps the MSO (ISO/IEC 18013-5, RFC 9052), so that is what `SHA256_SC`
  hashes. The Longfellow port hashes the same bytes.
- **Digest entry.** Step 3 reads `MSO[valueDigests][org.iso.18013.5.1][birth_date]`, and §5.1.1
  says the digest is extracted "using the same lookup protocol". The entry is therefore a third
  Fig. 7 field, with prefix `<digestID> 58 20`, where the digestID must equal the item's.
  Fig. 7 checks no enclosing map, so **the namespace is not checked**. Binding the digest to the
  item still needs a SHA-256 preimage, so the remaining gap is an issuer-signed item with the same
  `elementIdentifier` in another namespace. (The `veteran` scenario reads an item of the AAMVA
  namespace; nothing in the circuit depends on which namespace that is.)
- **Item preimage.** The paper hashes a "DOB preimage" without saying how it is tied to
  `birth_date` or how the date is read from it. The preimage is the `IssuerSignedItemBytes` as
  issued, parsed with `../../iso/common/lib` as in every other variant (its four entries in any
  order, its `digestID` and `elementIdentifier`), and hashed with `SHA256_SC`. The predicate reads
  the `elementValue` from it.
- **Date.** The public date is a CBOR full-date (`D9 03 EC 6A YYYY-MM-DD`), like `birth_date`,
  compared as midnight against `validUntil`.

## Departures that come from the backend

1. **Proof system.** SplitSpartan, Succinct NovaBlindFold and Hyrax are replaced by UltraHonk. The
   relation is backend-agnostic, but timings measure UltraHonk.
2. **VegaMC is not ported.** It folds the SHA-256 steps with SplitNeutronNova, which a single Noir
   circuit cannot express. VegaSC is the paper's single-circuit variant.
3. **No precomputation.** UltraHonk cannot rerandomize and reuse witness commitments, so every
   timing is a full proof and is not comparable with Vega's "online" proving time.
4. **ECDSA.** Fig. 6 verifies `(r, s⁻¹)` with native arithmetic because Vega's circuit field is
   the P-256 base field (T-256). Over BN254 that advantage does not exist, so both signatures use
   Noir's P-256 black box, as in the Longfellow port. The relation (a valid ECDSA signature) is
   unchanged.

## Soundness tests

`../../credentials/.venv/bin/python test_soundness.py` takes the committed credentials, or issues
fresh ones with pyMDOC-CBOR, and checks that the circuit rejects:

- fields read after the hashed message;
- a mismatched digestID;
- lookups that differ from the MSO;
- spliced bytes;
- a field read at the wrong prefix;
- a wrong, shifted or non-binary block selector;
- a wrong message length;
- an expired credential.

It also checks that an MSO with a 2-byte-length string is accepted.

The last four tests document **Vega's well-formedness assumption** (§5): the issuer signs
well-formed MSOs in which every field prefix is unique. Each test has the issuer sign, under the
MSO's `status` entry, a forged `validUntil` or `deviceKey` field in one of two places:

- inside an issuer-signed byte string;
- in an issuer-signed map other than `validityInfo` or `deviceKeyInfo`.

The VegaSC relation **accepts** the forged field. An expired credential is then presented as
valid, or a copied credential with the attacker's device key. The Longfellow
port **rejects** the same credential, because it parses the MSO. In a byte string the forged field does not start a
CBOR token; in another map it is not at the path `MSO[validityInfo][validUntil]` or
`MSO[deviceKeyInfo][deviceKey]`. The attack needs the issuer to sign such bytes. It is not a bug in
the port but the cost of skipping CBOR parsing.
