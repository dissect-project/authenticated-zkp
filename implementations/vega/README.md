# VegaSC port

A Noir port of the single-circuit mdoc relation of Vega (Kaviani & Setty, *Vega: Low-Latency
Zero-Knowledge Proofs over Existing Credentials*, IEEE S&P 2026; IACR ePrint 2025/2094), proven
with UltraHonk like every other variant in this repository. As with the Longfellow port
(`../longfellow`), what is ported is the **relation** the paper proves, not its proof system.

```
vega/
├── lib/src/lib.nr      # SHA256_SC (Fig. 3), ExtractFields (Fig. 7), verify_mdoc (Fig. 9a)
├── age/ int/ nationality/ str/
│   ├── src/main.nr     # verify_mdoc + the scenario predicate
│   ├── Prover.toml
│   └── inputs_vega_*.dart
├── generate.py         # Vega inputs from the Longfellow inputs (same credentials)
└── test_soundness.py   # attacks the circuit must reject, and Vega's parsing assumption
```

## Relation (Figure 9a)

Public: issuer key `Q_I`, device digest `H_dev`, today's date, the `elementIdentifier` and the
predicate's public input. Private: the issuer-signed bytes, `(addr, vals)`, the one-hot selectors,
both signatures and the item fields.

| Step | Paper | `lib/src/lib.nr` |
|---|---|---|
| 1 | `ExtractFields(MSO, addr, vals)`: lookup, prefix, contiguity (Fig. 7) | `extract_fields`: `signed[addr[i]] == vals[i]` with `addr[i] < len` (UltraHonk ROM lookups), prefixes of Fig. 8, consecutive addresses per field |
| 2 | `(Y, M, D) < validUntil` | `full_date_to_u64(today) < tdate_to_u64(validUntil)`, today taken as midnight |
| 3 | `SHA256_SC(preimage) = MSO[valueDigests][ns][birth_date]` | `item_digest` (SHA256_SC over IssuerSignedItemBytes) `==` the digest extracted in step 1 |
| 4 | `age ≥ τ` | in `age/src/main.nr`; `int`, `nationality` and `str` use the repository's other predicates |
| 5 | `H_MSO ← SHA256_SC(MSO)` | `sha256_sc(signed, signed_len, b_mso)`: 35 compressions, padding checked at `d = Σ j·b_j`, digest `Σ b_j H_{j+1}` |
| 6 | `ECDSAVerify` with `Q_I` and with the extracted device key over `H_dev` | `std::ecdsa_secp256r1::verify_signature`, twice |

Like the paper, the circuit does not parse the MSO as CBOR and checks neither `validFrom`,
`docType` nor `digestAlgorithm`.

## Same credentials as Longfellow

`generate.py` reads `../longfellow/SCENARIO/Prover.toml` and every run of
`../longfellow/SCENARIO/inputs_longfellow_SCENARIO.dart`, and derives the Vega inputs from the same
issuer-signed bytes, issuer signature, item and device signature. The size bound is the same:
35 SHA-256 blocks, so at most 2231 signed bytes. Vega's device signs a public digest (the paper's
mock device signs a verifier nonce). Here `H_dev` is the SHA-256 of the device-signed
`Sig_structure(DeviceAuthenticationBytes)` of the Longfellow credential. The verifier, who knows
the session, computes it outside the circuit, while Longfellow rebuilds it inside the circuit.

```
python3 generate.py SCENARIO --dart     # SCENARIO in int, age, nationality, str
```

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
  `elementIdentifier` in another namespace.
- **Item preimage.** The paper hashes a "DOB preimage" without saying how it is tied to
  `birth_date` or how the date is read from it. The item is built from its CBOR-encoded fields with
  `../../iso/lib`, as in every other variant, which fixes the `elementIdentifier` and the value,
  and is then hashed with `SHA256_SC`.
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

`python3 test_soundness.py` builds fresh credentials and checks that the circuit rejects:

- fields read after the hashed message;
- a mismatched digestID;
- lookups that differ from the MSO;
- spliced bytes;
- a field read at the wrong prefix;
- a wrong, shifted or non-binary block selector;
- a wrong message length;
- an expired credential.

It also checks that an MSO with a 2-byte-length string is accepted.

The last two tests document **Vega's well-formedness assumption** (§5): the issuer signs
well-formed MSOs in which every field prefix is unique. Suppose an issuer-signed byte string
contains the bytes of a `validUntil` or `deviceKey` field. The VegaSC relation **accepts** the
forged field, so an expired credential is presented as valid, or a copied credential with the
attacker's device key. On the same witness, the Longfellow port **rejects** it, because its
tokenizer requires each field to start a CBOR token. The attack needs the issuer to sign such
bytes; it is not a bug in the port but the cost of skipping CBOR parsing.
