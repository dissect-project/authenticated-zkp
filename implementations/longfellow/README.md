# Longfellow (Noir port)

Noir/UltraHonk re-implementation of the mdoc presentation circuit of Longfellow-zk
(M. Frigo, a. shelat, *Anonymous Credentials from ECDSA*, IACR Communications in Cryptology 3(1), 2025,
Algorithm 10), used as the "verify the issuer signature in-circuit" baseline against the
authenticated witness binding variants (`sha256`, `sha512`, `poseidon`).

Only the proof statement is ported: the original runs on Ligero + sumcheck with SHA-256 checked over
GF(2^128), while this version uses the same Noir + Barretenberg (UltraHonk) stack as the other
variants, so the comparison isolates the cost of *what* is proven.

## Layout

```
longfellow/
├── lib/            # Noir library with the shared mdoc verification (verify_mdoc)
├── int/            # same scenarios and predicates as the sha256 variant
├── age/
├── nationality/
├── str/
│   ├── src/main.nr                  # encodes elementValue, calls verify_mdoc, checks the predicate
│   ├── Prover.toml                  # inputs of run 1
│   ├── inputs_longfellow_<s>.dart   # the four runs of the primary scenario, for the testing app
│   └── target/
├── generate.py     # builds a credential and writes Prover.toml for any scenario
└── test_soundness.py  # attacks the circuit must reject (run on the int scenario)
```

## Statement (`lib/src/lib.nr`)

Public: issuer key `PK_I`, the CBOR-encoded `SessionTranscript` `tr` (≤ 256 bytes), `now`,
`elementIdentifier` and the scenario's public predicate input.
Private: everything else, including the attribute value, the whole MSO, the device key and `hdr`,
the COSE framing around `tr` in the device-signed message.

**Inputs are CBOR where the mdoc uses CBOR, as in the ISO variants (`../iso`):**
- **Item fields:** the attribute, `digestID` and `random`, as they appear in the issuer's item.
- **Other inputs:**
  - `now`, as a `tdate`: `C0 74 <YYYY-MM-DDTHH:MM:SSZ>`;
  - the `elementIdentifier`, as a text string;
  - the scenario's public input.
- **Not CBOR:**
  - the issuer key, which verifiers get from the X.509 certificate;
  - the signatures, which COSE also stores as raw `r‖s`;
  - the parser offsets and lengths, which are hints rather than data.

The item is built and hashed by the same code as the ISO variants
(`sha256_item_digest` in `../iso/lib`), so both approaches handle the attribute identically.
Unlike the authenticated witness binding construction, Longfellow's statement has no private
copies of the public inputs, and none were added.

| Step | Check | Cost (gates) |
|------|-------|--------------|
| 1 | `Sig_structure` / tag-24 wrapper of the MSO and its length fields | – |
| 2 | `e1 = SHA256(Sig_structure)`, variable length, ≤ 2231 bytes (35 blocks, as in the paper) and `p256.verify(σ_I, e1, PK_I)` | ~209k + ~71k |
| 3 | CBOR tokenization of the MSO (token starts + text-string counts); every field used below must lie within the signed bytes | ~83k |
| 4 | `h2 = MSO[valueDigests][org.iso.18013.5.1][digestID]`, where the entry's key and the item's `digestID` have the same value | small |
| 5 | `h2 = SHA256(IssuerSignedItemBytes(digestID, random, elementIdentifier, elementValue))`, from the CBOR-encoded fields | ~6–12k |
| 6 | `(dpk_x, dpk_y) = MSO[deviceKeyInfo][deviceKey][-2,-3]`, `docType`, `digestAlgorithm` | small |
| 7 | `validFrom < now < validUntil` | small |
| 8 | `e2 = SHA256(tr ‖ hdr)`, i.e. `Sig_structure(DeviceAuthenticationBytes)` with `DeviceAuthentication = ["DeviceAuthentication", tr, docType, DeviceNameSpacesBytes]`, ≤ 329 bytes | ~42k |
| 8 | `p256.verify(σ_D, e2, (dpk_x, dpk_y))` with the device key hidden | ~71k |
| 9 | Scenario predicate, identical to the `sha256` variant | small |

## Scenarios

| Scenario | `elementIdentifier` | `elementValue` (private, CBOR) | Public input (CBOR) and predicate | Gates | `sha256-iso` gates |
|----------|---------------------|--------------------------------|-----------------------------------|-------|--------------------|
| `int` | `age_in_years` | `x_cbor`: unsigned integer (any `u64`, any encoding) | `y_cbor`; `x > y` | 474,122 | 12,838 |
| `age` | `birth_date` | `dob_cbor`: full-date `1004("YYYY-MM-DD")` | `age_cbor`; age at the date of `now` ≥ `age` | 474,210 | 12,979 |
| `nationality` | `nationality` | `list_cbor`: array of 1 to 5 two-letter text strings | `nationality_cbor`; it is in the list | 474,196 | 12,812 |
| `str` | `resident_address` | `x_cbor`: 57-byte text string | `y_cbor`; `x` contains `y` | 480,460 | 19,065 |

Gate counts from `bb gates` with nargo 1.0.0-beta.7 and bb 0.84.0. Proofs are 14,080 bytes, as for
every other variant. `age` takes today's date from `now` instead of a separate input.
`nationality` follows the EU PID, where the element is an array of codes, as in the ISO variants;
the mDL element is a single text string. `tests/comparison.py` compares every scenario with
the ISO-compliant `sha256-iso` and `sha512-iso` versions (see `../iso/README.md`).

Differences from the original, all of which keep the comparison in Longfellow's favour or neutral:

- The attribute is hidden and the scenario predicate is evaluated on it, instead of disclosing `Z`.
- CBOR is not fully parsed into a tree (the paper reconstructs tree addresses, its Algorithm 8).
  The prover supplies the byte offsets of the fields; the circuit tokenizes the MSO to prove each
  offset is a genuine token start (not bytes inside a string) within the issuer-signed bytes, and
  proves the digest entry lies in the `org.iso.18013.5.1` map because no text-string token occurs
  between the namespace key and the entry. This relies on the issuer producing a well-formed MSO
  in which these keys only occur at their usual place, which holds for ISO 18013-5 MSOs.
- **`random` length:** it is 16 bytes, as in the ISO variants and the paper's Appendix A example,
  while Algorithm 10 mentions a 32-byte nonce. ISO 18013-5 only requires at least 16 bytes. A
  32-byte `random` would add up to one SHA-256 block (a few thousand gates, under 1%).
- **Fixed layouts:** COSE_Key encoded as `{1, -1, -2, -3}`, `tdate` without fractional seconds,
  and `IssuerSignedItem` fields in the ISO 18013-5 example order. `digestID` may be any unsigned
  integer in any encoding.
- Barretenberg's P-256 verifier expects low-s signatures; the prover normalises `s → n − s`, which
  any holder can do.

## Soundness tests

`python3 test_soundness.py` builds fresh credentials and checks, on the `int` scenario, that the
circuit accepts an honest one and rejects:

- a forged attribute digest;
- the attacker's own device key;
- a later `validUntil`;
- an item `digestID` that differs from the key of the MSO entry it points to.

In the first three attacks the forged field is written after the issuer-signed bytes. Those bytes are a
private witness that the issuer signature does not cover, so every field offset must be bounded
by `signed_len`.

It also checks that an MSO holding a string of 256 bytes or more (a 2-byte CBOR length) is
tokenized correctly. An earlier version of the circuit accepted the three attacks and
mis-measured long strings.

## Usage

```sh
./generate.py int 45 25                       # writes int/Prover.toml
./generate.py age 16/08/1999 24/07/2025 25    # date of birth, today, minimum age
./generate.py nationality PT,EN,--,--,-- EN
./generate.py str "42 Fictional Way, Smithfield, Dublin 7, D07 F4K3, Ireland" "Smithfield"
cd int
nargo execute
bb write_vk -b target/int.json -o target
bb prove -b target/int.json -w target/int.gz -o target
bb verify -k target/vk -p target/proof -i target/public_inputs
```

`generate.py` (needs `cbor2` and `cryptography`) creates fresh issuer and device keys, an mDL MSO with
two namespaces (≈ 2 kB signed, about 33 + 14 digests), and the device signature over a dummy
session. `--digest-id N` fixes the digestID, `--out FILE` writes elsewhere, and `--dart FILE RUN`
also adds the flattened inputs to a Dart inputs list in the format of the testing application.
