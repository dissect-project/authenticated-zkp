# How Longfellow and VegaSC were ported

Two papers in this directory are ported to Noir:

- Longfellow (`longfellow.pdf`), in `implementations/longfellow`;
- VegaSC (`vega.pdf`), in `implementations/vega`.

The other variants (`base`, `sha256-iso`, `sha512-iso`, `poseidon-iso`) are this repository's
own designs and are not ports. For the papers that are not ported, see `NOT_PORTED.md`.

## Approach

Each port reproduces the **relation** the paper proves: what is public, what is private, and every
check the paper's circuit makes. It does not reproduce the paper's proof system. Every variant is
compiled to one Noir circuit and proven with UltraHonk (Barretenberg). Differences in gates
between variants therefore come from the relations alone. Proving time also depends on how Noir
compiles each relation (black-box functions or Noir code) and on the power of two the circuit is
padded to.

The ports share the following with the other ISO variants:

- **Item.** The `IssuerSignedItemBytes` is received as issued and parsed by
  `implementations/iso/common/lib`: its four entries in any order (the standard fixes no order),
  a `random` of 16 to 32 bytes, its `digestID` and `elementIdentifier`. It is hashed by the same
  code in every variant.
- **Predicates.** All variants run the same four mDL scenarios, with the predicates of
  `implementations/iso/common/lib/src/predicates.nr`:
  - `age`: `birth_date`, a full-date;
  - `rental`: `driving_privileges`, an array of maps, parsed in the circuit;
  - `residence`: `resident_postal_code`, a text string;
  - `veteran`: `veteran` in the AAMVA namespace, an unsigned integer.

  The value is private and only the predicate result is revealed.
- **Credentials.** Both ports run on the same credentials: four mDLs issued by pyMDOC-CBOR, an
  implementation independent of the circuits, with a test PKI. The device side of each in-person
  session is built by the test harness and signed with pycose. See `credentials/README.md`.

Below, each port lists two kinds of change:

- **backend departures**, forced by moving to UltraHonk; they do not change the relation;
- **relation choices**, where the paper is underspecified or where the port differs from the
  paper's statement.

---

## Longfellow (Frigo & shelat, *Anonymous Credentials from ECDSA*, Algorithm 10)

### What the paper proves

The public inputs are `(PK_issuer, attr, Z, tr, t_now)`. The private witness holds the MSO, its
length, the parsing witnesses, both signatures and the device key. The relation is:

```
e1 = SHA256(MSO[0:len])
h2 = MSO[valueDigests][org.iso.18013.5.1][X]
h2 = SHA256(nonce, attr, Z)
(pk_dx, pk_dy) = MSO[deviceKeyInfo][deviceKey][-2, -3]
t_start = MSO[validityInfo][validFrom],  t_end = MSO[validityInfo][validUntil]
t_start < t_now < t_end
p256.verify((r1, s1), e1, PK_issuer)
p256.verify((r2, s2), H(tr || hdr), (pk_dx, pk_dy))
```

### How it maps to `implementations/longfellow/lib/src/lib.nr`

| Algorithm 10 | Port |
|---|---|
| `e1 = SHA256(MSO[0:len])` | SHA-256 over the issuer-signed bytes, at most 2231 bytes (35 blocks, the bound in the paper's Table 13). The bytes hashed are the COSE `Sig_structure` around the MSO, since that is what the issuer's ECDSA signature covers. |
| Parsing witnesses `c` | An in-circuit CBOR parser (paper §4.3). The tokenizer finds every token start in the MSO (Algorithm 6). A stack of open containers gives each token its parent container and whether it is a map key or a value, which is the information in Algorithm 8's tree addresses. The MSO must be exactly one CBOR map that ends at `len`. |
| `h2 = MSO[valueDigests][ns][X]` | The namespace is a key of the map stored under the top-level key `valueDigests`. The digest key is a key of the namespace's map, decodes to the item's `digestID`, and is followed by a 32-byte bstr. |
| `h2 = SHA256(nonce, attr, Z)` | `SHA256(IssuerSignedItemBytes)` of the item as issued, parsed with the `iso` library (its `digestID` and `elementIdentifier` are checked, and the predicate reads its `elementValue`). |
| Device key, `validFrom`, `validUntil` | `deviceKey` is a key of `MSO[deviceKeyInfo]`, and `validFrom` and `validUntil` are keys of `MSO[validityInfo]`. Each key's bytes must match, and its value is read right after it. |
| `t_start < t_now < t_end` | Both bounds are checked against a public CBOR `tdate`. |
| Two `p256.verify` | Noir's `std::ecdsa_secp256r1::verify_signature`, twice. |
| `H(tr ‖ hdr)` | The device-signed `Sig_structure(DeviceAuthenticationBytes)` is rebuilt in the circuit around the public `tr`, and its framing `hdr` is checked. The docType is `org.iso.18013.5.1.mDL` and `DeviceNameSpaces` is empty. |

The port also checks that `docType` and `digestAlgorithm = "SHA-256"` are top-level MSO keys with
the expected values. Every field must lie inside the hashed bytes, because the bytes after `len` are
unsigned witness.

### Backend departures

1. **Proof system.** Longfellow uses sumcheck with Ligero and a two-field design:
   - SHA-256 is proven over GF(2^128);
   - ECDSA is proven over the P-256 base field;
   - a MAC links the two parts.

   The port is one UltraHonk circuit over BN254. The two-field split and the MAC have no
   equivalent there and are not needed.
2. **Parser shape.** The paper runs the tokenizer and the tree-address computation over every
   byte, using parallel-prefix scans (Sklansky) to keep the circuit depth logarithmic, because
   sumcheck cost grows with depth. UltraHonk has no depth constraint and pays for every gate, so
   the port walks the MSO **token by token**: from each token start it reads the head byte,
   computes the token's length, and jumps to the next token. It finds the same set of token
   starts as Algorithm 6, and the container stack does Algorithm 8's job.

   This adds two completeness bounds (soundness is unaffected):
   - at most 256 tokens; the test MSOs have 104 to 106 in 1559 to 1595 bytes, since an MSO is
     mostly digests, keys and dates;
   - at most four nested containers that are not the last child of their parent; a standard MSO
     needs three.

   Walking per token rather than per byte also made the circuit smaller than the earlier per-byte
   tokenizer, which did not track positions: 440k against 474k gates on the earlier test
   credentials. The parser is `implementations/iso/common/lib/src/cbor.nr`; the `rental`
   predicate parses `driving_privileges` with it as well.
3. **ECDSA.** The paper's circuit does the P-256 arithmetic natively over Fp256. Over BN254 the
   port uses Noir's P-256 black box. The relation (a valid ECDSA signature) is unchanged.

### Relation choices

1. **Hidden attribute and predicate instead of disclosure.** Algorithm 10 discloses the value `Z`
   in public. The port keeps `elementValue` private and proves a predicate on it, as every variant
   here does. The item hash is the same; only the visibility of `Z` and the added predicate
   differ.
2. **Item preimage.** `SHA256(nonce, attr, Z)` stands for the ISO `IssuerSignedItemBytes` and is
   implemented as such, on the bytes as issued. The paper's nonce is the item's `random`, and
   `digestID` is included because ISO 18013-5 includes it. The namespace is a public input, as
   `attr` is: `veteran` is in `org.iso.18013.5.1.aamva`, the other elements in
   `org.iso.18013.5.1`.
3. **Paths are checked through parent containers.** Algorithm 8 compares full tree addresses.
   The port checks the same paths one step at a time instead. For example,
   `MSO[validityInfo][validUntil]` holds when:
   - the `validUntil` key's parent is a map;
   - the token just before that map is the key `validityInfo`;
   - `validityInfo`'s parent is the MSO's root map;
   - both are in key position.

   That is equivalent for the paths the relation reads. The checks reject a field whose bytes are
   right but whose path is wrong. Examples: a `validUntil` inside an issuer-signed byte string,
   which does not start a token, or a `validUntil` or `deviceKey` in another issuer-signed map.
4. **Encodings.** Only definite lengths, as mdoc requires; string lengths and container counts
   below 65536. `t_now` is a CBOR `tdate` with second precision.
5. **Dates of the predicate.** `t_now` checks the MSO's validity. A predicate that needs a date
   (`today` in `age`, the rental dates) takes it as its own public input, as in every other
   variant. The circuit does not tie it to `t_now`; the verifier sets both.

Tests: `implementations/longfellow/test_soundness.py` checks that the circuit rejects:

- fields placed after the hashed bytes;
- an item whose `digestID` does not match its MSO entry;
- fields at the right bytes but the wrong path. The issuer (pyMDOC-CBOR) signs, under the MSO's
  `status` entry, an attribute digest under a key `org.iso.18013.5.1`, a later `validUntil`, or
  the attacker's `deviceKey`. With the path checks removed, the circuit accepts all three.

It also checks that an MSO with a 2-byte-length string is parsed correctly.

---

## VegaSC (Kaviani & Setty, *Vega*, IEEE S&P 2026, Figure 9a)

### What the paper proves

The public inputs are the issuer key, the device digest, today's date and the predicate threshold.
The private inputs are the MSO bytes, the lookup addresses and values, the one-hot block selectors
and both signatures. The checks are:

1. `ExtractFields(MSO, addr, vals)` (Fig. 7): lookup, prefix and contiguity checks. There is no
   CBOR parsing.
2. today < `validUntil`.
3. `SHA256_SC(item preimage)` = the digest extracted from the MSO.
4. The predicate, `age ≥ τ`.
5. `H_MSO = SHA256_SC(MSO)`: length-hiding SHA-256 (Fig. 3) with a one-hot selector `b`, index
   `d = Σ j·b_j`, padding checked at block `d`, and digest `Σ b_j H_{j+1}`.
6. ECDSA verification with the issuer key over `H_MSO`, and with the extracted device key over
   the device digest.

### How it maps to `implementations/vega/lib/src/lib.nr`

| Figure 9a | Port |
|---|---|
| `ExtractFields` | `extract_fields`. Each lookup checks `signed[addr[i]] == vals[i]` with `addr[i] < len`; UltraHonk compiles these to ROM lookups. Fields are read at the Fig. 8 prefixes (`deviceKey`, 85 bytes; `validUntil`, 33 bytes), and each field's addresses must be consecutive. |
| `SHA256_SC` | `sha256_sc` implements Fig. 3 step by step: the selector is binary and one-hot, the padding boundary lies at `d`, the `0x80` byte, the zero bytes and the length field are checked, and the digest is selected from all 35 compression outputs. |
| Steps 2–6 | `verify_mdoc` runs them in the order of Fig. 9a. |

Like the paper, the port checks neither `validFrom`, `docType` nor `digestAlgorithm`, and does not
parse CBOR.

### Backend departures

1. **Proof system.** SplitSpartan, Succinct NovaBlindFold and Hyrax are replaced by UltraHonk.
2. **No precomputation.** Vega commits to the credential once and rerandomizes that commitment for
   each presentation. UltraHonk cannot reuse commitments, so every timing here is a full proof,
   not comparable with Vega's "online" proving time.
3. **ECDSA.** Fig. 6 verifies `(r, s⁻¹)` natively because Vega's field is the P-256 base field
   (T-256). Over BN254 that advantage is gone, so the port uses the P-256 black box, as the
   Longfellow port does.
4. **VegaMC is not ported** (see `NOT_PORTED.md`).

### Relation choices

The paper leaves the following points open, and Microsoft's public repository has no mDL circuit.

1. **Bytes hashed.** As in the Longfellow port, they are the COSE `Sig_structure` around the MSO,
   because that is what the issuer signs.
2. **Digest entry.** The paper extracts the digest "using the same lookup protocol". The port
   makes it a third Fig. 7 field with prefix `<digestID> 58 20`, where the `digestID` must equal
   the item's. Fig. 7 checks no enclosing map, so **the namespace is not checked**.
3. **Item preimage.** The paper hashes a "DOB preimage" without defining it. The port uses the
   `IssuerSignedItemBytes` as issued, parsed by the `iso` library, which fixes the
   `elementIdentifier` and the value.
4. **Date.** Today is a public CBOR full-date, compared against `validUntil` as midnight.
5. **Device digest.** The paper's mock device signs a verifier nonce. To reuse the credentials and
   device signatures of the Longfellow port, the port makes `H_dev` the SHA-256 of the same
   `Sig_structure(DeviceAuthenticationBytes)` of the in-person session. The verifier computes it outside the circuit,
   whereas Longfellow rebuilds it inside the circuit.
6. **Size bound.** The port keeps Longfellow's 35 blocks (2231 bytes), not the paper's 1920-byte
   MSO, so both ports run on the same credentials and bound. The test credentials sign 1559 to
   1595 bytes, within both.

Tests: `implementations/vega/test_soundness.py` has 21 checks covering:

- lookups after the hashed bytes, wrong values, spliced fields and wrong prefixes;
- a `digestID` mismatch;
- a shifted or non-binary selector, and a wrong length;
- an expired credential;
- an MSO with a 2-byte-length string, which must be accepted.

Four tests document **Vega's well-formedness assumption** (§5): the issuer must not sign bytes
that contain a field prefix outside its real position. In each test the issuer (pyMDOC-CBOR)
signs, under the MSO's `status` entry, a forged `validUntil` or `deviceKey` in one of two places:

- inside an issuer-signed byte string;
- in another issuer-signed map.

VegaSC accepts all four. The Longfellow port rejects the same credentials: in the byte string
the forged bytes do not start a token, and in the other map they are not at the required path.
This is how the paper defines the relation, not a bug in the port.

---

## Summary

| | Longfellow port | VegaSC port |
|---|---|---|
| Relation | Algorithm 10, with the value hidden behind a predicate | Fig. 9a |
| CBOR | Parsed in-circuit; each field must be at its MSO path | Not parsed; prefix lookups |
| Fields checked | digest (under `valueDigests` and the namespace), device key, `validFrom`, `validUntil`, docType, digestAlgorithm | digest (namespace unchecked), device key, `validUntil` |
| Device message | Rebuilt in-circuit from the public `tr` | Public digest `H_dev` |
| Main simplification | None; paths are checked through parent containers rather than full tree addresses | None beyond the paper's own assumption |
| Backend departures | Two-field sumcheck + Ligero → UltraHonk; per-token parser (256 tokens); ECDSA black box | Spartan/folding → UltraHonk; no precomputation; ECDSA black box |
