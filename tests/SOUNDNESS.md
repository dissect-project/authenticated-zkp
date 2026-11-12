# Soundness tests

This document lists what the soundness tests check for each implementation. All of them run with:

```
credentials/.venv/bin/python tests/soundness.py [iso | longfellow | vega] [--quiet]
```

| Suite | File | Circuits | Tests |
|---|---|---|---:|
| `iso` | `implementations/iso/common/test_soundness.py` | `base`, `sha256-iso`, `sha512-iso`, `poseidon-iso` | 904 |
| `longfellow` | `implementations/longfellow/test_soundness.py` | `longfellow` | 11 |
| `vega` | `implementations/vega/test_soundness.py` | `vega` (17), and `longfellow` for comparison (4) | 21 |

## Method

Every test builds the inputs of a circuit and runs it with `nargo execute`. Most start from a
credential issued by pyMDOC-CBOR (`credentials/`), committed or issued afresh with the test PKI.
Some are crafted by the test, as described in each section. The test then checks the outcome: the
circuit accepts the inputs, or rejects them with a specific assertion message. Checking the message
ensures that each attack is stopped by the check meant to stop it, not by an unrelated failure. A
few tests expect only a rejection, where the failing check depends on how a malformed input is
read; those are noted below.

The verifier fixes the public inputs and the prover controls the private ones. The attacks
therefore change private inputs, with the public inputs the verifier would use. Where a test
changes a public input, it says so.

Tests marked *documented* record behaviour that is accepted and is not an attack. They are there
so that the behaviour is explicit, and they would show any change in it.

## ISO variants: `sha256-iso`, `sha512-iso`, `poseidon-iso`

**Statement.** The public inputs are the requested `elementIdentifier`, the digest `h` taken from
the issuer-signed MSO, and the scenario's parameters. The circuit proves that the private
`IssuerSignedItemBytes` hashes to `h`, is an item of that element, and that its `elementValue`
satisfies the predicate. The MSO signature, validity and device signature are checked by the
verifier outside the circuit, and are not tested here.

Every test runs on the three digests. The predicate tests also run on `base`, which checks the
predicate alone.

| Group | Tests per variant | Total |
|---|---:|---:|
| Honest presentations | 16 | 48 |
| Binding to the issuer's digest | 46 (47 on Poseidon) | 139 |
| Element substitution | 76 | 228 |
| Item encoding | 63 | 189 |
| Predicates (also on `base`) | 69 | 276 |
| Public input encoding | 8 | 24 |
| **Total** | | **904** |

### Honest presentations

The four holders in the four scenarios are accepted.

### Binding to the issuer's digest

The prover gives an item that is not the one the issuer committed to, while `h` remains the
digest of the issued item. Each change must be rejected by the digest check, in all four
scenarios:

- one bit of `random` flipped;
- another `digestID`;
- the item truncated by one byte (`item_len - 1`);
- the item extended with a zero byte (`item_len + 1`). On SHA-256 and SHA-512 the digest check
  rejects it. On Poseidon the digest is unchanged, since Poseidon absorbs the item zero-padded,
  and the parser rejects it (*length mismatch*);
- `item_len` beyond the item array, and `item_len = 2^32 - 1` (any rejection);
- the same element's item from another holder;
- `h` taken from another element of the same credential.

Tampered values that would make a failing predicate pass, each with a control test showing that
the honest item fails the predicate:

| Scenario | Control (honest item, rejected by the predicate) | Tampered item (rejected by the digest check) |
|---|---|---|
| age | holder4 (23) against threshold 25 | `birth_date` moved back 10 years |
| rental | category B held since 2005 | B's `issue_date` moved back to 2004 |
| rental | category A requested | B renamed A |
| residence | ZIP range 94100–94199 | ZIP 94041 changed to 94150 |
| veteran | an item with `veteran` = 0 | value changed to 1 |

*Documented:* bytes in the item array after `item_len` are ignored. *Documented, Poseidon only:* a
public digest `h + p`, not reduced modulo the BN254 field order, is accepted, because it is the
same field element. The verifier must take the digest bytes from the MSO and compare them as
bytes.

### Element substitution

Every other item of holder1's credential in the requested element's namespace is given with its
genuine digest from the MSO. All are rejected with *Wrong elementIdentifier*. This is the attack of
a holder presenting a genuine item of another element, for example `issue_date` or
`expiry_date` for `birth_date`, or `aamva_version` = 1 for `veteran`.

| Scenario | Namespace | Items |
|---|---|---:|
| age | `org.iso.18013.5.1` | 23 |
| rental | `org.iso.18013.5.1` | 24 |
| residence | `org.iso.18013.5.1` | 23 |
| veteran | `org.iso.18013.5.1.aamva` | 6 |

Items larger than the circuit's item bound cannot be given to the circuit, and are not listed:
the portrait, and `driving_privileges` outside the rental scenario.

### Item encoding

These items are built by the test with their own digest, as an issuer could encode them. The
standard fixes neither the key order nor the length of `random` beyond 16 bytes. First, a check
that the test's item builder reproduces the issued item byte for byte. Then:

| Accepted | Rejected (assertion) |
|---|---|
| all 24 orders of the four entries | `random` of 0, 15 or 33 bytes (*unsupported length*) |
| `random` of 16, 23, 24 and 32 bytes | `random` as a text string |
| a 16-byte `random` with a non-preferred head (`58 10`) | `digestID` negative or a text string (*not a CBOR unsigned integer*) |
| `digestID` in its 2-, 3-, 5- and 9-byte encodings | `digestID` with a reserved head (`1C`): any rejection |
| a byte string with a 2-byte length (`59 00 LL`) | tag 25 instead of 24 |
| | byte-string length off by −1 or +1 (*length mismatch*) |
| | a map of 5 entries, or of 3 |
| | `random` twice and no `elementValue` |
| | each key misspelled (`digestId`, `randoM`, `elementIdentifiex`, `elementValuE`) |
| | `elementIdentifier` `birth_dates`, `birth_dat`, `Birth_date`, `birth date`, `birth_datf`, or as a byte string |
| | an extra byte after `elementValue`, as the last entry and as the third entry (as issued) |
| | a byte after the map, inside the byte string |
| | an `elementValue` longer than the circuit's bound |

### Predicates

These run on `base` and the three ISO variants. On `base` the value is given directly. On the ISO
variants it is placed in an item with its own digest. The other tests change the verifier's public
parameters against the issued item.

**age** (`birth_date`, at least `threshold` years old):
- accepted: holder1 (36) against threshold 36; the 21st birthday is today; threshold 21 in a
  non-preferred encoding;
- rejected: threshold 37; the 21st birthday is tomorrow; threshold 199 (*Age verification has
  failed*); threshold 200 (*Invalid age threshold*);
- `birth_date` untagged, with tag 1005, with tag 0, as `1990/05/14`, `199O-05-14` or `1990-5-14`:
  rejected;
- `today` not a full-date (public): rejected;
- *documented:* `1990-13-45` is accepted. Dates are compared as YYYYMMDD and not validated as
  calendar dates; the issuer signs them.

**rental** (`driving_privileges`, a privilege of the category held since `held_since` and valid
until `return_date`):
- accepted: B among four privileges; the keys of the privilege in another order; a privilege with
  `codes`; C and CE, with either requested; `issue_date` equal to `held_since`; `expiry_date` equal
  to `return_date`;
- rejected: only BE when B is requested and the reverse, lower-case `b` (*No privilege of the
  category*); no `issue_date`; no `expiry_date`; issued one day after `held_since`; expiring one day
  before `return_date`;
- dates of another privilege: a recent B next to an old A, and a B expiring early next to a valid
  A. Both are rejected, so the dates must belong to the privilege of the requested category;
- the category at the wrong path: B only in a map nested inside another privilege, or only as an
  array element rather than a key (*Invalid driving privilege*);
- malformed values: a single map rather than an array; an indefinite-length array (any rejection
  on the ISO variants); two CBOR items;
- category of 0 or 4 characters (public): rejected.

**residence** (`resident_postal_code`, a ZIP code within `[zip_min, zip_max]`):
- accepted: 94035 and 94043 (the range ends); ZIP+4 94040-1532; the single-ZIP range 94041–94041;
- rejected: 94034 and 94044 (just outside); ZIP+4 94044-0000; an empty range (public);
- malformed: `9404`, `940411`, `94041 1532`, `94041-15a2`, `9404A`, the empty string, the ZIP as
  an integer or a byte string, a range bound of 4 digits (public).

**veteran** (`veteran` = 1):
- accepted: 1 in each of its five CBOR encodings (1, 2, 3, 5 and 9 bytes);
- rejected: 0, 2, 256 and 2^32 + 1, so the whole value is compared, not its low byte;
- not an unsigned integer: `true`, −1, the text `"1"`, a reserved head (`1C`); 1 followed by
  another item.

### Public input encoding

In each scenario: the `elementIdentifier` given as a byte string, and the digest without its
byte-string head. Both are rejected.

## Longfellow

**Statement.** The circuit verifies the issuer's signature over the MSO, parses the MSO in the
circuit and reads each field at its CBOR path: the item digest in
`valueDigests[namespace][digestID]`, `validUntil` and `deviceKey`. It also verifies the device
signature. The tests run on the age scenario.

| Test | Expected |
|---|---|
| honest credential | accepted |
| forged attribute digest after the signed bytes | rejected: *MSO field outside the signed bytes* |
| attacker's device key after the signed bytes | rejected: *MSO field outside the signed bytes* |
| later `validUntil` after the signed bytes | rejected: *MSO field outside the signed bytes* |
| digest entry of another element | rejected: *digestID mismatch* |
| attribute digest signed by the issuer under `MSO[status]` | rejected: *Namespace is not in valueDigests* |
| later `validUntil` signed by the issuer under `MSO[status]` | rejected: *validUntil is not in validityInfo* |
| attacker's device key signed by the issuer under `MSO[status]` | rejected: *deviceKey is not in deviceKeyInfo* |
| later `validUntil` signed by the issuer inside a byte string under `MSO[status]` | rejected: *validUntil is not a CBOR token* |
| attacker's device key signed by the issuer inside a byte string under `MSO[status]` | rejected: *deviceKey is not a CBOR token* |
| MSO with a 300-byte string (a 2-byte CBOR length) | accepted |

The first three place a field in the private bytes after the signed MSO, which the signature does
not cover. The `status` tests have the issuer sign a field whose bytes are correct but which is in
the wrong place: in a map other than the one the field belongs to, or inside a byte string where
it is not CBOR structure at all. The circuit's path and token checks must reject them. The last
four `status` tests are the four ways of breaking VegaSC's parsing assumption (below), so this
suite shows on its own that Longfellow rejects all of them.

## VegaSC

**Statement.** As in Longfellow, but without CBOR parsing. Fields are read by lookups into the
signed message, each checked to lie within the hashed message, to be contiguous and to follow its
expected prefix (Vega, Figures 3, 7 and 9a). The tests run on the age scenario.

| Test | Expected |
|---|---|
| honest credential | accepted |
| forged attribute digest after the hashed message | rejected: *Lookup outside the hashed message* |
| attacker's device key after the hashed message | rejected: *Lookup outside the hashed message* |
| later `validUntil` after the hashed message | rejected: *Lookup outside the hashed message* |
| digest entry of another element | rejected: *digestID mismatch* |
| looked-up bytes that differ from the MSO | rejected: *Lookup does not match the MSO* |
| `validUntil` spliced from another position | rejected: *Field bytes are not contiguous* |
| `validUntil` read at `validFrom` | rejected: *Invalid validUntil prefix* |
| digest selected one block too late | rejected: *Padding boundary mismatch* |
| non-binary block selector | rejected: *Selector is not binary* |
| signed message one byte shorter | rejected: *Invalid SHA-256 padding* |
| expired credential | rejected: *Credential has expired* |
| MSO with a 300-byte string | accepted |

**Vega's parsing assumption.** Vega does not parse CBOR. It assumes the issuer signs well-formed
MSOs in which each field's prefix is unique (Section 5). Four tests break that assumption with an
MSO the issuer signs, forging a field under `MSO[status]`. Each builds one credential and runs it
on both VegaSC and Longfellow, to show the two results side by side. The same four cases are also
in the Longfellow suite.

| Forged field | VegaSC | Longfellow |
|---|---|---|
| `validUntil` inside a byte string | accepted | rejected: *validUntil is not a CBOR token* |
| `deviceKey` inside a byte string | accepted | rejected: *deviceKey is not a CBOR token* |
| `validUntil` in a map other than `validityInfo` | accepted | rejected: *validUntil is not in validityInfo* |
| `deviceKey` in a map other than `deviceKeyInfo` | accepted | rejected: *deviceKey is not in deviceKeyInfo* |

The VegaSC results are the expected behaviour of its relation, not failures of the port. They
show what the assumption covers.

## Limits

- **Witness generation, not a malicious prover.** `nargo execute` computes the circuits' hints
  (unconstrained functions) honestly. The tests show that the constraints reject bad inputs given
  honest hints. They do not show that every hinted value is constrained, which a cheating prover
  could exploit. That needs constraint-level analysis and is not part of these tests.
- **One credential per attack.** The attacks use holder1's credential, or a fresh one from the
  same issuer. The honest tests cover all four holders.
- **Longfellow and VegaSC** are tested on the age scenario. Their scenario circuits share the MSO
  and signature checks, and differ only in the item and predicate, which come from the same
  library as the ISO variants.
