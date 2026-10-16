# ISO/IEC 18013-5 versions (`*-iso`)

Versions of the `sha256`, `sha512`, `poseidon` and `base` circuits whose inputs follow ISO/IEC
18013-5: the hash commitment is the digest that an issuer puts in the MSO, so the inputs can come
from a real mdoc instead of `H(salt ‖ value)`.

```
h = H(IssuerSignedItemBytes)
IssuerSignedItemBytes = #6.24(bstr .cbor {
    "digestID": uint, "random": bstr, "elementIdentifier": tstr, "elementValue": any })
```

The verifier takes `h` from the `valueDigests` of the issuer-signed MSO, as before, so the
statement is still `x' = (h, pub)`. Each circuit keeps the predicate and public inputs of its
original. **Every input is CBOR-encoded**:
- **Issuer fields:** the attribute, `digestID` and `random`, exactly as they appear in the issuer's item.
- **Public inputs and their private copies:** CBOR values of their natural type.
- **The hash:** a byte string, exactly as the MSO stores it in `valueDigests`.

The circuit decodes them itself. The
`elementIdentifier` is fixed in the circuit, so the digest of another element of the same MSO is
rejected.

| Variant | `H` | ISO 18013-5 compliant |
|---------|-----|-----------------------|
| `sha256-iso` | SHA-256 | yes |
| `sha512-iso` | SHA-512 | yes (`digestAlgorithm` "SHA-512") |
| `poseidon-iso` | Poseidon (BN254, circom-compatible `hash_9`) over the same bytes | no: the standard only allows SHA-256/384/512, so no issuer produces this digest; it shows the cost of a SNARK-friendly hash over the real item |
| `base-iso` | none | values in their ISO format, no hash binding |

## Layout

```
iso/
├── lib/         # Noir library "iso": CBOR field checks, IssuerSignedItemBytes, SHA-256, padding
├── sha512/      # Noir library "iso_sha512": SHA-512 of the item
├── poseidon/    # Noir library "iso_poseidon": Poseidon of the item
├── hasher/      # Noir program that computes the Poseidon digest for generate.py
└── generate.py  # builds an item (or reads a real one) and writes Prover.toml for any variant
<variant>-iso/{int,age,nationality,str}/
├── src/main.nr                          # checks and decodes the CBOR fields, the hash and the predicate
├── Prover.toml                          # inputs of run 1
├── inputs_<variant>_iso_<s>.dart        # the four runs of the primary scenario, for the testing app
└── target/
```

Each hash lives in its own library, so a circuit only pulls in the dependencies it uses (this
matters for `nargo execute` times, which include compilation).

## Inputs

| Scenario | `elementIdentifier` | Private attribute | Private copies | Public inputs |
|----------|---------------------|-------------------|----------------|---------------|
| `int` | `age_in_years` | `x_cbor: [u8; 9]`, unsigned integer | `yp_cbor: [u8; 9]` | `y_cbor: [u8; 9]`, unsigned integer |
| `age` | `birth_date` | `dob_cbor: [u8; 14]`, full-date | `todayp_cbor: [u8; 14]`, `agep_cbor: [u8; 9]` | `today_cbor: [u8; 14]`, full-date; `age_cbor: [u8; 9]`, unsigned integer |
| `nationality` | `nationality` | `list_cbor: [u8; 16]`, array of 1 to 5 two-letter text strings | `nationalityp_cbor: [u8; 3]` | `nationality_cbor: [u8; 3]`, text string `62 c1 c2` |
| `str` | `resident_address` | `x_cbor: [u8; 59]`, 57-byte text string `78 39 <x>` | `yp_cbor: [u8; 11]` | `y_cbor: [u8; 11]`, text string `6A <10 bytes>` |

The hashed variants also take, after the inputs above:

| Input | Content |
|-------|---------|
| `hash_cbor: pub` | the digest as stored in the MSO: `58 20 <32 bytes>` (SHA-256, Poseidon) or `58 40 <64 bytes>` (SHA-512); for Poseidon the bytes are the field element, big-endian |
| `digest_id_cbor: [u8; 9]` | the `digestID` unsigned integer |
| `random_cbor: [u8; 17]` | the `random` byte string, `50 <16 bytes>` |

`base-iso` has none of these three, since it has no hash.

Encodings:
- **Unsigned integers** (`x`, `y`, `age` and their copies, `digestID`) are accepted in any of their
  CBOR encodings (1, 2, 3, 5 or 9 bytes, shortest or not).
- **A full-date** is `D9 03 EC 6A "YYYY-MM-DD"` (tag 1004, RFC 8943).

- **Zero-padded fields:** integer fields and `list_cbor` are padded with zeros. There are no
  length inputs: each value's length comes from its own CBOR head, and the bytes after it are
  ignored.
- **One value per field:** each field must be exactly one CBOR value of the expected type, with
  its length taken from that value. This makes the split of the item into fields unique, so a
  prover cannot move bytes from one field into another and keep the same hash.
- **Copies of public inputs:** the copies keep their role from the manuscript. A public input that
  no constraint references could be optimised away, so each circuit decodes both the public
  input and its copy and asserts that they are equal. They compare as values, so `y = 25` encoded
  `18 19` matches a copy encoded `19 00 19`. The verifier should still encode public inputs the
  same way each time (preferably shortest), since a proof is tied to the exact public bytes.
  The copies are private in every variant, as in `sha256`; some originals made them public
  (`sha512/age`, `base/nationality`, `base/str`).
- **`age`:** `today`, its copy and the date of birth are all CBOR full-dates (`YYYY-MM-DD`),
  read with the same decoder (`decode_full_date` in `lib`) and passed to the unchanged
  `calculate_age` as `DD/MM/YYYY`.
- **`nationality`:** the mDL (`org.iso.18013.5.1`) element is a single `tstr`, so this follows
  the EU PID (`eu.europa.ec.eudi.pid.1`), where `nationality` is an array of codes. Only the `n`
  entries of the array count, so nothing after it can match.

## Cost

Gates from `bb gates` and mean proving time over 5 runs (nargo 1.0.0-beta.7, bb 0.84.0). Verification takes
≈ 37 ms everywhere.

| Scenario | `sha256` → `-iso` | `sha512` → `-iso` | `poseidon` → `-iso` | `base` → `-iso` |
|----------|-------------------|-------------------|---------------------|-----------------|
| `int` | 7,158 → 12,838 gates<br>415 → 376 ms | 71,846 → 74,732<br>975 → 1,038 ms | 3,818 → 5,138<br>114 → 136 ms | 2,768 → 3,117<br>97 → 100 ms |
| `age` | 7,493 → 12,979<br>321 → 339 ms | 72,130 → 74,870<br>881 → 962 ms | 4,108 → 5,303<br>124 → 135 ms | 3,102 → 3,333<br>103 → 138 ms |
| `nationality` | 7,252 → 12,812<br>410 → 354 ms | 71,889 → 74,891<br>1,094 → 972 ms | 1,132 → 5,052<br>93 → 135 ms | 126 → 201<br>67 → 68 ms |
| `str` | 13,331 → 19,065<br>343 → 361 ms | 74,902 → 137,679<br>994 → 2,002 ms | 3,156 → 7,114<br>137 → 151 ms | 2,135 → 2,139<br>101 → 100 ms |

The machine was busy during this run, so the timings are noisy (the unchanged `sha256/int` took
415 ms here and 296 ms in a quieter run). Gate counts are exact. At these sizes proving time is
dominated by a fixed cost (process start-up, loading the SRS), so the extra gates of the `-iso`
circuits cost little in time: in quieter runs, `sha256-iso` was within about 8% of `sha256`. The
one real jump is `sha512-iso/str`, which needs a second SHA-512 block and roughly doubles. Rerun
with `--runs 10` on an idle machine for numbers to report.

With a 16-byte `random` and `u64` integers the item is 84–154 bytes, against 17–73 bytes of
`salt ‖ value`.

- **SHA-256:** this means two blocks instead of one (three for `str`).
- **SHA-512:** it means one block, or two for `str`. SHA-512 is not a black box in Barretenberg,
  so each block costs about 60k gates.
- **Poseidon:** the item is packed into nine 31-byte field elements, which adds a few thousand
  gates for the larger permutation.

Each scenario's largest item, with a 9-byte `digestID`, still fits in the same number of
blocks, so the cost does not depend on the `digestID`. With a 32-byte `random` the items grow by
17 bytes (16 plus a longer length header), and `sha256-iso` `age`/`nationality`, `sha512-iso` `int`/`age`/`nationality` would need one more
block.

`python3 tests/comparison.py` runs all variants, and `--variants` picks some of them.

## How the hash is computed

`issuer_signed_item` joins the fixed key strings and the CBOR-encoded fields. `decode_uint` reads
a CBOR unsigned integer in any of its encodings and returns its value and length,
`decode_full_date` reads a CBOR full-date, `decode_text` a short text string, `decode_digest`
the hash byte string, and `check_random` the `random` byte string. `digestID` takes 1, 2, 3, 5 or 9 bytes, and the
elementValue's length depends on the scenario. Rather than writing at variable offsets or using
`sha256_var`, the item is built byte by byte as a selection over the five possible `digestID`
lengths. For SHA-2, `md_pad` places the
`0x80` byte and the bit length at the end of whichever block the item ends in, and the compression
function runs on every block, keeping the state of the last one. For Poseidon, the item is
zero-padded to 279 bytes, which is unambiguous because CBOR encodes its length. `nargo test` in
`lib/` and `sha512/` checks items whose padding falls on a block boundary, with 1- and 9-byte
`digestID`s (the latter in a longer-than-necessary encoding), against Python's `hashlib`.

Assumptions. The key order is the one in the ISO 18013-5 Annex D examples:

- keys in the order `digestID`, `random`, `elementIdentifier`, `elementValue`;
- a 16-byte `random` with a 1-byte head, the minimum the standard allows. Issuers that use more,
  such as the 32 bytes of the Annex D examples, need `RANDOM_LEN` changed in `lib/src/lib.nr`
  and `generate.py`;
- the elementValue encodings listed under Inputs. Unsigned integers (`x`, `digestID`) are
  accepted in any of their encodings;
- an item of at most 255 bytes.

`generate.py --item` checks all of these on a real item and slices each field's CBOR bytes out of
it unchanged, so the issuer's own encodings reach the circuit.

## Usage

```sh
iso/generate.py sha256 int 45 25                           # writes sha256-iso/int/Prover.toml
iso/generate.py sha512 age 16/08/1999 24/07/2025 25        # date of birth, today, minimum age
iso/generate.py poseidon nationality PT,EN,--,--,-- EN
iso/generate.py base str "42 Fictional Way, Smithfield, Dublin 7, D07 F4K3, Ireland" "Smithfield"
iso/generate.py sha256 age --item d8185869a4686469... 24/07/2025 25   # fields from a real item
cd sha256-iso/age
nargo execute
bb write_vk -b target/age.json -o target
bb prove -b target/age.json -w target/age.gz -o target
bb verify -k target/vk -p target/proof -i target/public_inputs
```

- **Requirements:** `generate.py` needs `cbor2`, and `nargo` for Poseidon.
- **Output:** it prints the item and its hash.
- **Options:** `--digest-id N` fixes the digestID, `--out FILE` writes elsewhere, and
  `--dart FILE RUN` adds the inputs to a Dart inputs list for the testing application, under
  `"file": "<variant>_iso_<s>"`.
