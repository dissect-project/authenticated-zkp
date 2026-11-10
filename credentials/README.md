# Test credentials

Every circuit runs on mDLs (ISO/IEC 18013-5) issued by
[pyMDOC-CBOR](https://github.com/IdentityPython/pyMDOC-CBOR) 1.4.0 (IdentityPython). It is an mdoc
implementation independent of the circuits, so the circuits are tested on bytes they were not
written around.

```
credentials/
├── requirements.txt    # pyMDOC-CBOR and its dependencies, pinned
├── holders.py          # the four holders, their elements, and the scenarios' public parameters
├── issue.py            # test PKI and issuance (pyMDOC-CBOR), checked by pyMDOC-CBOR's verifier
├── present.py          # in-person sessions and device signatures (pycose)
├── inputs.py           # the inputs of every variant from an issued credential
├── generate.py         # Prover.toml and Dart inputs of every circuit (and ../scenarios/mdl)
├── testkit.py          # helpers of the soundness tests
├── pki/                # root.pem, ds.pem, ds_key.pem (test keys)
└── holders/<name>/     # mdoc.cbor, device_key.pem (test key), <scenario>.cbor (sessions)
```

```
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python issue.py      # new PKI and credentials (overwrites pki/ and holders/)
.venv/bin/python present.py    # new sessions
.venv/bin/python generate.py   # circuit inputs
```

The issued credentials are committed. pyMDOC-CBOR stamps the issuing time and draws random salts,
so re-issuing gives different bytes, and the benchmarks are reproducible only from the committed
files.

## Who produces what

| Part | Produced by | Checked by |
|---|---|---|
| Issuer side: items, MSO, issuer signature (`issuerSigned`) | pyMDOC-CBOR | pyMDOC-CBOR's verifier (document signer chain, issuer signature, every value digest), then the circuits |
| PKI: root (IACA) and document signer certificates | `issue.py` (cryptography) | pyMDOC-CBOR's verifier |
| Holder side: `SessionTranscript`, `DeviceAuthentication`, device signature | `present.py`, following ISO/IEC 18013-5 §9.1.3 and §9.1.5.1; the COSE_Sign1 is built and signed by pycose | the Longfellow and VegaSC circuits, which verify the device signature |

pyMDOC-CBOR has no holder side, so the device response is built by this harness. Its signature
is not checked separately. The focus of the assessment is the circuits, and the Longfellow and
VegaSC circuits verify it.

## The holders

The holders are four California mDLs (`holders.py`). Both namespaces hold every mandatory element
plus the optional elements a US issuer typically includes:

- **`org.iso.18013.5.1`:** the mandatory elements, including a portrait of realistic size, plus
  physical description, residence, issuing jurisdiction and `age_over_NN`.
- **`org.iso.18013.5.1.aamva`:** the mandatory elements plus `veteran`, `organ_donor`,
  `DHS_compliance` and `resident_county`.

Element identifiers, types and namespaces follow ISO/IEC 18013-5 Table 5 and the AAMVA mDL
Implementation Guidelines, as listed by the Multipaz mDL document type
(`openwallet-foundation/multipaz`, `DrivingLicense.kt`). The standard itself was not available.

| | Holder 1 | Holder 2 | Holder 3 | Holder 4 |
|---|---|---|---|---|
| Age on 2026-11-16 | 36 | 43 | 68 | 23 |
| Driving privileges | B | A, B | B, C, CE | AM, A, B, BE |
| ZIP code | 94041 | 94040-1532 (ZIP+4) | 94043 | 94035 |

Each holder satisfies every scenario, and each holder is one run of the benchmark. The signed MSO
(`Sig_structure`) is 1559 to 1595 bytes, within the 2231-byte (35-block) bound of the Longfellow
and VegaSC ports. The `SessionTranscript` is 201 bytes.

## What the credentials exposed

pyMDOC-CBOR encodes `IssuerSignedItem` in canonical key order (`random`, `digestID`,
`elementValue`, `elementIdentifier`), with a 32-byte `random`. The earlier circuits accepted only
the key order of the ISO/IEC 18013-5 Annex D examples and a 16-byte `random`. The standard fixes
neither, so the circuits now parse the item as issued:

- the four entries in any order;
- a `random` of 16 to 32 bytes;
- items longer than 255 bytes (`driving_privileges`).

See `implementations/iso/common/lib`.

## Transformations

The circuit inputs are the issued bytes, with two exceptions:

- **ECDSA low-s.** Barretenberg accepts only signatures with `s <= n/2`. A signature with a larger
  `s` is replaced by `(r, n - s)`, which is an equally valid ECDSA signature on the same message.
- **SHA-512 and Poseidon digests.** The issuer uses SHA-256. For `sha512-iso` and `poseidon-iso`,
  the digest of the same item is computed by `inputs.py`, as an issuer using that algorithm would.
