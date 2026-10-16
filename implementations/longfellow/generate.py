#!/usr/bin/env python3
"""Generates Prover.toml for the Longfellow-style mdoc circuits.

Builds an ISO/IEC 18013-5 mDL credential: the IssuerSignedItem of the private
attribute, an MSO with the salted digests of every attribute, the issuer's
COSE_Sign1 signature over it, and the device signature over the
DeviceAuthentication structure of a dummy session.

Usage:
  ./generate.py str ADDRESS SUBSTRING          # 57 and 10 characters
  ./generate.py int X Y                        # age_in_years X > Y
  ./generate.py age DOB TODAY AGE              # dates as DD/MM/YYYY
  ./generate.py nationality PT,EN,--,--,-- EN
The item fields, now, the elementIdentifier and the predicate's public input are written
CBOR-encoded, as in the ISO variants (../iso).
Options: --digest-id N, --out FILE (default: SCENARIO/Prover.toml),
         --dart FILE RUN (also add the flattened inputs to a Dart inputs list)
Requires: pip install cbor2 cryptography
"""

import argparse
import hashlib
import os
import random as rnd

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

MAX_SIGNED_LEN = 2231
MSO_START = 25
NAMESPACE = "org.iso.18013.5.1"
DOC_TYPE = "org.iso.18013.5.1.mDL"
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

VALID_FROM = "2025-01-01T00:00:00Z"
VALID_UNTIL = "2030-01-01T00:00:00Z"
SIGNED = "2025-01-01T00:00:00Z"
NOW = "2025-07-21T12:00:00Z"
MAX_TR_LEN = 256
MAX_DA_LEN = 45 + 2 + MAX_TR_LEN + 26
RANDOM_LEN = 16  # as in the ISO variants; the standard requires at least 16 bytes
NATIONALITIES = 5

# Other attributes of the credential: only their digests end up in the MSO.
MDL_ELEMENTS = [
    "family_name", "given_name", "birth_date", "issue_date", "expiry_date",
    "issuing_country", "issuing_authority", "document_number", "portrait",
    "driving_privileges", "un_distinguishing_sign", "administrative_number",
    "sex", "height", "weight", "eye_colour", "hair_colour", "birth_place",
    "resident_city", "resident_state", "resident_postal_code",
    "resident_country", "portrait_capture_date", "age_in_years",
    "age_birth_year", "age_over_18", "age_over_21", "issuing_jurisdiction",
    "nationality", "family_name_national_character",
    "given_name_national_character", "signature_usual_mark",
]
AAMVA_ELEMENTS = [
    "domestic_driving_privileges", "name_suffix", "organ_donor", "veteran",
    "family_name_truncation", "given_name_truncation", "aka_family_name.v2",
    "weight_range", "race_ethnicity", "EDL_credential", "DHS_compliance",
    "sex", "resident_county", "hazmat_endorsement_expiration_date",
]


def tdate(s):
    return cbor2.CBORTag(0, s)


def issuer_signed_item(digest_id, random, element_id, value):
    # field order as in the ISO/IEC 18013-5 examples; cbor2 keeps insertion order
    item = {
        "digestID": digest_id,
        "random": random,
        "elementIdentifier": element_id,
        "elementValue": value,
    }
    return cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(item)))


def sign(key, digest):
    der = key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    # (r, n - s) is an equally valid signature; Barretenberg expects low-s
    if s > P256_N // 2:
        s = P256_N - s
    return list(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def pub_xy(key):
    nums = key.public_key().public_numbers()
    return list(nums.x.to_bytes(32, "big")), list(nums.y.to_bytes(32, "big"))


def sig_structure(protected, payload):
    return cbor2.dumps(["Signature1", protected, b"", payload])


def find_token(buf, pattern, start=MSO_START):
    off = buf.find(pattern, start)
    assert off >= 0 and buf.find(pattern, off + 1) < 0, f"pattern not unique: {pattern!r}"
    return off


class Str(str):
    """A Noir str<N> input (as opposed to a [u8; N] one)."""


def build(element_id, value, digest_id, now, mso_extra=None):
    """mso_extra: optional extra MSO entries (used by test_soundness.py)."""
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    device_key = ec.generate_private_key(ec.SECP256R1())
    dpk_x, dpk_y = pub_xy(device_key)

    # Attribute digests (digestIDs are a random permutation, as issuers do)
    others = [e for e in MDL_ELEMENTS if e != element_id]
    ids = rnd.sample([i for i in range(len(others) + 9) if i != digest_id], len(others))
    random = os.urandom(RANDOM_LEN)
    item = issuer_signed_item(digest_id, random, element_id, value)
    mdl_digests = {digest_id: hashlib.sha256(item).digest()}
    for i, name in zip(ids, others):
        mdl_digests[i] = hashlib.sha256(
            issuer_signed_item(i, os.urandom(RANDOM_LEN), name, "dummy")).digest()
    aamva_digests = {i: os.urandom(32) for i in range(len(AAMVA_ELEMENTS))}

    mso = {
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "valueDigests": {NAMESPACE: mdl_digests, NAMESPACE + ".aamva": aamva_digests},
        "deviceKeyInfo": {"deviceKey": {1: 2, -1: 1, -2: bytes(dpk_x), -3: bytes(dpk_y)}},
        "docType": DOC_TYPE,
        "validityInfo": {
            "signed": tdate(SIGNED),
            "validFrom": tdate(VALID_FROM),
            "validUntil": tdate(VALID_UNTIL),
        },
    }
    mso.update(mso_extra or {})
    mso_bytes = cbor2.dumps(mso, canonical=True)
    payload = cbor2.dumps(cbor2.CBORTag(24, mso_bytes))
    protected = cbor2.dumps({1: -7})  # alg: ES256
    signed = sig_structure(protected, payload)
    assert signed[:MSO_START] + mso_bytes == signed
    assert len(signed) <= MAX_SIGNED_LEN, f"signed MSO is {len(signed)} bytes"
    issuer_sig = sign(issuer_key, hashlib.sha256(signed).digest())
    issuer_x, issuer_y = pub_xy(issuer_key)

    # DeviceAuthentication over a dummy session; tr is public, the framing around it is not
    session_transcript = [
        cbor2.CBORTag(24, os.urandom(64)),
        cbor2.CBORTag(24, os.urandom(77)),
        None,
    ]
    device_namespaces = cbor2.CBORTag(24, cbor2.dumps({}))
    device_auth = cbor2.dumps(
        ["DeviceAuthentication", session_transcript, DOC_TYPE, device_namespaces])
    device_auth_bytes = cbor2.dumps(cbor2.CBORTag(24, device_auth))
    device_msg = sig_structure(protected, device_auth_bytes)
    device_sig = sign(device_key, hashlib.sha256(device_msg).digest())
    tr = cbor2.dumps(session_transcript)
    assert len(tr) <= MAX_TR_LEN and tr in device_msg

    ns_off = find_token(signed, b"\x71" + NAMESPACE.encode())
    digest_off = find_token(signed, cbor2.dumps(digest_id) + b"\x58\x20" + mdl_digests[digest_id])

    return {
        "issuer_pk_x": issuer_x,
        "issuer_pk_y": issuer_y,
        "element_id_cbor": list(cbor2.dumps(element_id)),
        "tr": list(tr) + [0] * (MAX_TR_LEN - len(tr)),
        "tr_len": len(tr),
        "now_cbor": list(cbor2.dumps(cbor2.CBORTag(0, now))),  # C0 74 <tdate>
        "signed": list(signed) + [0] * (MAX_SIGNED_LEN - len(signed)),
        "signed_len": len(signed),
        "issuer_sig": issuer_sig,
        "digest_id_cbor": pad(cbor2.dumps(digest_id), 9),
        "random_cbor": list(cbor2.dumps(random)),
        # raw values, not circuit inputs (used by test_soundness.py)
        "digest_id": digest_id,
        "random": list(random),
        "ns_off": ns_off,
        "digest_off": digest_off,
        "dk_off": find_token(signed, b"\x69deviceKey\xa4"),
        "vf_off": find_token(signed, b"\x69validFrom\xc0"),
        "vu_off": find_token(signed, b"\x6avalidUntil\xc0"),
        "dt_off": find_token(signed, b"\x67docType\x75"),
        "da_off": find_token(signed, b"\x6fdigestAlgorithm"),
        "device_sig": device_sig,
        "device_msg": list(device_msg) + [0] * (MAX_DA_LEN - len(device_msg)),
        "device_msg_len": len(device_msg),
    }


# Parameter order of main(), which is also the flattened ABI order
PUBLIC = ["issuer_pk_x", "issuer_pk_y", "tr", "tr_len", "now_cbor", "element_id_cbor"]
PRIVATE = [
    "signed", "signed_len", "issuer_sig", "digest_id_cbor", "random_cbor", "ns_off", "digest_off",
    "dk_off", "vf_off", "vu_off", "dt_off", "da_off", "device_sig", "device_msg",
    "device_msg_len",
]


def dmy_to_iso(d):
    day, month, year = d.split("/")
    return f"{year}-{month}-{day}"


def pad(b, n):
    return list(b) + [0] * (n - len(b))


def scenario(a):
    """Returns (elementIdentifier, elementValue, public inputs, private inputs, now); the scenario
    inputs are CBOR-encoded byte arrays."""
    if a.scenario == "str":
        assert len(a.x.encode()) == 57, "the address must have 57 bytes"
        assert len(a.y.encode()) == 10, "the substring must have 10 bytes"
        return ("resident_address", a.x, {"y_cbor": list(cbor2.dumps(a.y))},
                {"x_cbor": list(cbor2.dumps(a.x))}, NOW)
    if a.scenario == "int":
        assert 0 <= a.x < 2**64 and 0 <= a.y < 2**64
        return ("age_in_years", a.x, {"y_cbor": pad(cbor2.dumps(a.y), 9)},
                {"x_cbor": pad(cbor2.dumps(a.x), 9)}, NOW)
    if a.scenario == "age":
        dob = cbor2.CBORTag(1004, dmy_to_iso(a.dob))
        return ("birth_date", dob, {"age_cbor": pad(cbor2.dumps(a.age), 9)},
                {"dob_cbor": list(cbor2.dumps(dob))}, dmy_to_iso(a.today) + "T12:00:00Z")
    if a.scenario == "nationality":
        codes = a.list.split(",")
        assert len(codes) == NATIONALITIES and all(len(c) == 2 for c in codes)
        n = codes.index("--") if "--" in codes else NATIONALITIES
        assert n > 0 and all(c == "--" for c in codes[n:]), "codes first, then -- padding"
        assert len(a.nationality) == 2
        # the elementValue holds only the n real codes, as in the ISO variants
        return ("nationality", codes[:n], {"nationality_cbor": list(cbor2.dumps(a.nationality))},
                {"list_cbor": pad(cbor2.dumps(codes[:n]), 1 + 3 * NATIONALITIES)}, NOW)
    raise ValueError(a.scenario)


def flatten(v):
    if isinstance(v, int):
        return [v]
    if isinstance(v, str):
        return list(v.encode())
    return [b for e in v for b in flatten(e)]


def toml_value(v):
    if isinstance(v, int):
        return f'"{v}"'
    if isinstance(v, Str):
        return f'"{v}"'
    if isinstance(v, list) and v and isinstance(v[0], Str):
        return "[" + ", ".join(f'"{e}"' for e in v) + "]"
    return "[" + ", ".join(str(b) for b in flatten(v)) + "]"


def to_toml(w, order):
    return "".join(f"{k} = {toml_value(w[k])}\n" for k in order)


def to_dart(w, order, name, run):
    body = ", ".join(str(b) for k in order for b in flatten(w[k]))
    return (f'  {{\n    "file": "{name}",\n    "executions": 250,\n'
            f'    "run": {run},\n    "inputs": [{body}]\n  }},\n')


def main():
    ap = argparse.ArgumentParser(description="Generates Prover.toml for the Longfellow circuits")
    sub = ap.add_subparsers(dest="scenario", required=True)
    p = sub.add_parser("str")
    p.add_argument("x")
    p.add_argument("y")
    p = sub.add_parser("int")
    p.add_argument("x", type=int)
    p.add_argument("y", type=int)
    p = sub.add_parser("age")
    p.add_argument("dob")
    p.add_argument("today")
    p.add_argument("age", type=int)
    p = sub.add_parser("nationality")
    p.add_argument("list")
    p.add_argument("nationality")
    for p in sub.choices.values():
        p.add_argument("--digest-id", type=int, default=None)
        p.add_argument("--out", default=None)
        p.add_argument("--dart", nargs=2, metavar=("FILE", "RUN"),
                       help="also add the flattened inputs to a Dart inputs list")
    a = ap.parse_args()

    element_id, value, pub, priv, now = scenario(a)
    digest_id = a.digest_id if a.digest_id is not None else rnd.randrange(0, 40)
    assert 0 <= digest_id < 2**64
    w = build(element_id, value, digest_id, now) | pub | priv
    order = PUBLIC + list(pub) + list(priv) + PRIVATE
    out = a.out or os.path.join(os.path.dirname(os.path.abspath(__file__)), a.scenario, "Prover.toml")
    with open(out, "w") as f:
        f.write(to_toml(w, order))
    print(f"signed MSO: {w['signed_len']} bytes, digestID {digest_id} -> {out}")
    if a.dart:
        if not os.path.exists(a.dart[0]):
            with open(a.dart[0], "w") as f:
                f.write("final inputs = [\n];\n")
        with open(a.dart[0]) as f:
            dart = f.read()
        i = dart.rindex("];")
        with open(a.dart[0], "w") as f:
            f.write(dart[:i] + to_dart(w, order, f"longfellow_{a.scenario}", int(a.dart[1])) + dart[i:])


if __name__ == "__main__":
    main()
