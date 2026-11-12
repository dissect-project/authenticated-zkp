#!/usr/bin/env python3
"""Soundness tests for the Longfellow circuits, on credentials issued by pyMDOC-CBOR
(../../credentials).

  ../../credentials/.venv/bin/python test_soundness.py

Each test takes the inputs of a committed or freshly issued credential, optionally tampers with
them, runs the circuit and checks that it accepts honest inputs and rejects each attack with the
expected assertion:

  - fields appended after the issuer-signed bytes (signed[signed_len..] is private and not covered
    by the issuer signature): a forged attribute digest, the attacker's device key and a later
    validUntil;
  - an MSO digest entry whose key is not the item's digestID;
  - fields at the right bytes but the wrong MSO path, which the issuer signed under the MSO's
    `status` entry: a namespace digest map, a later validUntil and the attacker's device key;
    (the namespace itself is part of the public statement, e.g. org.iso.18013.5.1.aamva for
    veteran, and the digest must be a key of that namespace's map in MSO[valueDigests])
  - fields the issuer signed inside a byte string under `status` (a later validUntil and the
    attacker's device key), which do not start a CBOR token of the MSO;
and that an MSO with a 300-byte string (a 2-byte CBOR length) is accepted.
"""

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "credentials"))
import cbor2  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from holders import MDL  # noqa: E402
from inputs import ITEM_MAX, low_s, pad  # noqa: E402
from testkit import committed, execute, fresh, report  # noqa: E402

OUTSIDE = "MSO field outside the signed bytes"
LATE = "2027-12-01T12:00:00Z"  # after validUntil (2027-11-10T23:59:59Z)


def run(w, scenario="age"):
    return execute("longfellow", scenario, w)


def item_bytes(digest_id, birth):
    """A birth_date IssuerSignedItemBytes that the issuer never signed."""
    return cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps({
        "digestID": digest_id, "random": bytes(32), "elementIdentifier": "birth_date",
        "elementValue": cbor2.CBORTag(1004, birth)})))


def append(w, data):
    """Writes `data` after the signed bytes and returns its offset."""
    off = w["signed_len"]
    w["signed"][off:off + len(data)] = list(data)
    return off


def sign_device(w, key):
    """The attacker signs the session's device message with its own key."""
    msg = bytes(w["device_msg"][:w["device_msg_len"]])
    r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
    w["device_sig"] = low_s(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def device_key_field(key):
    n = key.public_key().public_numbers()
    return (b"\x69deviceKey\xa4\x01\x02\x20\x01\x21\x58\x20" + n.x.to_bytes(32, "big")
            + b"\x22\x58\x20" + n.y.to_bytes(32, "big"))


def old_enough(w, item):
    """holder4 (born 2003) claims to be at least 24 with `item` (born 1990)."""
    w.update(item=pad(item, ITEM_MAX["age"]), item_len=len(item),
             threshold_cbor=pad(cbor2.dumps(24), 9))


# ---------------- fields after the signed bytes ----------------

def digest_after_signed():
    w = committed(3, "age").inputs("longfellow")
    item = item_bytes(99, "1990-07-19")
    ns = cbor2.dumps(MDL)
    off = append(w, ns + b"\xa1" + cbor2.dumps(99) + b"\x58\x20" + hashlib.sha256(item).digest())
    w.update(ns_off=off, digest_off=off + len(ns) + 1)
    old_enough(w, item)
    return run(w)


def device_key_after_signed():
    key = ec.generate_private_key(ec.SECP256R1())
    w = committed(0, "age").inputs("longfellow")
    w["dk_off"] = append(w, device_key_field(key))
    sign_device(w, key)
    return run(w)


def valid_until_after_signed():
    w = committed(0, "age").inputs("longfellow")
    w["vu_off"] = append(w, b"\x6avalidUntil\xc0\x74" + b"2099-01-01T00:00:00Z")
    w["now_cbor"] = list(cbor2.dumps(cbor2.CBORTag(0, LATE)))
    return run(w)


def other_digest_entry():
    """The digest entry of another element in the same namespace."""
    c = committed(0, "age")
    w = c.inputs("longfellow")
    other = (c.digest_id + 1) % len(c.mso["valueDigests"][MDL])
    w["digest_off"] = bytes(w["signed"]).find(
        cbor2.dumps(other) + b"\x58\x20" + c.mso["valueDigests"][MDL][other])
    return run(w)


# ---------------- fields at the wrong path (signed by the issuer under `status`) ----------------

def offset_in_status(w, pattern):
    signed = bytes(w["signed"][:w["signed_len"]])
    off = signed.find(pattern, signed.find(b"\x66status"))
    assert off > 0
    return off


def namespace_in_status():
    item = item_bytes(99, "1990-07-19")
    w = fresh(3, "age", status={MDL: {99: hashlib.sha256(item).digest()}}).inputs("longfellow")
    ns_off = offset_in_status(w, cbor2.dumps(MDL))
    w.update(ns_off=ns_off, digest_off=ns_off + len(cbor2.dumps(MDL)) + 1)
    old_enough(w, item)
    return run(w)


def valid_until_in_status():
    c = fresh(0, "age", status={"validUntil": cbor2.CBORTag(0, "2099-01-01T00:00:00Z")})
    w = c.inputs("longfellow")
    w.update(vu_off=offset_in_status(w, b"\x6avalidUntil\xc0"),
             now_cbor=list(cbor2.dumps(cbor2.CBORTag(0, LATE))))
    return run(w)


def device_key_in_status():
    key = ec.generate_private_key(ec.SECP256R1())
    n = key.public_key().public_numbers()
    c = fresh(0, "age", status={"deviceKey": {1: 2, -1: 1, -2: n.x.to_bytes(32, "big"),
                                              -3: n.y.to_bytes(32, "big")}})
    w = c.inputs("longfellow")
    w["dk_off"] = offset_in_status(w, b"\x69deviceKey\xa4")
    sign_device(w, key)
    return run(w)


# ---------------- fields inside a byte string (signed by the issuer under `status`) ----------------
# With the `status` tests above, these are the four ways of breaking the well-formedness
# assumption of VegaSC (Section 5), which ../vega/test_soundness.py runs on both circuits.

VALID_UNTIL = b"\x6avalidUntil\xc0\x74" + b"2099-01-01T00:00:00Z"


def valid_until_in_bstr():
    w = fresh(0, "age", status={"data": VALID_UNTIL}).inputs("longfellow")
    w.update(vu_off=offset_in_status(w, VALID_UNTIL),
             now_cbor=list(cbor2.dumps(cbor2.CBORTag(0, LATE))))
    return run(w)


def device_key_in_bstr():
    key = ec.generate_private_key(ec.SECP256R1())
    field = device_key_field(key)
    w = fresh(0, "age", status={"data": field}).inputs("longfellow")
    w["dk_off"] = offset_in_status(w, field)
    sign_device(w, key)
    return run(w)


def long_string():
    return run(fresh(0, "age", status={"note": "u" * 300}).inputs("longfellow"))


TESTS = [
    ("honest credential", lambda: (run(committed(0, "age").inputs("longfellow")), None)),
    ("forged attribute digest after the signed bytes", lambda: (digest_after_signed(), OUTSIDE)),
    ("attacker device key after the signed bytes", lambda: (device_key_after_signed(), OUTSIDE)),
    ("later validUntil after the signed bytes", lambda: (valid_until_after_signed(), OUTSIDE)),
    ("digest entry of another element", lambda: (other_digest_entry(), "digestID mismatch")),
    ("attribute digest signed under MSO[status]",
     lambda: (namespace_in_status(), "Namespace is not in valueDigests")),
    ("later validUntil signed under MSO[status]",
     lambda: (valid_until_in_status(), "validUntil is not in validityInfo")),
    ("attacker device key signed under MSO[status]",
     lambda: (device_key_in_status(), "deviceKey is not in deviceKeyInfo")),
    ("later validUntil signed inside a byte string under MSO[status]",
     lambda: (valid_until_in_bstr(), "validUntil is not a CBOR token")),
    ("attacker device key signed inside a byte string under MSO[status]",
     lambda: (device_key_in_bstr(), "deviceKey is not a CBOR token")),
    ("MSO with a 300-byte string", lambda: (long_string(), None)),
]

if __name__ == "__main__":
    sys.exit(1 if report(TESTS) else 0)
