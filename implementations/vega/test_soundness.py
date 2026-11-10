#!/usr/bin/env python3
"""Soundness tests for the VegaSC circuits, on credentials issued by pyMDOC-CBOR
(../../credentials), in the age scenario.

  ../../credentials/.venv/bin/python test_soundness.py

Each test takes the inputs of a committed or freshly issued credential, optionally tampers with
them, runs the circuit and checks that it accepts honest inputs and rejects each attack with the
expected assertion:

  - fields read from the bytes after the hashed message (the blocks after the one selected by
    b_mso are private and not covered by the issuer signature): a forged attribute digest, the
    attacker's device key and a later validUntil (Figure 7: addresses within the message);
  - a digest entry whose key is not the item's digestID;
  - lookups whose value does not match the MSO, spliced (non-contiguous) field bytes and a field
    read at the wrong prefix (Figure 7: lookup, contiguity, prefix);
  - a wrong one-hot selector, a non-binary selector and a wrong message length (Figure 3);
  - an expired credential (Figure 9a, step 2);
and that an MSO with a 300-byte string (a 2-byte CBOR length) is accepted.

The last four tests document the assumption Vega makes instead of parsing CBOR (Section 5): the
issuer signs well-formed MSOs in which each field prefix is unique. Two ways of breaking it are
tested, each for validUntil and deviceKey, with the issuer signing the forged field under the
MSO's `status` entry:
  - inside a byte string;
  - in a map other than validityInfo or deviceKeyInfo.
The VegaSC relation accepts the forged field in both cases. The Longfellow port, which parses the
MSO, rejects the same credential: in a byte string the field does not start a CBOR token, and in
the other map it is not at the path MSO[validityInfo][validUntil] or MSO[deviceKeyInfo][deviceKey].
Those four tests run both circuits.
"""

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "credentials"))
import cbor2  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import (  # noqa: E402
    Prehashed, decode_dss_signature)
from inputs import ITEM_MAX, MSO_BLOCKS, low_s, one_hot, pad  # noqa: E402
from testkit import committed, execute, fresh, report  # noqa: E402

OUTSIDE = "Lookup outside the hashed message"
DK, VU, DG = slice(0, 85), slice(85, 118), slice(118, 161)  # fields in (addr, vals)
LATE = "2027-12-01"  # after validUntil (2027-11-10T23:59:59Z)


def run(v):
    return execute("vega", "age", v)


def date(d):
    return list(cbor2.dumps(cbor2.CBORTag(1004, d)))


def item_bytes(digest_id, birth):
    """A birth_date IssuerSignedItemBytes that the issuer never signed."""
    return cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps({
        "digestID": digest_id, "random": bytes(32), "elementIdentifier": "birth_date",
        "elementValue": cbor2.CBORTag(1004, birth)})))


def free_offset(v):
    """First byte after the block selected by b_mso: private, unconstrained and unhashed."""
    return 64 * (v["b_mso"].index(1) + 1)


def place(v, field, off, data=None):
    """Points `field` of (addr, vals) at signed[off..], writing `data` there first."""
    if data is not None:
        v["signed"][off:off + len(data)] = list(data)
    n = field.stop - field.start
    v["addr"][field] = [off + t for t in range(n)]
    v["vals"][field] = [v["signed"][off + t] for t in range(n)]


def attacker_key():
    key = ec.generate_private_key(ec.SECP256R1())
    n = key.public_key().public_numbers()
    field = (b"\x69deviceKey\xa4\x01\x02\x20\x01\x21\x58\x20" + n.x.to_bytes(32, "big")
             + b"\x22\x58\x20" + n.y.to_bytes(32, "big"))
    return key, field


def sign_digest(key, digest):
    r, s = decode_dss_signature(key.sign(bytes(digest), ec.ECDSA(Prehashed(hashes.SHA256()))))
    return low_s(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def sign_message(key, msg):
    r, s = decode_dss_signature(key.sign(bytes(msg), ec.ECDSA(hashes.SHA256())))
    return low_s(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def honest():
    return committed(0, "age").inputs("vega")


# ---------------- attacks on the hashed-message bound ----------------

def forged_digest():
    """holder4 (born 2003) claims to be at least 24 with an item born 1990, whose digest entry is
    after the hashed message."""
    v = committed(3, "age").inputs("vega")
    item = item_bytes(99, "1990-07-19")
    entry = cbor2.dumps(99) + b"\x58\x20" + hashlib.sha256(item).digest()
    place(v, DG, free_offset(v), entry.ljust(43, b"\0"))
    v.update(item=pad(item, ITEM_MAX["age"]), item_len=len(item),
             threshold_cbor=pad(cbor2.dumps(24), 9),
             b_item=one_hot((len(item) + 9 + 63) // 64 - 1, len(v["b_item"])))
    return run(v)


def own_device_key():
    v = honest()
    key, field = attacker_key()
    place(v, DK, free_offset(v), field)
    v["device_sig"] = sign_digest(key, v["h_dev"])
    return run(v)


def later_valid_until():
    v = honest()
    place(v, VU, free_offset(v), b"\x6avalidUntil\xc0\x74" + b"2099-01-01T00:00:00Z")
    v["today_cbor"] = date(LATE)
    return run(v)


# ---------------- attacks on the lookups (Figure 7) ----------------

def other_digest_entry():
    c = committed(0, "age")
    v = c.inputs("vega")
    other = (c.digest_id + 1) % len(c.mso["valueDigests"]["org.iso.18013.5.1"])
    entry = cbor2.dumps(other) + b"\x58\x20" + c.mso["valueDigests"]["org.iso.18013.5.1"][other]
    place(v, DG, bytes(v["signed"]).find(entry))
    return run(v)


def wrong_value():
    """Claims validUntil is in 2099 by changing the looked-up bytes only."""
    v = honest()
    v["vals"][VU.start + 13:VU.start + 17] = list(b"2099")
    v["today_cbor"] = date(LATE)
    return run(v)


def spliced():
    """Takes the third digit of the validUntil year from another position of the MSO."""
    v = honest()
    i = VU.start + 15
    nines = [a for a in range(v["signed_len"]) if v["signed"][a] == ord("9")]
    v["addr"][i] = nines[0]
    v["vals"][i] = ord("9")
    v["today_cbor"] = date(LATE)
    return run(v)


def wrong_prefix():
    """Reads the validUntil field at validFrom."""
    v = honest()
    vf = bytes(v["signed"]).find(b"\x69validFrom\xc0")
    place(v, VU, vf)
    return run(v)


# ---------------- attacks on the length-hiding SHA-256 (Figure 3) ----------------

def shifted_selector():
    v = honest()
    v["b_mso"] = one_hot(v["b_mso"].index(1) + 1, MSO_BLOCKS)
    return run(v)


def non_binary_selector():
    """b = 2 e_d - e_{d+1}: sums to 1 but is not one-hot."""
    v = honest()
    d = v["b_mso"].index(1)
    v["b_mso"][d], v["b_mso"][d + 1] = 2, -1
    return run(v)


def shorter_message():
    v = honest()
    v["signed_len"] -= 1
    return run(v)


def expired():
    v = honest()
    v["today_cbor"] = date(LATE)
    return run(v)


def long_string():
    return run(fresh(0, "age", status={"note": "u" * 300}).inputs("vega"))


# ---------------- Vega's well-formedness assumption (Section 5) ----------------

VALID_UNTIL = b"\x6avalidUntil\xc0\x74" + b"2099-01-01T00:00:00Z"


def assumption(status, field, kind, key=None):
    c = fresh(0, "age", status=status)
    v, w = c.inputs("vega"), c.inputs("longfellow")
    signed = bytes(w["signed"][:w["signed_len"]])
    off = signed.find(field, signed.find(b"\x66status"))
    assert off > 0
    if kind == "validUntil":
        place(v, VU, off)
        v["today_cbor"] = date(LATE)
        w.update(vu_off=off, now_cbor=list(cbor2.dumps(cbor2.CBORTag(0, LATE + "T12:00:00Z"))))
    else:
        place(v, DK, off)
        v["device_sig"] = sign_digest(key, v["h_dev"])
        w.update(dk_off=off, device_sig=sign_message(key, w["device_msg"][:w["device_msg_len"]]))
    return run(v), execute("longfellow", "age", w)


def valid_until_in_bstr():
    return assumption({"data": VALID_UNTIL}, VALID_UNTIL, "validUntil")


def valid_until_in_map():
    return assumption({"validUntil": cbor2.CBORTag(0, "2099-01-01T00:00:00Z")}, VALID_UNTIL,
                      "validUntil")


def device_key_in_bstr():
    key, field = attacker_key()
    return assumption({"data": field}, field, "deviceKey", key)


def device_key_in_map():
    key, field = attacker_key()
    n = key.public_key().public_numbers()
    return assumption({"deviceKey": {1: 2, -1: 1, -2: n.x.to_bytes(32, "big"),
                                     -3: n.y.to_bytes(32, "big")}}, field, "deviceKey", key)


def both(make, expected_lf):
    """Two tests (VegaSC, Longfellow) from one credential."""
    results = {}

    def get():
        if not results:
            results["v"], results["lf"] = make()
        return results

    return [(f"[vega] {make.__doc__}", lambda: (get()["v"], None)),
            (f"[longfellow] {make.__doc__}", lambda: (get()["lf"], expected_lf))]


valid_until_in_bstr.__doc__ = "validUntil forged inside an issuer-signed bstr (assumption)"
valid_until_in_map.__doc__ = "validUntil forged in another issuer-signed map (assumption)"
device_key_in_bstr.__doc__ = "deviceKey forged inside an issuer-signed bstr (assumption)"
device_key_in_map.__doc__ = "deviceKey forged in another issuer-signed map (assumption)"

TESTS = [
    ("[vega] honest credential", lambda: (run(honest()), None)),
    ("[vega] forged attribute digest after the hashed message", lambda: (forged_digest(), OUTSIDE)),
    ("[vega] attacker device key after the hashed message", lambda: (own_device_key(), OUTSIDE)),
    ("[vega] later validUntil after the hashed message", lambda: (later_valid_until(), OUTSIDE)),
    ("[vega] digest entry of another element", lambda: (other_digest_entry(), "digestID mismatch")),
    ("[vega] looked-up bytes that differ from the MSO",
     lambda: (wrong_value(), "Lookup does not match the MSO")),
    ("[vega] validUntil spliced from another position",
     lambda: (spliced(), "Field bytes are not contiguous")),
    ("[vega] validUntil read at validFrom", lambda: (wrong_prefix(), "Invalid validUntil prefix")),
    ("[vega] digest selected one block too late",
     lambda: (shifted_selector(), "Padding boundary mismatch")),
    ("[vega] non-binary block selector", lambda: (non_binary_selector(), "Selector is not binary")),
    ("[vega] signed message one byte shorter", lambda: (shorter_message(), "Invalid SHA-256 padding")),
    ("[vega] expired credential", lambda: (expired(), "Credential has expired")),
    ("[vega] MSO with a 300-byte string", lambda: (long_string(), None)),
    *both(valid_until_in_bstr, "validUntil is not a CBOR token"),
    *both(device_key_in_bstr, "deviceKey is not a CBOR token"),
    *both(valid_until_in_map, "validUntil is not in validityInfo"),
    *both(device_key_in_map, "deviceKey is not in deviceKeyInfo"),
]

if __name__ == "__main__":
    sys.exit(1 if report(TESTS) else 0)
