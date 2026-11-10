#!/usr/bin/env python3
"""Soundness tests for the VegaSC circuits, run on the int scenario.

Each test builds a fresh credential with ../longfellow/generate.py, converts it with generate.py,
optionally tampers with the witness, runs `nargo execute` on a temporary copy of int/ and lib/,
and checks that the circuit accepts honest inputs and rejects each attack with the expected
assertion:

  - fields read from the bytes after the hashed message (the blocks after the one selected by
    b_mso are private and not covered by the issuer signature): a forged attribute digest, the
    attacker's own device key and a later validUntil (Figure 7: addresses within the message);
  - an item whose digestID differs from the key of the MSO entry it points to;
  - lookups whose value does not match the MSO, spliced (non-contiguous) field bytes and a
    field read at the wrong prefix (Figure 7: lookup, contiguity, prefix);
  - a wrong one-hot selector, a non-binary selector and a wrong message length (Figure 3);
  - an expired credential (Figure 9a, step 2);
  - an MSO containing a string with a 2-byte length (>= 256 bytes).

The last four tests document the assumption Vega makes instead of parsing CBOR (Section 5): the
issuer signs well-formed MSOs in which each field prefix is unique. Two ways of breaking it are
tested, each for validUntil and deviceKey:

  - an issuer-signed byte string that contains the bytes of the field;
  - an issuer-signed map, other than validityInfo or deviceKeyInfo, with a field of that name.

The VegaSC relation accepts the forged field in both cases. The Longfellow port, which parses the
MSO, rejects the same witness: in a byte string the field does not start a CBOR token, and in the
other map it is not at the path MSO[validityInfo][validUntil] or MSO[deviceKeyInfo][deviceKey].
Those four tests run both circuits.

Usage: python3 test_soundness.py      Requires: nargo, cbor2, cryptography
"""

import hashlib
import importlib.util
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec

HERE = Path(__file__).resolve().parent
IMPLEMENTATIONS = HERE.parent
_spec = importlib.util.spec_from_file_location("vega_generate", HERE / "generate.py")
vg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vg)
lf = vg.lf  # the Longfellow generator

OUTSIDE = "Lookup outside the hashed message"
X, Y = 7, 5  # the issuer signs age_in_years = 7, proven > 5
DK, VU, DG = slice(0, 85), slice(85, 118), slice(118, 161)  # fields in (addr, vals)
LATE = "2031-06-01"  # after the credential's validUntil (2030-01-01)


def uint_cbor(v):
    return lf.pad(cbor2.dumps(v), 9)


def credential(mso_extra=None):
    """A Longfellow witness of the int scenario (also used to derive the Vega one)."""
    return lf.build("age_in_years", X, 5, lf.NOW, mso_extra) | {
        "y_cbor": uint_cbor(Y), "x_cbor": uint_cbor(X)}


def vega(w):
    return vg.convert(w, "int")


def free_offset(v):
    """First byte after the block selected by b_mso: private, unconstrained and unhashed."""
    return 64 * (v["b_mso"].index(1) + 1)


def place(v, field, data, off):
    """Points `field` of (addr, vals) at signed[off..], writing `data` there."""
    v["signed"][off:off + len(data)] = list(data)
    n = field.stop - field.start
    v["addr"][field] = [off + t for t in range(n)]
    v["vals"][field] = [v["signed"][off + t] for t in range(n)]


# ---------------- attacks on the hashed-message bound ----------------

def forged_digest(w, v):
    """Claims age_in_years = 200 (> 150) with a digest entry after the hashed message."""
    item = lf.issuer_signed_item(w["digest_id"], bytes(w["random"]), "age_in_years", 200)
    entry = cbor2.dumps(w["digest_id"]) + b"\x58\x20" + hashlib.sha256(item).digest()
    place(v, DG, entry.ljust(43, b"\0"), free_offset(v))
    v.update(x_cbor=uint_cbor(200), y_cbor=uint_cbor(150))


def attacker_key():
    key = ec.generate_private_key(ec.SECP256R1())
    x, y = lf.pub_xy(key)
    field = b"\x69deviceKey\xa4\x01\x02\x20\x01\x21\x58\x20" + bytes(x) + b"\x22\x58\x20" + bytes(y)
    return key, field


def own_device_key(w, v):
    """Uses a copied credential with the attacker's device key after the hashed message."""
    key, field = attacker_key()
    place(v, DK, field, free_offset(v))
    v["device_sig"] = lf.sign(key, bytes(v["h_dev"]))


def today(date):
    return list(cbor2.dumps(cbor2.CBORTag(1004, date)))


def later_valid_until(w, v):
    """Uses an expired credential with a validUntil of 2099 after the hashed message."""
    place(v, VU, b"\x6avalidUntil\xc0\x74" + b"2099-01-01T00:00:00Z", free_offset(v))
    v["today_cbor"] = today(LATE)


# ---------------- attacks on the lookups (Figure 7) ----------------

def other_digest_id(w, v):
    """Claims the item has another digestID than the MSO entry it points to."""
    v["digest_id_cbor"] = uint_cbor(w["digest_id"] + 1)


def wrong_value(w, v):
    """Claims validUntil is in 2099 by changing the looked-up bytes only."""
    v["vals"][VU.start + 13:VU.start + 17] = list(b"2099")
    v["today_cbor"] = today(LATE)


def spliced(w, v):
    """Takes the first digit of the validUntil year from another position of the MSO."""
    i = VU.start + 13
    nines = [a for a in range(w["signed_len"]) if v["signed"][a] == ord("9")]
    v["addr"][i] = nines[0]
    v["vals"][i] = ord("9")
    v["today_cbor"] = today(LATE)


def wrong_prefix(w, v):
    """Reads the validUntil field at validFrom."""
    place(v, VU, bytes(v["signed"][w["vf_off"]:w["vf_off"] + 33]), w["vf_off"])


# ---------------- attacks on the length-hiding SHA-256 (Figure 3) ----------------

def shifted_selector(w, v):
    """Selects the digest one block after the one where the message ends."""
    d = v["b_mso"].index(1)
    v["b_mso"] = vg.one_hot(d + 1, vg.MSO_BLOCKS)


def non_binary_selector(w, v):
    """b = 2 e_d - e_{d+1}: sums to 1 but is not one-hot."""
    d = v["b_mso"].index(1)
    v["b_mso"][d], v["b_mso"][d + 1] = 2, -1


def shorter_message(w, v):
    """Claims the signed message is one byte shorter."""
    v["signed_len"] -= 1


def expired(w, v):
    v["today_cbor"] = today(LATE)


# ---------------- Vega's well-formedness assumption (Section 5) ----------------

EXTRA = "issuer_extension_data"  # sorts after every MSO key (canonical CBOR), so the real
# fields come first


def first_match(buf, pattern, start=lf.MSO_START):
    return buf.find(pattern, start)


def forged_inside(field, extra=None):
    """A credential whose MSO has the issuer-signed entry EXTRA: extra, by default the byte string
    `field`, which contains the bytes of a forged field.
    Returns (Longfellow witness, offset of the forged field)."""
    find_token = lf.find_token
    lf.find_token = first_match  # the prefix now occurs twice; Longfellow points at the real one
    try:
        w = credential({EXTRA: field if extra is None else extra})
    finally:
        lf.find_token = find_token
    signed = bytes(w["signed"][:w["signed_len"]])
    off = signed.find(field)
    assert off > 0 and signed.find(field, off + 1) < 0
    return w, off


def prefix_in_bstr_valid_until():
    return forged_valid_until(nested=False)


def prefix_in_bstr_device_key():
    return forged_device_key(nested=False)


def prefix_in_map_valid_until():
    return forged_valid_until(nested=True)


def prefix_in_map_device_key():
    return forged_device_key(nested=True)


LATER = "2099-01-01T00:00:00Z"


def forged_valid_until(nested):
    """An expired credential presented with a forged validUntil of 2099."""
    field = b"\x6avalidUntil\xc0\x74" + LATER.encode()
    w, off = forged_inside(field, {"validUntil": cbor2.CBORTag(0, LATER)} if nested else None)
    w["vu_off"] = off
    w["now_cbor"] = list(cbor2.dumps(cbor2.CBORTag(0, LATE + "T12:00:00Z")))
    return w, vega(w)


def forged_device_key(nested):
    """A copied credential presented with the attacker's device key."""
    key, field = attacker_key()
    x, y = lf.pub_xy(key)
    w, off = forged_inside(field, {"deviceKey": {1: 2, -1: 1, -2: bytes(x), -3: bytes(y)}}
                           if nested else None)
    w["dk_off"] = off
    msg = bytes(w["device_msg"][:w["device_msg_len"]])
    w["device_sig"] = lf.sign(key, hashlib.sha256(msg).digest())  # the attacker signs the session
    return w, vega(w)


# ---------------- runner ----------------

def execute(variant, inputs, order):
    with tempfile.TemporaryDirectory() as tmp:
        # mirror implementations/: int/ depends on ../lib, which depends on ../../iso/common/lib
        root = Path(tmp)
        for d in [f"{variant}/lib", f"{variant}/int", "iso/common/lib"]:
            shutil.copytree(IMPLEMENTATIONS / d, root / d, ignore=shutil.ignore_patterns("target"))
        work = root / variant / "int"
        (work / "Prover.toml").write_text(lf.to_toml(inputs, order))
        res = subprocess.run(["nargo", "execute"], cwd=work, capture_output=True, text=True)
        out = res.stdout + res.stderr
        if res.returncode == 0:
            return None
        for line in out.splitlines():
            if "Assertion failed:" in line:
                return line.split("Assertion failed:", 1)[1].strip().rstrip(".")
        return out.strip().splitlines()[-1]


def run_vega(v):
    return execute("vega", v, vg.order("int"))


def run_longfellow(w):
    return execute("longfellow", w, lf.PUBLIC + ["y_cbor", "x_cbor"] + lf.PRIVATE)


def tampered(tamper):
    def make():
        w = credential()
        v = vega(w)
        tamper(w, v)
        return w, v
    return make


# (name, builder returning (Longfellow witness, Vega witness), expected Vega result,
#  expected Longfellow result or False to skip it); None means the witness must be accepted
TESTS = [
    ("honest credential", tampered(lambda w, v: None), None, False),
    ("forged attribute digest after the hashed message", tampered(forged_digest), OUTSIDE, False),
    ("attacker device key after the hashed message", tampered(own_device_key), OUTSIDE, False),
    ("later validUntil after the hashed message", tampered(later_valid_until), OUTSIDE, False),
    ("item digestID different from the MSO entry's key", tampered(other_digest_id),
     "digestID mismatch", False),
    ("looked-up bytes that differ from the MSO", tampered(wrong_value),
     "Lookup does not match the MSO", False),
    ("validUntil spliced from another position", tampered(spliced),
     "Field bytes are not contiguous", False),
    ("validUntil read at validFrom", tampered(wrong_prefix), "Invalid validUntil prefix", False),
    ("digest selected one block too late", tampered(shifted_selector), "Padding boundary mismatch",
     False),
    ("non-binary block selector", tampered(non_binary_selector), "Selector is not binary", False),
    ("signed message one byte shorter", tampered(shorter_message), "Invalid SHA-256 padding", False),
    ("expired credential", tampered(expired), "Credential has expired", False),
    ("MSO with a 300-byte string",
     lambda: (lambda w: (w, vega(w)))(credential({"status": "u" * 300})), None, False),
    # Vega's well-formedness assumption: accepted by VegaSC, rejected by the Longfellow parser
    ("validUntil forged inside an issuer-signed bstr (assumption)", prefix_in_bstr_valid_until,
     None, "validUntil is not a CBOR token"),
    ("deviceKey forged inside an issuer-signed bstr (assumption)", prefix_in_bstr_device_key,
     None, "deviceKey is not a CBOR token"),
    ("validUntil forged in another issuer-signed map (assumption)", prefix_in_map_valid_until,
     None, "validUntil is not in validityInfo"),
    ("deviceKey forged in another issuer-signed map (assumption)", prefix_in_map_device_key,
     None, "deviceKey is not in deviceKeyInfo"),
]


def describe(got):
    return "accepted" if got is None else f"rejected ({got})"


def main():
    lf.AAMVA_ELEMENTS[:] = []  # keeps the MSO within the bound for the tests that extend it
    failed = 0
    for name, make, expected, expected_lf in TESTS:
        w, v = make()
        results = [("vega", run_vega(v), expected)]
        if expected_lf is not False:
            results.append(("longfellow", run_longfellow(w), expected_lf))
        for variant, got, exp in results:
            ok = got == exp
            failed += not ok
            print(f"{'PASS' if ok else 'FAIL'}  [{variant}] {name}: {describe(got)}"
                  + ("" if ok else f", expected {describe(exp)}"))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
