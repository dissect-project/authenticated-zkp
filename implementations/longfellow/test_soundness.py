#!/usr/bin/env python3
"""Soundness tests for the Longfellow circuits, run on the int scenario.

Each test builds a fresh credential with generate.py, optionally tampers with the witness, runs
`nargo execute` on a temporary copy of int/ and lib/, and checks that the circuit accepts honest
inputs and rejects each attack with the expected assertion:

  - fields appended after the issuer-signed bytes (signed[signed_len..] is private and not
    covered by the issuer signature): a forged attribute digest, the attacker's own device key,
    and a later validUntil;
  - an item whose digestID differs from the key of the MSO entry it points to;
  - fields at the right bytes but the wrong MSO path: a namespace digest map, a validUntil and a
    deviceKey that the issuer signed inside another top-level map (`status`), which the token
    checks alone accept and the tree positions reject;
  - an MSO containing a string with a 2-byte length (>= 256 bytes), which the tokenizer must
    measure correctly.

Usage: python3 test_soundness.py      Requires: nargo, cbor2, cryptography
"""

import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate as g  # noqa: E402

OUTSIDE = "MSO field outside the signed bytes"
X, Y = 7, 5  # the issuer signs age_in_years = 7, proven > 5


def uint_cbor(v):
    return g.pad(cbor2.dumps(v), 9)


def credential(mso_extra=None):
    w = g.build("age_in_years", X, 5, g.NOW, mso_extra) | {"y_cbor": uint_cbor(Y), "x_cbor": uint_cbor(X)}
    return w


def append_after_signed(w, fields):
    """Writes fake MSO fields after signed_len and returns the offset of each."""
    offs, pos = [], w["signed_len"]
    for f in fields:
        w["signed"][pos:pos + len(f)] = list(f)
        offs.append(pos)
        pos += len(f)
    return offs


def forged_digest(w):
    """Claims age_in_years = 200 (> 150) with a digest map appended after the signed bytes."""
    item = g.issuer_signed_item(w["digest_id"], bytes(w["random"]), "age_in_years", 200)
    ns = b"\x71" + g.NAMESPACE.encode()
    (off,) = append_after_signed(w, [ns + b"\xa1" + cbor2.dumps(w["digest_id"]) + b"\x58\x20"
                                     + hashlib.sha256(item).digest()])
    w.update(ns_off=off, digest_off=off + len(ns) + 1, x_cbor=uint_cbor(200), y_cbor=uint_cbor(150))


def own_device_key(w):
    """Uses a copied credential with the attacker's device key appended after the signed bytes."""
    key = ec.generate_private_key(ec.SECP256R1())
    x, y = g.pub_xy(key)
    (off,) = append_after_signed(w, [b"\x69deviceKey\xa4\x01\x02\x20\x01\x21\x58\x20" + bytes(x)
                                     + b"\x22\x58\x20" + bytes(y)])
    msg = bytes(w["device_msg"][:w["device_msg_len"]])
    w.update(dk_off=off, device_sig=g.sign(key, hashlib.sha256(msg).digest()))


def later_valid_until(w):
    """Uses an expired credential with a validUntil of 2099 appended after the signed bytes."""
    (off,) = append_after_signed(w, [b"\x6avalidUntil\xc0\x74" + b"2099-01-01T00:00:00Z"])
    w.update(vu_off=off, now_cbor=list(cbor2.dumps(cbor2.CBORTag(0, "2031-06-01T12:00:00Z"))))


def first_match_build(mso_extra):
    """Builds a credential whose MSO repeats field patterns: generate.py otherwise requires them to
    be unique, here the first occurrence is kept and the test sets the attacked offset itself."""
    unique = g.find_token
    g.find_token = lambda buf, pattern, start=g.MSO_START: buf.find(pattern, start)
    try:
        return credential(mso_extra)
    finally:
        g.find_token = unique


def in_status(w, pattern):
    """Offset of `pattern` inside the issuer-signed `status` map."""
    signed = bytes(w["signed"][:w["signed_len"]])
    off = signed.find(pattern, signed.find(b"\x66status"))
    assert off >= 0
    return off


def nested_namespace():
    """Claims age_in_years = 200 (> 150) with a digest that the issuer signed under
    MSO[status][org.iso.18013.5.1], not MSO[valueDigests][org.iso.18013.5.1]."""
    item = g.issuer_signed_item(5, b"\x00" * g.RANDOM_LEN, "age_in_years", 200)
    w = first_match_build({"status": {g.NAMESPACE: {5: hashlib.sha256(item).digest()}}})
    ns_off = in_status(w, b"\x71" + g.NAMESPACE.encode())
    w.update(ns_off=ns_off, digest_off=ns_off + 19, random_cbor=list(cbor2.dumps(b"\x00" * g.RANDOM_LEN)),
             x_cbor=uint_cbor(200), y_cbor=uint_cbor(150))
    return w


def nested_valid_until():
    """Uses an expired credential with a validUntil of 2099 that the issuer signed under
    MSO[status], not MSO[validityInfo]."""
    w = first_match_build({"status": {"validUntil": cbor2.CBORTag(0, "2099-01-01T00:00:00Z")}})
    w.update(vu_off=in_status(w, b"\x6avalidUntil\xc0"),
             now_cbor=list(cbor2.dumps(cbor2.CBORTag(0, "2031-06-01T12:00:00Z"))))
    return w


ATTACKER = ec.generate_private_key(ec.SECP256R1())


def nested_device_key():
    """Uses a copied credential with the attacker's device key, which the issuer signed under
    MSO[status], not MSO[deviceKeyInfo]."""
    x, y = g.pub_xy(ATTACKER)
    w = first_match_build({"status": {"deviceKey": {1: 2, -1: 1, -2: bytes(x), -3: bytes(y)}}})
    msg = bytes(w["device_msg"][:w["device_msg_len"]])
    w.update(dk_off=in_status(w, b"\x69deviceKey\xa4"),
             device_sig=g.sign(ATTACKER, hashlib.sha256(msg).digest()))
    return w


def other_digest_id(w):
    """Claims the item has another digestID than the MSO entry it points to."""
    w.update(digest_id_cbor=uint_cbor(w["digest_id"] + 1))


def execute(w):
    order = g.PUBLIC + ["y_cbor", "x_cbor"] + g.PRIVATE
    with tempfile.TemporaryDirectory() as tmp:
        # mirror implementations/: int/ depends on ../lib, which depends on ../../iso/lib
        root = Path(tmp)
        for d in ["lib", "int"]:
            shutil.copytree(HERE / d, root / "longfellow" / d, ignore=shutil.ignore_patterns("target"))
        shutil.copytree(HERE.parent / "iso" / "lib", root / "iso" / "lib", ignore=shutil.ignore_patterns("target"))
        work = root / "longfellow" / "int"
        (work / "Prover.toml").write_text(g.to_toml(w, order))
        res = subprocess.run(["nargo", "execute"], cwd=work, capture_output=True, text=True)
        out = res.stdout + res.stderr
        if res.returncode == 0:
            return None
        for line in out.splitlines():
            if "Assertion failed:" in line:
                return line.split("Assertion failed:", 1)[1].strip().rstrip(".")
        return out.strip().splitlines()[-1]


# (name, credential builder, tampering, expected assertion or None if it must succeed)
TESTS = [
    ("honest credential", credential, None, None),
    ("forged attribute digest after the signed bytes", credential, forged_digest, OUTSIDE),
    ("attacker device key after the signed bytes", credential, own_device_key, OUTSIDE),
    ("later validUntil after the signed bytes", credential, later_valid_until, OUTSIDE),
    ("item digestID different from the MSO entry's key", credential, other_digest_id, "digestID mismatch"),
    ("attribute digest signed under MSO[status]", nested_namespace, None,
     "Namespace is not in valueDigests"),
    ("later validUntil signed under MSO[status]", nested_valid_until, None,
     "validUntil is not in validityInfo"),
    ("attacker device key signed under MSO[status]", nested_device_key, None,
     "deviceKey is not in deviceKeyInfo"),
    # 300-byte string in the MSO (2-byte CBOR length); the aamva namespace is dropped to stay
    # within the 2231-byte bound
    ("MSO with a 300-byte string", lambda: credential({"status": "u" * 300}), None, None),
]


def main():
    g.AAMVA_ELEMENTS[:] = []  # keeps the MSO small enough for the long-string test
    failed = 0
    for name, make, tamper, expected in TESTS:
        w = make()
        if tamper:
            tamper(w)
        got = execute(w)
        ok = got == expected
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}: "
              f"{'accepted' if got is None else 'rejected (' + got + ')'}"
              + ("" if ok else f", expected {'acceptance' if expected is None else expected!r}"))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
