#!/usr/bin/env python3
"""Soundness tests of the ISO variants (sha256-iso, sha512-iso, poseidon-iso) and of the library
they share (../common/lib: IssuerSignedItemBytes parsing and the scenario predicates).

  ../../../credentials/.venv/bin/python test_soundness.py [--variants V ...] [-k TEXT]

Threat model. The verifier fixes the public inputs: the requested elementIdentifier, the digest h
it read from the issuer-signed MSO, and the scenario's parameters. The prover controls the private
inputs: the item and its length. A test runs the circuit (nargo execute) on the given inputs and
checks that it accepts them, or rejects them with the expected assertion.

Groups:
  honest        every holder in every scenario is accepted
  binding       the private item differs from the one the issuer committed to (h is the issued
                item's digest): rejected by the digest check, whatever the change
  substitution  a genuine item of another element of the same credential, with its genuine digest:
                rejected by the elementIdentifier check
  encoding      items the issuer could have encoded differently (their own digest): accepted when
                they are valid IssuerSignedItemBytes, rejected otherwise
  predicates    the elementValue and the public parameters at and beyond the predicates'
                boundaries, also on the base circuits (the predicate alone)
  public        malformed public inputs

Each test runs on every ISO variant (and base, for the predicates), so the three digests and the
shared code are tested on the same cases. Tests marked "documented" record accepted behaviour that
is not an attack (e.g. a date the issuer signed that is not a calendar date).
"""

import argparse
import hashlib
import itertools
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "credentials"))
import cbor2  # noqa: E402
from cbor2 import CBORTag  # noqa: E402
from holders import AAMVA, HOLDERS, MDL  # noqa: E402
from inputs import (BN254_P, ITEM_MAX, MAX_UINT_LEN, VALUE_MAX, full_date, pad,  # noqa: E402
                    poseidon, tstr, uint)
from testkit import committed, execute  # noqa: E402

ISO = ["sha256-iso", "sha512-iso", "poseidon-iso"]
ALL = ["base"] + ISO
HASH = "Hash verification has failed"
WRONG_ID = "Wrong elementIdentifier"
NOT_FILLED = "IssuerSignedItem entries do not fill the item"
REJECTED = object()  # any rejection


# ---------------------------------------------------------------- inputs

def digest(variant, item):
    """The digest an issuer using the variant's algorithm puts in the MSO for `item`."""
    if variant == "sha256-iso":
        return hashlib.sha256(item).digest()
    if variant == "sha512-iso":
        return hashlib.sha512(item).digest()
    return poseidon(item)


def honest(variant, scenario, holder=0, **params):
    """The inputs of a holder's issued credential, with public parameters overridden."""
    w = committed(holder, scenario).inputs(variant)
    w.update(params)
    return w


def with_item(variant, scenario, item, committed_item=None, item_len=None, **params):
    """Inputs with the private `item`, against the digest of `committed_item` (the item the issuer
    signed; default `item` itself, i.e. an item the issuer could have encoded this way)."""
    w = honest(variant, scenario, **params)
    w.update(item=pad(item, ITEM_MAX[scenario]),
             item_len=len(item) if item_len is None else item_len,
             hash_cbor=list(cbor2.dumps(digest(variant, committed_item or item))))
    return w


CANONICAL = ("random", "digestID", "elementValue", "elementIdentifier")  # pyMDOC-CBOR's order
VALUE_LAST = ("random", "digestID", "elementIdentifier", "elementValue")


def make_item(scenario, value=None, *, element=None, order=CANONICAL, random=None, random_enc=None,
              id_enc=None, element_enc=None, keys=None, extra=(), trailing=b"", tag=24,
              long_head=False, len_delta=0):
    """IssuerSignedItemBytes for holder1's element of `scenario`, with the fields of the issued
    item unless overridden. `value` is the encoded elementValue; `order` lists the entries
    (a key may repeat); `keys` renames keys; `extra` appends (key, encoded value) entries;
    `trailing` follows the map inside the byte string; `len_delta` corrupts the bstr length."""
    c = committed(0, scenario)
    issued = cbor2.loads(cbor2.loads(c.item).value)
    fields = {
        "random": random_enc if random_enc is not None
        else cbor2.dumps(issued["random"] if random is None else random),
        "digestID": id_enc if id_enc is not None else cbor2.dumps(c.digest_id),
        "elementValue": c.value if value is None else value,
        "elementIdentifier": element_enc if element_enc is not None
        else cbor2.dumps(element or c.element),
    }
    keys = keys or {}
    entries = [(keys.get(k, k), fields[k]) for k in order] + list(extra)
    inner = bytes([0xA0 + len(entries)]) + b"".join(cbor2.dumps(k) + v for k, v in entries) + trailing
    n = len(inner) + len_delta
    head = b"\x59" + n.to_bytes(2, "big") if long_head or n > 255 else b"\x58" + bytes([n])
    return b"\xd8" + bytes([tag]) + head + inner


def with_value(variant, scenario, value, order=CANONICAL, **params):
    """Inputs whose elementValue is `value`: directly for base, in an item (entries in `order`)
    for the ISO variants."""
    if variant == "base":
        w = honest("base", scenario, **params)
        w.update(value=pad(value, VALUE_MAX[scenario]), value_len=len(value))
        return w
    return with_item(variant, scenario, make_item(scenario, value, order=order), **params)


def tamper(item, old, new):
    assert len(old) == len(new) and item.count(old) == 1, (old, new)
    return item.replace(old, new)


def flip(item, offset):
    b = bytearray(item)
    b[offset] ^= 1
    return bytes(b)


def namespace_items(holder, namespace):
    """(elementIdentifier, IssuerSignedItemBytes, digest in the MSO) of every issued item."""
    folder = ROOT / "credentials" / "holders" / HOLDERS[holder]["name"]
    doc = cbor2.loads((folder / "mdoc.cbor").read_bytes())["documents"][0]
    mso = cbor2.loads(cbor2.loads(doc["issuerSigned"]["issuerAuth"][2]).value)
    for t in doc["issuerSigned"]["nameSpaces"][namespace]:
        inner = cbor2.loads(t.value)
        yield (inner["elementIdentifier"], cbor2.dumps(t),
               mso["valueDigests"][namespace][inner["digestID"]])


def uint_enc(n, width):
    """CBOR uint n in a head of `width` bytes (1, 2, 3, 5 or 9), preferred or not."""
    if width == 1:
        assert n < 24
        return bytes([n])
    ai = {2: 24, 3: 25, 5: 26, 9: 27}[width]
    return bytes([ai]) + n.to_bytes(width - 1, "big")


def date(d):
    return cbor2.dumps(CBORTag(1004, d))


def privilege(code, issue, expiry, **extra):
    return {"vehicle_category_code": code, "issue_date": CBORTag(1004, issue),
            "expiry_date": CBORTag(1004, expiry)} | extra


def privileges(*ps):
    return cbor2.dumps(list(ps))


def checked_builder(v):
    assert make_item("age") == committed(0, "age").item, "make_item does not reproduce the item"
    return with_item(v, "age", make_item("age"))


# ---------------------------------------------------------------- tests
# A test is (name, scenario, build(variant) -> inputs, expected, variants); expected is None
# (accepted), an assertion message, REJECTED, or a dict by variant with a "default".

GROUPS = {}


def test(group, name, scenario, build, expected, variants=ISO):
    GROUPS.setdefault(group, []).append((name, scenario, build, expected, variants))


SCEN = ["age", "rental", "residence", "veteran"]

# ---- honest: every holder in every scenario
for s in SCEN:
    for h in range(len(HOLDERS)):
        test("honest", f"{s}: holder{h + 1}", s, lambda v, s=s, h=h: honest(v, s, h), None)

# ---- binding: the private item is not the one the issuer committed to
for s in SCEN:
    c = committed(0, s)
    issued = c.item
    rand_off = issued.index(cbor2.dumps("random")) + 9  # a byte inside the random
    test("binding", f"{s}: random with one bit flipped", s,
         lambda v, s=s, i=issued, o=rand_off: with_item(v, s, flip(i, o), i), HASH)
    test("binding", f"{s}: another digestID", s,
         lambda v, s=s, i=issued, c=c: with_item(
             v, s, tamper(i, cbor2.dumps("digestID") + cbor2.dumps(c.digest_id),
                          cbor2.dumps("digestID") + cbor2.dumps(c.digest_id ^ 1)), i), HASH)
    test("binding", f"{s}: item truncated by one byte (item_len - 1)", s,
         lambda v, s=s, i=issued: with_item(v, s, i, i, item_len=len(i) - 1), HASH)
    test("binding", f"{s}: item extended with a zero byte (item_len + 1)", s,
         lambda v, s=s, i=issued: with_item(v, s, i + b"\x00", i),
         # Poseidon absorbs the item zero-padded, so the digest is the same: the parser rejects it
         {"poseidon-iso": "IssuerSignedItemBytes length mismatch", "default": HASH})
    test("binding", f"{s}: item_len beyond the array", s,
         lambda v, s=s, i=issued: with_item(v, s, i, i, item_len=ITEM_MAX[s] + 1), REJECTED)
    test("binding", f"{s}: item_len 2^32 - 1", s,
         lambda v, s=s, i=issued: with_item(v, s, i, i, item_len=2**32 - 1), REJECTED)
    test("binding", f"{s}: holder3's item of the same element", s,
         lambda v, s=s, i=issued, o=committed(2, s).item: with_item(v, s, o, i), HASH)
    ns = MDL if s != "veteran" else AAMVA
    sibling = next(b for e, b, _ in namespace_items(0, ns)
                   if e != c.element and len(b) <= ITEM_MAX[s])
    test("binding", f"{s}: digest of another element of the credential", s,
         lambda v, s=s, i=issued, o=sibling: with_item(v, s, i, o), HASH)

    def garbage(v, s=s, i=issued):
        w = with_item(v, s, i)
        w["item"] = list(i) + [0xAB] * (ITEM_MAX[s] - len(i))
        return w
    test("binding", f"{s}: bytes after item_len are not zero (documented: ignored)", s,
         garbage, None)

# changes that would make a failing predicate hold, against the issued digest
test("binding", "age: holder4 under 25 (control)", "age",
     lambda v: honest(v, "age", 3, threshold_cbor=uint(25)), "Age verification has failed")
test("binding", "age: holder4's birth_date moved back 10 years", "age",
     lambda v: with_item(v, "age", tamper(committed(3, "age").item, b"2003-07-19", b"1993-07-19"),
                         committed(3, "age").item, threshold_cbor=uint(25)), HASH)
test("binding", "rental: holding B since 2005 (control)", "rental",
     lambda v: honest(v, "rental", held_since_cbor=full_date("2005-01-01")),
     "Privilege held for too short a time")
test("binding", "rental: issue_date of B moved back to 2004", "rental",
     lambda v: with_item(v, "rental",
                         tamper(committed(0, "rental").item, b"2008-06-20", b"2004-06-20"),
                         committed(0, "rental").item, held_since_cbor=full_date("2005-01-01")),
     HASH)
test("binding", "rental: category A (control)", "rental",
     lambda v: honest(v, "rental", category_cbor=pad(tstr("A"), 4)),
     "No privilege of the category")
test("binding", "rental: category B renamed A", "rental",
     lambda v: with_item(v, "rental", tamper(committed(0, "rental").item, b"\x61B", b"\x61A"),
                         committed(0, "rental").item, category_cbor=pad(tstr("A"), 4)), HASH)
test("binding", "residence: ZIP outside 94100-94199 (control)", "residence",
     lambda v: honest(v, "residence", zip_min_cbor=tstr("94100"), zip_max_cbor=tstr("94199")),
     "Residence verification has failed")
test("binding", "residence: ZIP 94041 changed to 94150", "residence",
     lambda v: with_item(v, "residence",
                         tamper(committed(0, "residence").item, b"94041", b"94150"),
                         committed(0, "residence").item,
                         zip_min_cbor=tstr("94100"), zip_max_cbor=tstr("94199")), HASH)
VET0 = make_item("veteran", b"\x00")  # an item the issuer signs for a non-veteran
test("binding", "veteran: non-veteran item (control)", "veteran",
     lambda v: with_item(v, "veteran", VET0), "Veteran verification has failed")
test("binding", "veteran: value 0 changed to 1", "veteran",
     lambda v: with_item(v, "veteran", make_item("veteran", b"\x01"), VET0), HASH)


def poseidon_alias(v):
    w = with_item(v, "age", committed(0, "age").item)
    h = int.from_bytes(bytes(w["hash_cbor"][2:]), "big") + BN254_P
    w["hash_cbor"] = list(cbor2.dumps(h.to_bytes(32, "big")))
    return w


test("binding", "public digest h + p, not reduced mod p (documented: the same Field; the "
     "verifier compares the digest bytes with the MSO)", "age", poseidon_alias, None,
     ["poseidon-iso"])

# ---- substitution: genuine items of other elements, with their genuine digests
for s in SCEN:
    ns = MDL if s != "veteran" else AAMVA
    element = committed(0, s).element
    for e, item, mso_digest in namespace_items(0, ns):
        assert mso_digest == hashlib.sha256(item).digest()
        if e == element or len(item) > ITEM_MAX[s]:
            continue  # the requested element itself, or an item the circuit cannot receive
        test("substitution", f"{s}: issued item of {e}", s,
             lambda v, s=s, i=item: with_item(v, s, i), WRONG_ID)

# ---- encoding: items the issuer could have encoded differently (their own digest)
test("encoding", "the test builder reproduces the issued item", "age", checked_builder, None)
for perm in itertools.permutations(CANONICAL):
    test("encoding", "key order " + ", ".join(perm), "age",
         lambda v, p=perm: with_item(v, "age", make_item("age", order=p)), None)
for n, exp in [(0, "random has an unsupported length"), (15, "random has an unsupported length"),
               (16, None), (23, None), (24, None), (32, None),
               (33, "random has an unsupported length")]:
    test("encoding", f"random of {n} bytes", "age",
         lambda v, n=n: with_item(v, "age", make_item("age", random=bytes(range(n)))), exp)
test("encoding", "random of 16 bytes with a 2-byte head (58 10)", "age",
     lambda v: with_item(v, "age", make_item("age", random_enc=b"\x58\x10" + bytes(16))), None)
test("encoding", "random as a text string", "age",
     lambda v: with_item(v, "age", make_item("age", random_enc=cbor2.dumps("r" * 16))),
     "random is not a CBOR byte string")
DID = committed(0, "age").digest_id
for width in [1, 2, 3, 5, 9]:
    if width == 1 and DID >= 24:
        continue
    test("encoding", f"digestID in a {width}-byte encoding", "age",
         lambda v, w=width: with_item(v, "age", make_item("age", id_enc=uint_enc(DID, w))), None)
for name, enc, exp in [("a negative integer", b"\x20", "Not a CBOR unsigned integer"),
                       ("a text string", cbor2.dumps("7"), "Not a CBOR unsigned integer"),
                       # the entries cannot be located, so a later check fails
                       ("a reserved head (1C)", b"\x1c", REJECTED)]:
    test("encoding", f"digestID {name}", "age",
         lambda v, e=enc: with_item(v, "age", make_item("age", id_enc=e)), exp)
test("encoding", "byte string with a 2-byte length (59 00 LL)", "age",
     lambda v: with_item(v, "age", make_item("age", long_head=True)), None)
test("encoding", "tag 25 instead of 24", "age",
     lambda v: with_item(v, "age", make_item("age", tag=25)), "Not IssuerSignedItemBytes (#6.24)")
for d in [-1, 1]:
    test("encoding", f"byte string length off by {d:+d}", "age",
         lambda v, d=d: with_item(v, "age", make_item("age", len_delta=d)),
         "IssuerSignedItemBytes length mismatch")
test("encoding", "map of 5 entries (an extra key)", "age",
     lambda v: with_item(v, "age", make_item("age", extra=[("extra", b"\x01")])),
     "IssuerSignedItem is not a map of 4 entries")
test("encoding", "map of 3 entries (no digestID)", "age",
     lambda v: with_item(v, "age", make_item(
         "age", order=("random", "elementValue", "elementIdentifier"))),
     "IssuerSignedItem is not a map of 4 entries")
test("encoding", "random twice and no elementValue", "age",
     lambda v: with_item(v, "age", make_item(
         "age", order=("random", "digestID", "random", "elementIdentifier"))),
     "Invalid elementValue key")
for key, wrong, exp in [("digestID", "digestId", "Invalid digestID key"),
                        ("random", "randoM", "Invalid random key"),
                        ("elementIdentifier", "elementIdentifiex", "Invalid elementIdentifier key"),
                        ("elementValue", "elementValuE", "Invalid elementValue key")]:
    test("encoding", f"key {wrong!r} instead of {key!r}", "age",
         lambda v, k=key, w=wrong: with_item(v, "age", make_item("age", keys={k: w})), exp)
for e in ["birth_dates", "birth_dat", "Birth_date", "birth date", "birth_datf"]:
    test("encoding", f"elementIdentifier {e!r}", "age",
         lambda v, e=e: with_item(v, "age", make_item("age", element=e)), WRONG_ID)
test("encoding", "elementIdentifier as a byte string", "age",
     lambda v: with_item(v, "age", make_item("age", element_enc=cbor2.dumps(b"birth_date"))),
     WRONG_ID)
test("encoding", "elementValue (last entry) followed by an extra byte", "age",
     lambda v: with_item(v, "age", make_item("age", committed(0, "age").value + b"\x00",
                                             order=VALUE_LAST)), NOT_FILLED)
test("encoding", "elementValue (third entry, as issued) followed by an extra byte", "age",
     lambda v: with_item(v, "age", make_item("age", committed(0, "age").value + b"\x00")),
     "Invalid elementIdentifier key")
test("encoding", "a byte after the map, inside the byte string", "age",
     lambda v: with_item(v, "age", make_item("age", trailing=b"\x00")), NOT_FILLED)
test("encoding", "elementValue longer than the circuit's bound", "residence",
     lambda v: with_item(v, "residence", make_item("residence", cbor2.dumps("94041-15320"))),
     "elementValue exceeds the maximum size")

# ---- predicates: on base and every ISO variant
P = "predicates"


def value_test(s, name, value, expected, variants=ALL, order=CANONICAL, **params):
    test(P, f"{s}: {name}", s, lambda v: with_value(v, s, value, order, **params), expected,
         variants)


def param_test(s, name, expected, holder=0, variants=ALL, **params):
    test(P, f"{s}: {name}", s, lambda v: honest(v, s, holder, **params), expected, variants)


AGE_FAIL = "Age verification has failed"
param_test("age", "holder1 (36) against threshold 36", None, threshold_cbor=uint(36))
param_test("age", "holder1 (36) against threshold 37", AGE_FAIL, threshold_cbor=uint(37))
param_test("age", "21st birthday is today", None, today_cbor=full_date("2011-05-14"))
param_test("age", "21st birthday is tomorrow", AGE_FAIL, today_cbor=full_date("2011-05-13"))
param_test("age", "threshold 199", AGE_FAIL, threshold_cbor=uint(199))
param_test("age", "threshold 200", "Invalid age threshold", threshold_cbor=uint(200))
param_test("age", "threshold 21 in a 2-byte encoding (18 15)", None,
           threshold_cbor=pad(b"\x18\x15", MAX_UINT_LEN))
param_test("age", "today not a full-date (untagged)", "Not a CBOR full-date",
           today_cbor=pad(cbor2.dumps("2026-11-16"), 14))
value_test("age", "birth_date untagged", cbor2.dumps("1990-05-14"),
           "birth_date is not a CBOR full-date")
value_test("age", "birth_date with tag 1005", cbor2.dumps(CBORTag(1005, "1990-05-14")),
           "Not a CBOR full-date")
value_test("age", "birth_date with tag 0 (tdate)", cbor2.dumps(CBORTag(0, "1990-05-14")),
           "birth_date is not a CBOR full-date")
value_test("age", "birth_date 1990/05/14", date("1990/05/14"), "Not a YYYY-MM-DD date")
value_test("age", "birth_date 199O-05-14 (letter O)", date("199O-05-14"), "Not a YYYY-MM-DD date")
value_test("age", "birth_date 1990-5-14", date("1990-5-14"), "birth_date is not a CBOR full-date")
value_test("age", "birth_date 1990-13-45 (documented: not a calendar date, compared as YYYYMMDD)",
           date("1990-13-45"), None)

OLD, FAR = "2008-06-20", "2029-05-14"
NO_CAT = "No privilege of the category"
value_test("rental", "B among four privileges", privileges(
    privilege("AM", OLD, FAR), privilege("A", OLD, FAR), privilege("BE", OLD, FAR),
    privilege("B", OLD, FAR)), None)
value_test("rental", "keys in another order", cbor2.dumps([
    {"expiry_date": CBORTag(1004, FAR), "issue_date": CBORTag(1004, OLD),
     "vehicle_category_code": "B"}]), None)
value_test("rental", "privilege with codes", privileges(
    privilege("B", OLD, FAR, codes=[{"code": "01", "sign": "=", "value": "x"}])), None)
value_test("rental", "only BE, B requested", privileges(privilege("BE", OLD, FAR)), NO_CAT)
value_test("rental", "only B, BE requested", privileges(privilege("B", OLD, FAR)), NO_CAT,
           category_cbor=pad(tstr("BE"), 4))
value_test("rental", "C and CE, C requested",
           privileges(privilege("C", OLD, FAR), privilege("CE", OLD, FAR)), None,
           category_cbor=pad(tstr("C"), 4))
value_test("rental", "C and CE, CE requested",
           privileges(privilege("C", OLD, FAR), privilege("CE", OLD, FAR)), None,
           category_cbor=pad(tstr("CE"), 4))
value_test("rental", "lower-case b", privileges(privilege("b", OLD, FAR)), NO_CAT)
value_test("rental", "B without issue_date", cbor2.dumps(
    [{"vehicle_category_code": "B", "expiry_date": CBORTag(1004, FAR)}]),
    "The privilege has no issue_date")
value_test("rental", "B without expiry_date", cbor2.dumps(
    [{"vehicle_category_code": "B", "issue_date": CBORTag(1004, OLD)}]),
    "The privilege has no expiry_date")
value_test("rental", "recent B, old A (dates of another privilege)", privileges(
    privilege("B", "2025-01-01", FAR), privilege("A", "2000-01-01", FAR)),
    "Privilege held for too short a time")
value_test("rental", "B expiring early, A valid (dates of another privilege)", privileges(
    privilege("B", OLD, "2026-11-01"), privilege("A", OLD, "2035-01-01")),
    "Privilege expires before the return")
value_test("rental", "B issued on held_since", privileges(privilege("B", "2024-11-16", FAR)), None)
value_test("rental", "B issued the day after held_since",
           privileges(privilege("B", "2024-11-17", FAR)), "Privilege held for too short a time")
value_test("rental", "B expiring on return_date", privileges(privilege("B", OLD, "2026-11-23")),
           None)
value_test("rental", "B expiring the day before return_date",
           privileges(privilege("B", OLD, "2026-11-22")), "Privilege expires before the return")
value_test("rental", "B only in a map nested in another privilege", privileges(
    privilege("A", OLD, FAR, codes=[privilege("B", OLD, FAR)])), "Invalid driving privilege")
value_test("rental", "B only as an array element, not a key", privileges(
    privilege("A", OLD, FAR, codes=["vehicle_category_code", "B"])), "Invalid driving privilege")
value_test("rental", "a single map, not an array", cbor2.dumps(privilege("B", OLD, FAR)),
           "driving_privileges is not an array")
# in an item, the entries cannot be located (definite lengths only), so a parser check fails
value_test("rental", "indefinite-length array",
           b"\x9f" + cbor2.dumps(privilege("B", OLD, FAR)) + b"\xff",
           {"base": "Invalid CBOR token", "default": REJECTED})
value_test("rental", "two items (the array, then another)",
           privileges(privilege("B", OLD, FAR)) + b"\x00",
           {"base": "CBOR item is not well-formed", "default": NOT_FILLED}, order=VALUE_LAST)
param_test("rental", "empty category", "Invalid vehicle category", category_cbor=[0x60, 0, 0, 0])
param_test("rental", "category of 4 characters", "Invalid vehicle category",
           category_cbor=[0x64, 0x41, 0x42, 0x43])

RES = "Residence verification has failed"
for z, exp in [("94035", None), ("94043", None), ("94034", RES), ("94044", RES),
               ("94040-1532", None), ("94044-0000", RES)]:
    value_test("residence", f"ZIP {z}", cbor2.dumps(z), exp)
for z, exp in [("9404", "Not a US ZIP code"), ("940411", "Not a US ZIP code"),
               ("94041 1532", "Not a US ZIP+4 code"), ("94041-15a2", "Not a US ZIP+4 code"),
               ("9404A", "Not a ZIP code"), ("", "Not a US ZIP code")]:
    value_test("residence", f"value {z!r}", cbor2.dumps(z), exp)
value_test("residence", "ZIP as an integer", cbor2.dumps(94041),
           "resident_postal_code is not a CBOR text string")
value_test("residence", "ZIP as a byte string", cbor2.dumps(b"94041"),
           "resident_postal_code is not a CBOR text string")
param_test("residence", "range 94041-94041", None,
           zip_min_cbor=tstr("94041"), zip_max_cbor=tstr("94041"))
param_test("residence", "empty range 94043-94035", RES,
           zip_min_cbor=tstr("94043"), zip_max_cbor=tstr("94035"))
param_test("residence", "range bound of 4 digits", "Invalid ZIP range",
           zip_min_cbor=pad(tstr("9403"), 6))

VET = "Veteran verification has failed"
for width in [1, 2, 3, 5, 9]:
    value_test("veteran", f"1 in a {width}-byte encoding", uint_enc(1, width), None)
for name, enc, exp in [("0", b"\x00", VET), ("2", b"\x02", VET), ("256", uint_enc(256, 3), VET),
                       ("2^32 + 1", uint_enc(2**32 + 1, 9), VET),
                       ("true", b"\xf5", "Not a CBOR unsigned integer"),
                       ("-1", b"\x20", "Not a CBOR unsigned integer"),
                       ("the text \"1\"", cbor2.dumps("1"), "Not a CBOR unsigned integer"),
                       ("a reserved head (1C)", b"\x1c",
                        {"base": "Invalid CBOR integer head", "default": REJECTED})]:
    value_test("veteran", f"value {name}", enc, exp)
value_test("veteran", "1 followed by another item", b"\x01\x00",
           {"base": "veteran is not a CBOR unsigned integer", "default": NOT_FILLED},
           order=VALUE_LAST)

# ---- public: malformed public inputs (the verifier's encoding)
for s in SCEN:
    def bad_id(v, s=s):
        w = honest(v, s)
        w["element_id_cbor"] = [w["element_id_cbor"][0] - 0x20] + w["element_id_cbor"][1:]
        return w

    def bad_hash(v, s=s):
        w = honest(v, s)
        w["hash_cbor"] = [0x59] + w["hash_cbor"][1:]
        return w
    test("public", f"{s}: elementIdentifier as a byte string", s, bad_id,
         "Not a CBOR text string of the expected length")
    test("public", f"{s}: digest without the byte-string head", s, bad_hash,
         "Not a CBOR byte string of the digest length")


# ---------------------------------------------------------------- runner

def expected_for(expected, variant):
    if isinstance(expected, dict):
        return expected.get(variant, expected["default"])
    return expected


def show(r):
    if r is REJECTED:
        return "rejected"
    return "accepted" if r is None else f"rejected ({r})"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--variants", nargs="+", choices=ALL, default=ALL)
    ap.add_argument("-k", metavar="TEXT", help="only the tests whose name contains TEXT")
    args = ap.parse_args()
    total = failed = 0
    for group, tests in GROUPS.items():
        print(f"\n== {group}", flush=True)
        for name, scenario, build, expected, variants in tests:
            if args.k and args.k not in name:
                continue
            for v in variants:
                if v not in args.variants:
                    continue
                exp = expected_for(expected, v)
                got = execute(v, scenario, build(v))
                ok = (got is not None) if exp is REJECTED else got == exp
                total += 1
                failed += not ok
                print(f"{'PASS' if ok else 'FAIL'}  [{v}] {name}: {show(got)}"
                      + ("" if ok else f", expected {show(exp)}"), flush=True)
    print(f"\n{total - failed}/{total} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
