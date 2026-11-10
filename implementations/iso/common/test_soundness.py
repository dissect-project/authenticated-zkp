#!/usr/bin/env python3
"""Soundness tests of the shared ISO library: the parsing of IssuerSignedItemBytes (on the
sha256-iso circuits) and the scenario predicates (on the base circuits, which check only the
predicate).

  ../../../credentials/.venv/bin/python test_soundness.py

Items: the issued item (pyMDOC-CBOR: canonical key order, 32-byte random) and the same element in
the key order of the ISO/IEC 18013-5 Annex D examples with a 16-byte random are accepted; a
15-byte random, another elementIdentifier, a tampered value and a value followed by extra bytes are
rejected. Predicates: each scenario's predicate rejects a holder that does not satisfy it.
"""

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "credentials"))
import cbor2  # noqa: E402
from inputs import ITEM_MAX, pad  # noqa: E402
from testkit import committed, execute, report  # noqa: E402


def item_bytes(entries):
    """IssuerSignedItemBytes with the (key, encoded value) entries in this order."""
    inner = b"\xa4" + b"".join(cbor2.dumps(k) + v for k, v in entries)
    return cbor2.dumps(cbor2.CBORTag(24, inner))


def with_item(c, item, scenario="age"):
    """sha256-iso inputs of credential c with `item` and its digest."""
    w = c.inputs("sha256-iso")
    w.update(item=pad(item, ITEM_MAX[scenario]), item_len=len(item),
             hash_cbor=list(cbor2.dumps(hashlib.sha256(item).digest())))
    return w


def annex_d_order(random_len, value_suffix=b"", element="birth_date"):
    c = committed(0, "age")
    item = item_bytes([("digestID", cbor2.dumps(c.digest_id)),
                       ("random", cbor2.dumps(bytes(range(random_len)))),
                       ("elementIdentifier", cbor2.dumps(element)),
                       ("elementValue", c.value + value_suffix)])
    return execute("sha256-iso", "age", with_item(c, item))


def tampered_value():
    """holder1's item with another birth date, against the issued digest."""
    c = committed(0, "age")
    w = c.inputs("sha256-iso")
    item = c.item.replace(b"1990-05-14", b"1980-05-14")
    w.update(item=pad(item, ITEM_MAX["age"]))
    return execute("sha256-iso", "age", w)


def base(holder, scenario, **params):
    c = committed(holder, scenario)
    w = c.inputs("base")
    for k, v in params.items():
        w[k] = v
    return execute("base", scenario, w)


def full_date(d):
    return list(cbor2.dumps(cbor2.CBORTag(1004, d)))


def text(s, n=None):
    b = list(cbor2.dumps(s))
    return b + [0] * ((n or len(b)) - len(b))


def value(c_bytes, scenario):
    from inputs import VALUE_MAX
    return {"value": pad(c_bytes, VALUE_MAX[scenario]), "value_len": len(c_bytes)}


TESTS = [
    # ---------------- IssuerSignedItemBytes ----------------
    ("issued item (canonical order, 32-byte random)",
     lambda: (execute("sha256-iso", "age", committed(0, "age").inputs("sha256-iso")), None)),
    ("Annex D key order, 16-byte random", lambda: (annex_d_order(16), None)),
    ("15-byte random", lambda: (annex_d_order(15), "random has an unsupported length")),
    ("item of another element", lambda: (annex_d_order(16, element="issue_date"),
                                         "Wrong elementIdentifier")),
    ("value followed by an extra byte", lambda: (annex_d_order(16, value_suffix=b"\x00"),
                                                 "IssuerSignedItem entries do not fill the item")),
    ("tampered birth_date", lambda: (tampered_value(), "Hash verification has failed")),
    # ---------------- predicates ----------------
    ("age: under the threshold",
     lambda: (base(3, "age", threshold_cbor=pad(cbor2.dumps(24), 9)), "Age verification has failed")),
    ("rental: no privilege of the category",
     lambda: (base(0, "rental", category_cbor=text("C", 4)), "No privilege of the category")),
    ("rental: privilege held for too short a time",
     lambda: (base(0, "rental", held_since_cbor=full_date("2005-01-01")),
              "Privilege held for too short a time")),
    ("rental: privilege expires before the return",
     lambda: (base(0, "rental", return_date_cbor=full_date("2030-01-01")),
              "Privilege expires before the return")),
    ("residence: ZIP outside the range",
     lambda: (base(0, "residence", zip_min_cbor=text("94100"), zip_max_cbor=text("94199")),
              "Residence verification has failed")),
    ("residence: not a ZIP code",
     lambda: (base(0, "residence", **value(cbor2.dumps("9404A"), "residence")), "Not a ZIP code")),
    ("veteran: value 0", lambda: (base(0, "veteran", **value(b"\x00", "veteran")),
                                  "Veteran verification has failed")),
    ("veteran: value 1 in a non-preferred encoding (18 01)",
     lambda: (base(0, "veteran", **value(b"\x18\x01", "veteran")), None)),
]

if __name__ == "__main__":
    sys.exit(1 if report(TESTS) else 0)
