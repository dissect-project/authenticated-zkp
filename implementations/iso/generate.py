#!/usr/bin/env python3
"""Writes Prover.toml for the ISO/IEC 18013-5 circuits (sha256-iso, sha512-iso, poseidon-iso, base-iso).

  ./generate.py VARIANT int X Y                         age_in_years = X, prove X > Y
  ./generate.py VARIANT age DOB TODAY AGE               birth_date = DOB, dates as DD/MM/YYYY
  ./generate.py VARIANT nationality PT,EN,--,--,-- EN   nationality list ("--" pads it to 5 codes)
  ./generate.py VARIANT str "ADDRESS" SUBSTRING         resident_address (57 characters)

VARIANT is sha256, sha512, poseidon or base. Each command creates a fresh IssuerSignedItem
(random digestID and 16-byte random). With --item HEX the item is instead an existing
IssuerSignedItemBytes, e.g. from a real mdoc, and only the public arguments are given (int Y,
age TODAY AGE, nationality NAT, str Y). The circuits receive digestID, random and the
elementValue CBOR-encoded, sliced from the item as the issuer encoded them.

hash is H(IssuerSignedItemBytes), the value the verifier finds in the MSO valueDigests. For
poseidon, which no issuer uses, it is computed by running hasher/ with nargo. base takes no hash.
Requires cbor2.
"""

import argparse
import hashlib
import json
import re
import secrets
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

import cbor2

HERE = Path(__file__).resolve().parent
RANDOM_LEN = 16
NATIONALITIES = 5
STRSIZE = 57
KEYS = ["digestID", "random", "elementIdentifier", "elementValue"]
ELEMENT = {"int": "age_in_years", "age": "birth_date", "nationality": "nationality", "str": "resident_address"}
BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
VARIANTS = ["sha256", "sha512", "poseidon", "base"]
PUBLIC_ARGS = {"int": ["Y"], "age": ["TODAY", "AGE"], "nationality": ["NATIONALITY"], "str": ["Y"]}
PRIVATE_ARGS = {"int": ["X"], "age": ["DOB"], "nationality": ["LIST"], "str": ["X"]}


def item_bytes(digest_id, random, element, value):
    item = dict(zip(KEYS, [digest_id, random, element, value]))
    return cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(item)))


def dmy_to_iso(d):
    return datetime.strptime(d, "%d/%m/%Y").strftime("%Y-%m-%d")


def element_value(scenario, private):
    """CBOR elementValue of the private argument, for a new item."""
    if scenario == "int":
        return int(private)
    if scenario == "age":
        return cbor2.CBORTag(1004, dmy_to_iso(private))
    if scenario == "nationality":
        codes = private.split(",")
        if len(codes) != NATIONALITIES or any(len(c) != 2 for c in codes):
            raise SystemExit(f"give {NATIONALITIES} two-letter codes, padded with --")
        n = codes.index("--") if "--" in codes else NATIONALITIES
        if n == 0 or any(c != "--" for c in codes[n:]):
            raise SystemExit("the list needs at least one code and the -- padding at the end")
        return codes[:n]
    if len(private.encode()) != STRSIZE:
        raise SystemExit(f"the address must have {STRSIZE} bytes in UTF-8, not {len(private.encode())}")
    return private


def item_end(b, i):
    """End of the CBOR data item that starts at b[i] (definite lengths only)."""
    major, ai = b[i] >> 5, b[i] & 0x1F
    if ai < 24:
        arg, head = ai, 1
    elif ai <= 27:
        size = 1 << (ai - 24)
        arg, head = int.from_bytes(b[i + 1:i + 1 + size], "big"), 1 + size
    else:
        raise SystemExit("indefinite-length or reserved CBOR encodings are not supported")
    if major in (0, 1, 7):
        return i + head
    if major in (2, 3):
        return i + head + arg
    if major == 6:
        return item_end(b, i + head)
    j = i + head
    for _ in range(arg * (2 if major == 5 else 1)):
        j = item_end(b, j)
    return j


def raw_fields(data):
    """[(key, raw CBOR bytes of the value)] of an IssuerSignedItemBytes, in encoded order."""
    if data[:2] != b"\xd8\x18" or data[2] >> 5 != 2 or item_end(data, 2) != len(data):
        raise SystemExit("not an IssuerSignedItemBytes (#6.24 bstr)")
    start = len(data) - len(cbor2.loads(data[2:]))  # the bstr content starts after its head
    inner = data[start:]
    if inner[0] >> 5 != 5 or item_end(inner, 0) != len(inner):
        raise SystemExit("IssuerSignedItem is not a single CBOR map")
    fields, i = [], 1
    while i < len(inner):
        k_end = item_end(inner, i)
        v_end = item_end(inner, k_end)
        fields.append((cbor2.loads(inner[i:k_end]), inner[k_end:v_end]))
        i = v_end
    return fields


def check_fields(scenario, data):
    """Splits an item into the CBOR-encoded fields the circuits take, checking what they accept."""
    fields = raw_fields(data)
    if [k for k, _ in fields] != KEYS:
        raise SystemExit(f"unsupported key order {[k for k, _ in fields]}")
    raw = dict(fields)
    if cbor2.loads(raw["elementIdentifier"]) != ELEMENT[scenario]:
        raise SystemExit(f"elementIdentifier is {cbor2.loads(raw['elementIdentifier'])!r}, not {ELEMENT[scenario]!r}")
    if raw["digestID"][0] >> 5 != 0:
        raise SystemExit("digestID is not a CBOR unsigned integer")
    if raw["random"][0] != 0x40 + RANDOM_LEN or len(raw["random"]) != 1 + RANDOM_LEN:
        raise SystemExit(f"random must be a {RANDOM_LEN}-byte bstr with a 1-byte head, got {raw['random'][:2].hex()}...")
    v = raw["elementValue"]
    ok = {
        "int": v[0] >> 5 == 0,
        "age": v[:4] == b"\xd9\x03\xec\x6a" and len(v) == 14 and v[8] == v[11] == ord("-"),
        "nationality": 0x81 <= v[0] <= 0x80 + NATIONALITIES and len(v) == 1 + 3 * (v[0] - 0x80)
                       and all(v[1 + 3 * i] == 0x62 for i in range(v[0] - 0x80)),
        "str": v[:2] == bytes([0x78, STRSIZE]) and len(v) == 2 + STRSIZE,
    }[scenario]
    if not ok:
        raise SystemExit(f"elementValue {v.hex()} is not the encoding the {scenario} circuits expect")
    return raw["digestID"], raw["random"], v


def poseidon(data):
    """Poseidon digest of the item, from the same Noir code as the poseidon-iso circuits."""
    with tempfile.TemporaryDirectory() as tmp:
        # hasher/ depends on ../poseidon and ../lib, so copy the whole iso/ folder
        shutil.copytree(HERE, Path(tmp) / "iso", ignore=shutil.ignore_patterns("target", "*.py"))
        work = Path(tmp) / "iso" / "hasher"
        (work / "Prover.toml").write_text(f"item = {list(data.ljust(279, bytes(1)))}\n")
        res = subprocess.run(["nargo", "execute"], cwd=work, capture_output=True, text=True)
        m = re.search(r"Circuit output: Field\((-?\d+)\)", res.stdout + res.stderr)
        if not m:
            raise SystemExit(f"nargo execute failed in hasher:\n{res.stdout}{res.stderr}")
        return (int(m.group(1)) % BN254_P).to_bytes(32, "big")  # nargo prints large values as negative


def digest(variant, data):
    if variant == "sha256":
        return hashlib.sha256(data).digest()
    if variant == "sha512":
        return hashlib.sha512(data).digest()
    return poseidon(data)


# Circuit inputs in ABI order, as (name, value), all CBOR-encoded byte arrays: the attribute,
# digestID and random as sliced from the item; the public inputs and their private copies (yp,
# todayp, agep, nationalityp) as CBOR values of their natural type; and the hash as the MSO stores
# it in valueDigests (a byte string). Integer fields are zero-padded to 9 bytes.
VALUE_SIZE = {"int": 9, "age": 14, "nationality": 1 + 3 * NATIONALITIES, "str": 2 + STRSIZE}
SUBSTRSIZE = 10


def pad(b, n):
    return list(b) + [0] * (n - len(b))


def circuit_inputs(scenario, value, public, hash_, digest_id, random):
    tail = [] if hash_ is None else [("hash_cbor", list(cbor2.dumps(hash_))), ("digest_id_cbor", pad(digest_id, 9)),
                                     ("random_cbor", list(random))]
    v = pad(value, VALUE_SIZE[scenario])
    if scenario == "int":
        (y,) = public
        y_cbor = pad(cbor2.dumps(int(y)), 9)
        return [("x_cbor", v), ("yp_cbor", y_cbor), ("y_cbor", y_cbor)] + tail
    if scenario == "age":
        today, age = public
        today_cbor = list(cbor2.dumps(cbor2.CBORTag(1004, dmy_to_iso(today))))  # full-date, like birth_date
        age_cbor = pad(cbor2.dumps(int(age)), 9)
        return [("dob_cbor", v), ("todayp_cbor", today_cbor), ("agep_cbor", age_cbor),
                ("today_cbor", today_cbor), ("age_cbor", age_cbor)] + tail
    if scenario == "nationality":
        (nat,) = public
        if len(nat.encode()) != 2:
            raise SystemExit("the nationality must be a two-letter code")
        nat_cbor = list(cbor2.dumps(nat))
        return [("list_cbor", v), ("nationalityp_cbor", nat_cbor), ("nationality_cbor", nat_cbor)] + tail
    (y,) = public
    if len(y.encode()) != SUBSTRSIZE:
        raise SystemExit(f"the substring must have {SUBSTRSIZE} bytes")
    y_cbor = list(cbor2.dumps(y))
    return [("x_cbor", v), ("yp_cbor", y_cbor), ("y_cbor", y_cbor)] + tail


def to_toml(inputs):
    return "".join(f"{name} = {json.dumps(value)}\n" for name, value in inputs)


def to_dart(inputs, name, run):
    lines = [f"      ...[{', '.join(map(str, value))}].map((b) => b.toString())," for _, value in inputs]
    return (f'  {{\n    "file": "{name}",\n    "executions": 250,\n    "run": {run},\n'
            f'    "inputs": [\n' + "\n".join(lines) + "\n    ]\n  },\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("variant", choices=VARIANTS)
    ap.add_argument("scenario", choices=list(ELEMENT))
    ap.add_argument("args", nargs="+", metavar="ARG")
    ap.add_argument("--item", metavar="HEX", help="existing IssuerSignedItemBytes in hex")
    ap.add_argument("--digest-id", type=int, help="digestID (default: random below 64)")
    ap.add_argument("--out", type=Path, help="output file (default: VARIANT-iso/SCENARIO/Prover.toml)")
    ap.add_argument("--dart", nargs=2, metavar=("FILE", "RUN"),
                    help="also add the inputs as run RUN of the Dart inputs list FILE")
    args = ap.parse_args()
    s, v = args.scenario, args.variant

    if args.item:
        if len(args.args) != len(PUBLIC_ARGS[s]):
            ap.error(f"with --item give {' '.join(PUBLIC_ARGS[s])}")
        data = bytes.fromhex(args.item)
        public = args.args
    else:
        if len(args.args) != 1 + len(PUBLIC_ARGS[s]):
            ap.error(f"give {' '.join(PRIVATE_ARGS[s] + PUBLIC_ARGS[s])}")
        private, *public = args.args
        digest_id = args.digest_id if args.digest_id is not None else secrets.randbelow(64)
        if not 0 <= digest_id < 2**64:
            raise SystemExit("digestID must fit in a u64")
        data = item_bytes(digest_id, secrets.token_bytes(RANDOM_LEN), ELEMENT[s], element_value(s, private))
    if s == "int" and not all(0 <= int(n) < 2**64 for n in public):
        raise SystemExit("y must fit in a u64")
    digest_id_cbor, random_cbor, value_cbor = check_fields(s, data)
    hash_ = None if v == "base" else digest(v, data)
    inputs = circuit_inputs(s, value_cbor, public, hash_, digest_id_cbor, random_cbor)

    out = args.out or HERE.parent / f"{v}-iso" / s / "Prover.toml"
    out.write_text(to_toml(inputs))
    print(f"IssuerSignedItemBytes: {data.hex()}")
    if hash_ is not None:
        print(f"hash: {hash_.hex()}")
    print(f"wrote {out}")

    if args.dart:
        path, run = Path(args.dart[0]), int(args.dart[1])
        body = path.read_text() if path.exists() else "final inputs = [\n];\n"
        path.write_text(body[:body.rindex("];")] + to_dart(inputs, f"{v}_iso_{s}", run) + "];\n")
        print(f"added run {run} to {path}")


if __name__ == "__main__":
    main()
