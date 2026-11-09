#!/usr/bin/env python3
"""Generates Prover.toml for the VegaSC mdoc circuits from the Longfellow inputs.

The Vega circuits run on the same credentials as the Longfellow ones: this script reads the
inputs of ../longfellow (its Prover.toml and the runs of its Dart inputs list) and derives the
Vega inputs from the same issuer-signed bytes, issuer signature, IssuerSignedItem and device
signature:

  signed      the issuer-signed Sig_structure with its SHA-256 padding, over 35 blocks
  b_mso       one-hot selector of the block where it ends (Figure 3)
  addr, vals  positions and bytes of deviceKey, validUntil and the item's digest entry (Figure 7)
  b_item      one-hot selector of the block where the IssuerSignedItemBytes end
  h_dev       SHA-256 of the device-signed Sig_structure(DeviceAuthenticationBytes): Vega's
              device signs a digest that is public, so the verifier computes it from the session
  today_cbor  the date of Longfellow's `now`, as a CBOR full-date

Usage:
  ./generate.py SCENARIO                # ../longfellow/SCENARIO/Prover.toml -> SCENARIO/Prover.toml
  ./generate.py SCENARIO --dart         # also convert every run of the Longfellow Dart inputs
SCENARIO is one of int, age, nationality, str.
Requires: pip install cbor2 cryptography (and Python 3.11+ for tomllib)
"""

import argparse
import hashlib
import importlib.util
import io
import re
import sys
import tomllib
from pathlib import Path

import cbor2

HERE = Path(__file__).resolve().parent
LONGFELLOW = HERE.parent / "longfellow"
# the Longfellow generator (build, to_toml, to_dart), loaded under its own name since this file
# is also called generate.py
_spec = importlib.util.spec_from_file_location("longfellow_generate", LONGFELLOW / "generate.py")
lf = importlib.util.module_from_spec(_spec)
sys.modules["longfellow_generate"] = lf
_spec.loader.exec_module(lf)

MSO_BLOCKS = 35
MAX_UINT_LEN = 9
DK_LEN, VU_LEN, DG_LEN = 85, 33, MAX_UINT_LEN + 2 + 32
# item size bound, as in ../../iso/lib: HEAD_LEN + MAX_UINT_LEN + RANDOM_PART_LEN + 1 + E +
# VALUE_KEY_LEN + V + 1 = 80 + E + V bytes (with 16-byte random)
ITEM_FIXED = 80

# scenario -> (public predicate input, private elementValue input)
SCENARIO_KEYS = {
    "int": ("y_cbor", "x_cbor"),
    "age": ("age_cbor", "dob_cbor"),
    "nationality": ("nationality_cbor", "list_cbor"),
    "str": ("y_cbor", "x_cbor"),
}
PUBLIC = ["issuer_pk_x", "issuer_pk_y", "h_dev", "today_cbor", "element_id_cbor"]
PRIVATE = ["signed", "signed_len", "b_mso", "addr", "vals", "issuer_sig", "digest_id_cbor",
           "random_cbor", "b_item", "device_sig"]


def sha256_pad(msg, blocks):
    """msg with its SHA-256 padding, followed by zero blocks up to `blocks` blocks; returns the
    padded bytes and the index of the block where the padding ends."""
    n = len(msg)
    d = (n + 9 + 63) // 64 - 1
    assert d < blocks, f"message of {n} bytes does not fit in {blocks} blocks"
    out = bytearray(64 * blocks)
    out[:n] = msg
    out[n] = 0x80
    out[64 * (d + 1) - 8:64 * (d + 1)] = (8 * n).to_bytes(8, "big")
    return list(out), d


def one_hot(i, n):
    return [int(j == i) for j in range(n)]


def cbor_len(b):
    """Length of the CBOR data item at the start of b (trailing zero padding is ignored)."""
    f = io.BytesIO(bytes(b))
    cbor2.CBORDecoder(f).decode()
    return f.tell()


def convert(w, scenario):
    """Vega inputs from a Longfellow witness (Prover.toml values or generate.build output)."""
    pub_key, val_key = SCENARIO_KEYS[scenario]
    num = lambda k: int(w[k])
    signed_len = num("signed_len")
    msg = bytes(w["signed"][:signed_len])
    signed, d = sha256_pad(msg, MSO_BLOCKS)

    # Figure 7: deviceKey, validUntil and the digest entry, at the offsets Longfellow uses
    addr = ([num("dk_off") + t for t in range(DK_LEN)]
            + [num("vu_off") + t for t in range(VU_LEN)]
            + [num("digest_off") + t for t in range(DG_LEN)])
    vals = [signed[a] for a in addr]

    # IssuerSignedItemBytes length -> the block where its padding ends
    element_id = bytes(w["element_id_cbor"])
    value = w[val_key]
    item_len = (14 + cbor_len(w["digest_id_cbor"]) + 7 + len(w["random_cbor"]) + 18
                + len(element_id) + 13 + cbor_len(value))
    item_blocks = (ITEM_FIXED + (len(element_id) - 1) + len(value) + 8 + 63) // 64
    item_d = (item_len + 9 + 63) // 64 - 1

    now_cbor = bytes(w["now_cbor"])  # C0 74 <YYYY-MM-DDTHH:MM:SSZ>
    assert now_cbor[:2] == b"\xc0\x74"
    today = now_cbor[2:12].decode()
    device_msg = bytes(w["device_msg"][:num("device_msg_len")])
    return {
        "issuer_pk_x": w["issuer_pk_x"],
        "issuer_pk_y": w["issuer_pk_y"],
        "h_dev": list(hashlib.sha256(device_msg).digest()),
        "today_cbor": list(cbor2.dumps(cbor2.CBORTag(1004, today))),
        "element_id_cbor": w["element_id_cbor"],
        pub_key: w[pub_key],
        val_key: value,
        "signed": signed,
        "signed_len": signed_len,
        "b_mso": one_hot(d, MSO_BLOCKS),
        "addr": addr,
        "vals": vals,
        "issuer_sig": w["issuer_sig"],
        "digest_id_cbor": w["digest_id_cbor"],
        "random_cbor": w["random_cbor"],
        "b_item": one_hot(item_d, item_blocks),
        "device_sig": w["device_sig"],
    }


def order(scenario):
    pub_key, val_key = SCENARIO_KEYS[scenario]
    return PUBLIC + [pub_key, val_key] + PRIVATE


def dart_runs(path, template):
    """Splits each run of a Longfellow Dart inputs list back into named inputs, with the input
    order and sizes of `template` (the Longfellow Prover.toml)."""
    keys = list(template)
    sizes = [len(v) if isinstance(v, list) else 1 for v in template.values()]
    text = path.read_text()
    runs = []
    for m in re.finditer(r'"run":\s*(\d+),\s*"inputs":\s*\[([^\]]*)\]', text):
        flat = [int(x) for x in m.group(2).split(",")]
        assert len(flat) == sum(sizes), f"run {m.group(1)}: unexpected number of inputs"
        w, i = {}, 0
        for k, n in zip(keys, sizes):
            w[k] = flat[i:i + n] if isinstance(template[k], list) else flat[i]
            i += n
        runs.append((int(m.group(1)), w))
    return runs


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scenario", choices=list(SCENARIO_KEYS))
    ap.add_argument("--dart", action="store_true",
                    help="also convert every run of the Longfellow Dart inputs list")
    a = ap.parse_args()

    src = LONGFELLOW / a.scenario / "Prover.toml"
    text = src.read_text()
    w = tomllib.loads(text)
    v = convert(w, a.scenario)
    out = HERE / a.scenario / "Prover.toml"
    out.write_text(lf.to_toml(v, order(a.scenario)))
    print(f"{src} -> {out}")

    if a.dart:
        dart_in = LONGFELLOW / a.scenario / f"inputs_longfellow_{a.scenario}.dart"
        dart_out = HERE / a.scenario / f"inputs_vega_{a.scenario}.dart"
        body = "".join(lf.to_dart(convert(r, a.scenario), order(a.scenario), f"vega_{a.scenario}", run)
                       for run, r in dart_runs(dart_in, w))
        dart_out.write_text("final inputs = [\n" + body + "];\n")
        print(f"{dart_in} -> {dart_out}")


if __name__ == "__main__":
    main()
