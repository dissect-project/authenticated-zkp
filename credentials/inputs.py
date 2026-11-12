"""Circuit inputs from an issued credential (holders/<name>/mdoc.cbor) and a presentation
session (holders/<name>/<scenario>.cbor), for every variant:

  base             the elementValue as issued and the predicate's public parameters
  sha256-iso, ...  the IssuerSignedItemBytes as issued and its digest
  longfellow       the signed MSO, the item, the MSO field offsets and the device message
  vega             the same credential in VegaSC form (padded MSO, lookups, block selectors)

Nothing is re-encoded: the item, the MSO and the session transcript are the bytes the issuer and
the device signed. The only transformation is ECDSA low-s: Barretenberg accepts only signatures
with s <= n/2, and (r, n - s) is an equally valid signature on the same message.

For the sha512-iso and poseidon-iso variants the issuer (SHA-256) gives no digest, so the
digest is computed here over the same item, as an issuer using that algorithm would.
"""

import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import serialization

from holders import AAMVA, DOC_TYPE, MDL, PRESENTATION, SCENARIOS

HERE = Path(__file__).resolve().parent
IMPLEMENTATIONS = HERE.parent / "implementations"

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# circuit bounds (they match the Noir globals)
MAX_SIGNED_LEN = 2231  # longfellow
MAX_TR_LEN = 256
MAX_DA_LEN = 17 + 2 + 2 + 2 + 22 + 2 + MAX_TR_LEN + 26
MSO_BLOCKS = 35  # vega
DK_LEN, VU_LEN, DG_LEN = 85, 33, 9 + 2 + 32
VALUE_MAX = {"age": 14, "rental": 384, "residence": 11, "veteran": 9}
ITEM_MAX = {"age": 128, "rental": 512, "residence": 128, "veteran": 128}
MAX_UINT_LEN = 9


def pad(b, n):
    b = list(b)
    assert len(b) <= n, f"{len(b)} bytes exceed the bound {n}"
    return b + [0] * (n - len(b))


def low_s(sig):
    r, s = sig[:32], int.from_bytes(sig[32:], "big")
    if s > P256_N // 2:
        s = P256_N - s
    return list(r + s.to_bytes(32, "big"))


def full_date(d):
    return list(cbor2.dumps(cbor2.CBORTag(1004, d)))


def uint(v):
    return pad(cbor2.dumps(v), MAX_UINT_LEN)


def tstr(s):
    return list(cbor2.dumps(s))


def one_hot(i, n):
    return [int(j == i) for j in range(n)]


def sha256_pad(msg, blocks):
    """msg with SHA-256 padding, zero-filled to `blocks` blocks, and the index of its last block."""
    padded = msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64) + (8 * len(msg)).to_bytes(8, "big")
    assert len(padded) <= 64 * blocks
    return list(padded) + [0] * (64 * blocks - len(padded)), len(padded) // 64 - 1


def cbor_len(buf, off):
    """Size of the CBOR data item at buf[off:] (definite lengths)."""
    pos, left = off, 1
    while left:
        b = buf[pos]
        major, ai = b >> 5, b & 31
        head = {24: 2, 25: 3, 26: 5, 27: 9}.get(ai, 1)
        arg = ai if ai < 24 else int.from_bytes(buf[pos + 1:pos + head], "big")
        left -= 1
        pos += head
        if major in (2, 3):
            pos += arg
        elif major == 4:
            left += arg
        elif major == 5:
            left += 2 * arg
        elif major == 6:
            left += 1
    return pos - off


def element_value(item):
    """The elementValue bytes of IssuerSignedItemBytes, exactly as issued."""
    inner = cbor2.loads(item).value
    assert inner[0] == 0xA4
    pos = 1
    for _ in range(4):
        key_len = cbor_len(inner, pos)
        key = cbor2.loads(inner[pos:pos + key_len])
        val_len = cbor_len(inner, pos + key_len)
        if key == "elementValue":
            return inner[pos + key_len:pos + key_len + val_len]
        pos += key_len + val_len
    raise ValueError("no elementValue")


def find(buf, pattern, start=0):
    off = buf.find(pattern, start)
    assert off >= 0 and buf.find(pattern, off + 1) < 0, f"pattern not unique: {pattern[:24]!r}"
    return off


class Credential:
    """An issued mdoc, its holder's device key and the presentation session of a scenario."""

    def __init__(self, holder, scenario, folder=None):
        folder = folder or HERE / "holders" / holder
        self.scenario = scenario
        self.params = SCENARIOS[scenario]
        self.namespace, self.element = self.params["element"]
        doc = cbor2.loads((folder / "mdoc.cbor").read_bytes())["documents"][0]
        self.issuer_auth = doc["issuerSigned"]["issuerAuth"]
        self.mso_bytes = cbor2.loads(self.issuer_auth[2]).value
        self.mso = cbor2.loads(self.mso_bytes)
        # the item of the element, exactly as issued: #6.24(bstr)
        items = [cbor2.dumps(t) for t in doc["issuerSigned"]["nameSpaces"][self.namespace]]
        self.item = next(b for b in items if cbor2.loads(cbor2.loads(b).value)["elementIdentifier"]
                         == self.element)
        self.digest_id = cbor2.loads(cbor2.loads(self.item).value)["digestID"]
        self.value = element_value(self.item)
        session = cbor2.loads((folder / f"{scenario}.cbor").read_bytes())
        self.tr = session["SessionTranscript"]
        self.device_sign1 = session["deviceSignature"]
        ds = serialization.load_pem_private_key((HERE / "pki" / "ds_key.pem").read_bytes(), None)
        n = ds.public_key().public_numbers()
        self.issuer_pk = (list(n.x.to_bytes(32, "big")), list(n.y.to_bytes(32, "big")))

    # ---------------- public parameters of the predicate ----------------
    def predicate_params(self):
        p = self.params
        return {
            "age": lambda: {"today_cbor": full_date(p["today"]), "threshold_cbor": uint(p["threshold"])},
            "rental": lambda: {"category_cbor": pad(tstr(p["category"]), 4),
                               "held_since_cbor": full_date(p["held_since"]),
                               "return_date_cbor": full_date(p["return_date"])},
            "residence": lambda: {"zip_min_cbor": tstr(p["zip_min"]), "zip_max_cbor": tstr(p["zip_max"])},
            "veteran": lambda: {},
        }[self.scenario]()

    def element_id_cbor(self):
        return tstr(self.element)

    def item_inputs(self):
        return {"item": pad(self.item, ITEM_MAX[self.scenario]), "item_len": len(self.item)}

    # ---------------- variants ----------------
    def base(self):
        return self.predicate_params() | {
            "value": pad(self.value, VALUE_MAX[self.scenario]), "value_len": len(self.value)}

    def iso(self, h):
        if h == "sha256":
            digest = self.mso["valueDigests"][self.namespace][self.digest_id]
            assert digest == hashlib.sha256(self.item).digest()
        elif h == "sha512":
            digest = hashlib.sha512(self.item).digest()
        else:
            digest = poseidon(self.item)
        return {"element_id_cbor": self.element_id_cbor(), "hash_cbor": list(cbor2.dumps(digest))} \
            | self.predicate_params() | self.item_inputs()

    def signed(self):
        """The issuer-signed bytes: Sig_structure = ["Signature1", protected, h'', payload]."""
        return cbor2.dumps(["Signature1", self.issuer_auth[0], b"", self.issuer_auth[2]])

    def device_msg(self):
        tr = cbor2.loads(self.tr)
        auth = ["DeviceAuthentication", tr, DOC_TYPE, cbor2.CBORTag(24, cbor2.dumps({}))]
        payload = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(auth)))
        return cbor2.dumps(["Signature1", self.device_sign1[0], b"", payload])

    def offsets(self, signed):
        """Offsets of the MSO fields, each searched after its parent's key (so a copy of a field
        elsewhere in the MSO, as in the soundness tests, is not picked)."""
        def under(parent, pattern):
            start = signed.find(cbor2.dumps(parent))
            assert start > 0, parent
            off = signed.find(pattern, start)
            assert off > 0, pattern[:24]
            return off
        ns = cbor2.dumps(self.namespace)
        ns_off = under("valueDigests", ns)
        digest = self.mso["valueDigests"][self.namespace][self.digest_id]
        return {
            "ns_off": ns_off,
            "digest_off": signed.find(cbor2.dumps(self.digest_id) + b"\x58\x20" + digest, ns_off),
            "dk_off": under("deviceKeyInfo", b"\x69deviceKey\xa4"),
            "vf_off": under("validityInfo", b"\x69validFrom\xc0"),
            "vu_off": under("validityInfo", b"\x6avalidUntil\xc0"),
            "dt_off": find(signed, b"\x67docType\x75"),
            "da_off": find(signed, b"\x6fdigestAlgorithm"),
        }

    def longfellow(self):
        signed = self.signed()
        device_msg = self.device_msg()
        assert self.tr in device_msg
        return {
            "issuer_pk_x": self.issuer_pk[0],
            "issuer_pk_y": self.issuer_pk[1],
            "tr": pad(self.tr, MAX_TR_LEN),
            "tr_len": len(self.tr),
            "now_cbor": list(cbor2.dumps(cbor2.CBORTag(0, PRESENTATION))),
            "namespace_cbor": tstr(self.namespace),
            "element_id_cbor": self.element_id_cbor(),
        } | self.predicate_params() | {
            "signed": pad(signed, MAX_SIGNED_LEN),
            "signed_len": len(signed),
            "issuer_sig": low_s(self.issuer_auth[3]),
        } | self.item_inputs() | self.offsets(signed) | {
            "device_sig": low_s(self.device_sign1[3]),
            "device_msg": pad(device_msg, MAX_DA_LEN),
            "device_msg_len": len(device_msg),
        }

    def vega(self):
        signed = self.signed()
        padded, d = sha256_pad(signed, MSO_BLOCKS)
        off = self.offsets(signed)
        # Figure 7: deviceKey, validUntil and the digest entry
        addr = ([off["dk_off"] + t for t in range(DK_LEN)]
                + [off["vu_off"] + t for t in range(VU_LEN)]
                + [off["digest_off"] + t for t in range(DG_LEN)])
        n_item = ITEM_MAX[self.scenario]
        params = self.predicate_params()
        params.pop("today_cbor", None)  # the age scenario's today is Vega's today
        return {
            "issuer_pk_x": self.issuer_pk[0],
            "issuer_pk_y": self.issuer_pk[1],
            "h_dev": list(hashlib.sha256(self.device_msg()).digest()),
            "today_cbor": full_date(PRESENTATION[:10]),
            "element_id_cbor": self.element_id_cbor(),
        } | params | {
            "signed": padded,
            "signed_len": len(signed),
            "b_mso": one_hot(d, MSO_BLOCKS),
            "addr": addr,
            "vals": [padded[a] for a in addr],
            "issuer_sig": low_s(self.issuer_auth[3]),
        } | self.item_inputs() | {
            "b_item": one_hot((len(self.item) + 9 + 63) // 64 - 1, (n_item + 9 + 63) // 64),
            "device_sig": low_s(self.device_sign1[3]),
        }

    def inputs(self, variant):
        if variant == "base":
            return self.base()
        if variant.endswith("-iso"):
            return self.iso(variant[:-4])
        return getattr(self, variant)()


_poseidon_cache = {}
_hasher = None  # a copy of the hasher program, compiled once per process


def poseidon(item):
    """Poseidon digest of the item, from the same Noir code as the poseidon-iso circuits."""
    global _hasher
    if item not in _poseidon_cache:
        if _hasher is None:
            common = IMPLEMENTATIONS / "iso" / "common"
            _hasher = tempfile.TemporaryDirectory()
            for d in ["hasher", "poseidon", "lib"]:
                shutil.copytree(common / d, Path(_hasher.name) / d,
                                ignore=shutil.ignore_patterns("target"))
            subprocess.run(["nargo", "compile"], cwd=Path(_hasher.name) / "hasher", check=True,
                           capture_output=True)
        work = Path(_hasher.name) / "hasher"
        (work / "Prover.toml").write_text(f"item = {pad(item, 992)}\n")
        res = subprocess.run(["nargo", "execute"], cwd=work, capture_output=True, text=True)
        # nargo 1.0 prints the output in hex (0x...), earlier versions as Field(<decimal>)
        out = res.stdout + res.stderr
        m = re.search(r"Circuit output: (?:Field\((-?\d+)\)|(0x[0-9a-fA-F]+))", out)
        if not m:
            raise SystemExit(f"nargo execute failed in hasher:\n{out}")
        value = int(m.group(1)) if m.group(1) else int(m.group(2), 16)
        _poseidon_cache[item] = (value % BN254_P).to_bytes(32, "big")
    return _poseidon_cache[item]
