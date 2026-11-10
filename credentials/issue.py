#!/usr/bin/env python3
"""Issues the test mDL credentials with pyMDOC-CBOR, an mdoc implementation independent of the
circuits (IdentityPython, pinned in requirements.txt).

  .venv/bin/python issue.py

Creates a test PKI (a root certificate and a document signer certificate, P-256) and, for each
holder in holders.py, a device key and an mDL with the org.iso.18013.5.1 and
org.iso.18013.5.1.aamva namespaces. Every credential is checked with pyMDOC-CBOR's verifier
(document signer chain, issuer signature and every value digest) before it is written.

Output (committed, since pyMDOC-CBOR stamps the current time and draws random salts):
  pki/root.pem, pki/ds.pem              certificates
  pki/ds_key.pem                        document signer key (test key)
  holders/<name>/mdoc.cbor              the issued mdoc, as pyMDOC-CBOR returns it
  holders/<name>/device_key.pem         the holder's device key (test key)
"""

import datetime
import sys
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mdoc.verifier import MdocCbor

from holders import DOC_TYPE, HOLDERS, MDL, AAMVA, element_data

HERE = Path(__file__).resolve().parent
PKI = HERE / "pki"
OUT = HERE / "holders"


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "US-CA"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def certificates():
    """A root certificate (the IACA of ISO/IEC 18013-5 Annex B) and a document signer certificate
    issued by it."""
    now = datetime.datetime.now(datetime.timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = (x509.CertificateBuilder()
            .subject_name(name("Test IACA")).issuer_name(name("Test IACA"))
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=9 * 365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                           critical=True)
            .sign(root_key, hashes.SHA256()))
    ds_key = ec.generate_private_key(ec.SECP256R1())
    ds = (x509.CertificateBuilder()
          .subject_name(name("Test Document Signer")).issuer_name(root.subject)
          .public_key(ds_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3 * 365))
          .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                         critical=True)
          .sign(root_key, hashes.SHA256()))
    return root, ds, ds_key


def cose_private(key):
    d = key.private_numbers().private_value.to_bytes(32, "big")
    return {"KTY": "EC2", "CURVE": "P_256", "ALG": "ES256", "D": d}


def cose_public(key):
    n = key.public_key().public_numbers()
    return {1: 2, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


def pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def load_pki():
    """The committed test PKI: (root certificate, document signer certificate, its key)."""
    return (x509.load_pem_x509_certificate((PKI / "root.pem").read_bytes()),
            x509.load_pem_x509_certificate((PKI / "ds.pem").read_bytes()),
            serialization.load_pem_private_key((PKI / "ds_key.pem").read_bytes(), None))


def issue(holder, out, pki, data=None, status=None):
    """Issues `holder`'s mDL (or `data`, a {namespace: elements} dict) into the folder `out` and
    checks it with pyMDOC-CBOR's verifier. `status` is passed to pyMDOC-CBOR as the MSO's status
    entry (the tests use it to have the issuer sign extra MSO content)."""
    root, ds, ds_key = pki
    device_key = ec.generate_private_key(ec.SECP256R1())
    issuer = MdocCborIssuer(private_key=cose_private(ds_key), alg="ES256")
    issuer.new(data=data or {MDL: element_data(holder, MDL), AAMVA: element_data(holder, AAMVA)},
               doctype=DOC_TYPE, validity=holder["validity"],
               devicekeyinfo=cose_public(device_key),
               x509_chain=[ds.public_bytes(serialization.Encoding.DER)], revocation=status)
    mdoc = issuer.dump()
    verifier = MdocCbor()
    verifier.loads(mdoc)
    if not verifier.verify(trusted_root_certs=[root]):
        sys.exit(f"{holder['name']}: pyMDOC-CBOR rejects the issued credential")
    out.mkdir(parents=True, exist_ok=True)
    (out / "mdoc.cbor").write_bytes(mdoc)
    (out / "device_key.pem").write_bytes(pem_key(device_key))
    return mdoc


def main():
    PKI.mkdir(exist_ok=True)
    root, ds, ds_key = certificates()
    (PKI / "root.pem").write_bytes(root.public_bytes(serialization.Encoding.PEM))
    (PKI / "ds.pem").write_bytes(ds.public_bytes(serialization.Encoding.PEM))
    (PKI / "ds_key.pem").write_bytes(pem_key(ds_key))

    for holder in HOLDERS:
        mdoc = issue(holder, OUT / holder["name"], (root, ds, ds_key))
        issuer_auth = cbor2.loads(mdoc)["documents"][0]["issuerSigned"]["issuerAuth"]
        mso_bytes = cbor2.loads(issuer_auth[2]).value
        sig_structure = cbor2.dumps(["Signature1", issuer_auth[0], b"", issuer_auth[2]])
        print(f"{holder['name']}: verified; MSO {len(mso_bytes)} bytes, "
              f"signed Sig_structure {len(sig_structure)} bytes")


if __name__ == "__main__":
    main()
