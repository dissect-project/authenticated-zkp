"""
This script issues a Mobile Document (mDL) and a Mobile Security
Object (MSO) using the pymdoccbor library.
"""

import pprint
import cbor2
from cbor2 import CBORTag
import hashlib

from matplotlib.pylab import rand
from pymdoccbor.mdoc.issuer import MdocCborIssuer, MsoIssuer
from pymdoccbor.mdoc.verifier import MdocCbor

########## SETUP FOR TESTING ##########

PKEY = {
    'KTY': 'EC2',
    'CURVE': 'P_256',
    'ALG': 'ES256',
    'D': b'\x9cD\xacuq\x9b/\xf2\xea\x17I\x13M\x1c\xe7\x19\x8cA\x82\xc1h{|s\xc8\xb1\x82\x04a\x95*\x01',
    'KID': b"demo-kid"
}

PID_DATA = {
    "org.iso.18013.5.1.mDL": {
        "expiry_date": "2050-08-01",
        "issue_date": "2025-08-01",
        "issuing_country": "PT",
        "issuing_authority": "Instituto da Mobilidade e dos Transportes",
        "family_name": "Pessoa",
        "given_name": "Fernando",
        "birth_date": "1888-06-13",
        "document_number": "P-1234567 8",
        "driving_privileges": [
            {
                "vehicle_category_code": "B",
                "issue_date": "2025-08-01",
                "expiry_date": "2050-08-01"
            },
            {
                "vehicle_category_code": "A1",
                "issue_date": "2025-08-01",
                "expiry_date": "2050-08-01"
            },
            {
                "vehicle_category_code": "A2",
                "issue_date": "2025-08-01",
                "expiry_date": "2050-08-01"
            }
        ]
    }
}

def decode_bytes(tagged_bytes):
    decoded_map = cbor2.loads(tagged_bytes)
    return decoded_map

def hash_field_with_id(id, element_id, value, random):
    # The map structure as used in pyMDOC-CBOR
    tag = cbor2.CBORTag(
        24,
        value=cbor2.dumps(
            {
                "digestID": id,
                "random": random,
                "elementIdentifier": element_id,
                "elementValue": value,
            },
            canonical=True,
        ),
    )

    # Canonical CBOR serialize the tagged structure
    cbor_bytes = cbor2.dumps(tag)

    # Hash with SHA-256
    digest = hashlib.sha256(cbor_bytes).digest()

    return digest

def main():
    ########## ISSUE MDOC ##########

    print("Issuing mDL...")

    mdoci = MdocCborIssuer(
        private_key=PKEY,
        alg="ES256"
    )

    mdoc = mdoci.new(
        doctype="org.iso.18013.5.1.mDL",
        data=PID_DATA,
        validity={
            "issuance_date": "2025-08-05",
            "expiry_date": "2030-08-05"
        },
        cert_path="ecdsa_cert.pem",
    )

    #pprint.pprint(mdoc)

    ISSUED_MDOC = mdoci.dump()

    print("mDL issued successfully!")

    ########## ISSUE MSO ALONE ##########

    msoi = MsoIssuer(
        data = PID_DATA,
        private_key = PKEY,
        validity={
            "issuance_date": "2025-08-05",
            "expiry_date": "2030-08-05"
        },
        alg="ES256",
        cert_path="ecdsa_cert.pem"
    )

    mso = msoi.sign()
    #print(msoi.hash_map)


    ########## VERIFY MDOC ##########

    print("Verifying mDL...")

    verifier = MdocCbor()
    verifier.loads(ISSUED_MDOC)
    valid = verifier.verify()

    if valid:
        print("mDL is valid!")
        mdl_readable = verifier.disclosure_map
        print("\n" +"#" * 100 + "\n")
        pprint.pprint(mdl_readable)
        print("\n" +"#" * 100 + "\n")
        pprint.pprint(msoi.hash_map)
        print("\n" + "#" * 40 + " Hashed structures " + "#" * 41 + "\n")
        #pprint.pprint(msoi.disclosure_map)
        for i in msoi.disclosure_map['org.iso.18013.5.1.mDL']:
            print(f"Field: {i}")
            tagged_bytes = msoi.disclosure_map['org.iso.18013.5.1.mDL'][i].value
            decoded_bytes = decode_bytes(tagged_bytes)
            print(f"hash input: {decoded_bytes}")
            print(f"hash output: {hash_field_with_id(
                decoded_bytes['digestID'],
                decoded_bytes['elementIdentifier'],
                decoded_bytes['elementValue'],
                decoded_bytes['random']
            )}\n")
        print("\n" + "#" * 100 + "\n")
        # Let's hash a field from the mDL
        field = "family_name"
        mso_field = 4
        value = mdl_readable['org.iso.18013.5.1.mDL'][field]
        # Print the hashes for comparison
        print("")
        #print("Hashed family_name from mDL:", hashed_family_name)
        
        #print("Hashed family_name from MSO:", mso_hash_map['org.iso.18013.5.1.mDL'][mso_field].hex())

    else:
        print("mDL is invalid!")

if __name__ == "__main__":
    main()