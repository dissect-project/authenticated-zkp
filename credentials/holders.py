"""Test holders: four California mDLs.

Element identifiers, types and namespaces follow ISO/IEC 18013-5 (Table 5, org.iso.18013.5.1)
and the AAMVA mDL Implementation Guidelines (org.iso.18013.5.1.aamva), as listed by the Multipaz
mDL document type (openwallet-foundation/multipaz, DrivingLicense.kt). Every mandatory element of
both namespaces is present, plus the optional ones a US issuer typically includes.

pyMDOC-CBOR tags birth_date, issue_date and expiry_date (also inside driving_privileges) as
full-date itself; every other date is tagged here.

The scenario parameters (public inputs) are in SCENARIOS; every holder satisfies every scenario,
as each holder is one run of the benchmark.
"""

import hashlib

from cbor2 import CBORTag

DOC_TYPE = "org.iso.18013.5.1.mDL"
MDL = "org.iso.18013.5.1"
AAMVA = "org.iso.18013.5.1.aamva"

# Presentation time of every proof, after issuance (validFrom is the issuing time)
PRESENTATION = "2026-11-16T10:00:00Z"

SCENARIOS = {
    # online alcohol sale: at least 21 in the US
    "age": {"element": (MDL, "birth_date"), "today": "2026-11-16", "threshold": 21},
    # car rental: category B, held for at least 2 years, valid until the car is returned
    "rental": {"element": (MDL, "driving_privileges"), "category": "B",
               "held_since": "2024-11-16", "return_date": "2026-11-23"},
    # resident discount (Mountain View, CA): ZIP code from 94035 to 94043
    "residence": {"element": (MDL, "resident_postal_code"), "zip_min": "94035", "zip_max": "94043"},
    # veteran discount
    "veteran": {"element": (AAMVA, "veteran")},
}


def full_date(d):
    return CBORTag(1004, d)


def portrait(seed, size):
    """Stand-in for the JPEG portrait: SOI/EOI markers around deterministic bytes. The circuits
    only see its digest, so its size (typical of mDL portraits) matters, not its content."""
    body = b"".join(hashlib.sha256(f"{seed}-{i}".encode()).digest() for i in range(size // 32))
    return b"\xff\xd8\xff\xe0" + body + b"\xff\xd9"


def privilege(code, issue, expiry):
    # pyMDOC-CBOR tags issue_date and expiry_date
    return {"vehicle_category_code": code, "issue_date": issue, "expiry_date": expiry}


def domestic_privilege(code, description, issue, expiry):
    return {"domestic_vehicle_class": {
        "domestic_vehicle_class_code": code,
        "domestic_vehicle_class_description": description,
        "issue_date": full_date(issue),
        "expiry_date": full_date(expiry),
    }}


HOLDERS = [
    {
        "name": "holder1",
        "validity": {"issuance_date": "2026-11-10", "expiry_date": "2027-11-10"},
        MDL: {
            "family_name": "Sample", "given_name": "Alex", "birth_date": "1990-05-14",
            "issue_date": "2024-03-02", "expiry_date": "2029-05-14", "issuing_country": "US",
            "issuing_authority": "California DMV", "document_number": "D1234567",
            "portrait": portrait("holder1", 9600),
            "driving_privileges": [privilege("B", "2008-06-20", "2029-05-14")],
            "un_distinguishing_sign": "USA", "sex": 2, "height": 168, "weight": 61,
            "eye_colour": "brown", "hair_colour": "brown", "resident_address": "450 Castro St",
            "resident_city": "Mountain View", "resident_state": "CA",
            "resident_postal_code": "94041", "resident_country": "US",
            "issuing_jurisdiction": "US-CA", "portrait_capture_date": full_date("2024-02-21"),
            "age_over_18": True, "age_over_21": True, "age_over_65": False,
        },
        AAMVA: {
            "domestic_driving_privileges": [
                domestic_privilege("C", "Class C", "2008-06-20", "2029-05-14")],
            "family_name_truncation": "N", "given_name_truncation": "N", "sex": 2,
            "DHS_compliance": "F", "resident_county": "085", "veteran": 1, "aamva_version": 1,
        },
    },
    {
        "name": "holder2",
        "validity": {"issuance_date": "2026-11-10", "expiry_date": "2027-11-10"},
        MDL: {
            "family_name": "Garcia Lopez", "given_name": "Maria Elena", "birth_date": "1983-11-02",
            "issue_date": "2023-10-15", "expiry_date": "2028-11-02", "issuing_country": "US",
            "issuing_authority": "California DMV", "document_number": "F7654321",
            "portrait": portrait("holder2", 12800),
            "driving_privileges": [
                privilege("A", "2012-04-11", "2028-11-02"),
                privilege("B", "2001-12-05", "2028-11-02"),
            ],
            "un_distinguishing_sign": "USA", "sex": 2, "height": 160, "weight": 58,
            "eye_colour": "black", "hair_colour": "black",
            "resident_address": "2111 Latham St Apt 214", "resident_city": "Mountain View",
            "resident_state": "CA", "resident_postal_code": "94040-1532",
            "resident_country": "US", "issuing_jurisdiction": "US-CA",
            "portrait_capture_date": full_date("2023-09-28"),
            "age_over_18": True, "age_over_21": True, "age_over_65": False,
        },
        AAMVA: {
            "domestic_driving_privileges": [
                domestic_privilege("M1", "Class M1", "2012-04-11", "2028-11-02"),
                domestic_privilege("C", "Class C", "2001-12-05", "2028-11-02")],
            "family_name_truncation": "N", "given_name_truncation": "N", "sex": 2,
            "DHS_compliance": "F", "resident_county": "085", "organ_donor": 1, "veteran": 1,
            "aamva_version": 1,
        },
    },
    {
        "name": "holder3",
        "validity": {"issuance_date": "2026-11-10", "expiry_date": "2027-11-10"},
        MDL: {
            "family_name": "Nguyen", "given_name": "Thanh", "birth_date": "1958-02-27",
            "issue_date": "2025-01-30", "expiry_date": "2030-02-27", "issuing_country": "US",
            "issuing_authority": "California DMV", "document_number": "Y0948316",
            "portrait": portrait("holder3", 7400),
            "driving_privileges": [
                privilege("B", "1976-08-03", "2030-02-27"),
                privilege("C", "1989-05-17", "2030-02-27"),
                privilege("CE", "1991-09-09", "2030-02-27"),
            ],
            "un_distinguishing_sign": "USA", "sex": 1, "height": 172, "weight": 70,
            "eye_colour": "brown", "hair_colour": "grey", "resident_address": "1 Rengstorff Ave",
            "resident_city": "Mountain View", "resident_state": "CA",
            "resident_postal_code": "94043", "resident_country": "US",
            "issuing_jurisdiction": "US-CA", "portrait_capture_date": full_date("2025-01-14"),
            "age_over_18": True, "age_over_21": True, "age_over_65": True,
        },
        AAMVA: {
            "domestic_driving_privileges": [
                domestic_privilege("C", "Class C", "1976-08-03", "2030-02-27"),
                domestic_privilege("A", "Class A", "1989-05-17", "2030-02-27")],
            "family_name_truncation": "N", "given_name_truncation": "N", "sex": 1,
            "DHS_compliance": "F", "resident_county": "085", "veteran": 1, "aamva_version": 1,
        },
    },
    {
        "name": "holder4",
        "validity": {"issuance_date": "2026-11-10", "expiry_date": "2027-11-10"},
        MDL: {
            "family_name": "Okafor", "given_name": "Daniel", "birth_date": "2003-07-19",
            "issue_date": "2026-07-01", "expiry_date": "2031-07-19", "issuing_country": "US",
            "issuing_authority": "California DMV", "document_number": "B5512870",
            "portrait": portrait("holder4", 10900),
            "driving_privileges": [
                privilege("AM", "2019-08-01", "2031-07-19"),
                privilege("A", "2022-03-15", "2031-07-19"),
                privilege("B", "2021-07-22", "2031-07-19"),
                privilege("BE", "2024-02-10", "2031-07-19"),
            ],
            "un_distinguishing_sign": "USA", "sex": 1, "height": 183, "weight": 79,
            "eye_colour": "brown", "hair_colour": "black",
            "resident_address": "100 W El Camino Real Apt 63", "resident_city": "Mountain View",
            "resident_state": "CA", "resident_postal_code": "94035", "resident_country": "US",
            "issuing_jurisdiction": "US-CA", "portrait_capture_date": full_date("2026-06-18"),
            "age_over_18": True, "age_over_21": True, "age_over_65": False,
        },
        AAMVA: {
            "domestic_driving_privileges": [
                domestic_privilege("M2", "Class M2", "2019-08-01", "2031-07-19"),
                domestic_privilege("M1", "Class M1", "2022-03-15", "2031-07-19"),
                domestic_privilege("C", "Class C", "2021-07-22", "2031-07-19")],
            "family_name_truncation": "N", "given_name_truncation": "N", "sex": 1,
            "DHS_compliance": "F", "resident_county": "085", "organ_donor": 1, "veteran": 1,
            "aamva_version": 1,
        },
    },
]


def copy(v):
    if isinstance(v, dict):
        return {k: copy(x) for k, x in v.items()}
    if isinstance(v, list):
        return [copy(x) for x in v]
    if isinstance(v, CBORTag):
        return CBORTag(v.tag, copy(v.value))
    return v


def element_data(holder, namespace):
    """A fresh copy of the holder's elements in a namespace (pyMDOC-CBOR tags dates in place)."""
    return copy(holder[namespace])
