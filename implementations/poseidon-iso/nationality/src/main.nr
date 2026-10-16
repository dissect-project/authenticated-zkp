// ISO/IEC 18013-5 version of the poseidon nationality circuit: the hash is the Poseidon digest (not an ISO 18013-5 algorithm) of the
// nationality item of the EU PID (eu.europa.ec.eudi.pid.1), whose
// elementValue is an array of 1 to 5 ISO 3166-1 alpha-2 codes.
// Every input is CBOR-encoded: the attribute, digestID and random as in the issuer's item, the
// public inputs and their private copies as CBOR values of their natural type, and the hash as
// the MSO stores it in valueDigests (see ../../iso/lib).
// Poseidon is not an ISO 18013-5 digest algorithm: no issuer produces this hash, it
// only measures the cost of a SNARK-friendly hash over the same bytes.
use iso::{decode_digest, decode_text, field_from_be_bytes, MAX_UINT_LEN, RANDOM_CBOR_LEN};
use iso_poseidon::poseidon_item_digest;

global ELEMENT_ID: [u8; 11] = "nationality".as_bytes();
global Nationalities: u32 = 5; // Maximum number of allowed nationalities
// 8n (62 c1 c2)*n
global LIST_CBOR_LEN: u32 = 1 + 3 * Nationalities;

fn main(
    list_cbor: [u8; LIST_CBOR_LEN],
    nationalityp_cbor: [u8; 3],
    nationality_cbor: pub [u8; 3],
    hash_cbor: pub [u8; 34],
    digest_id_cbor: [u8; MAX_UINT_LEN],
    random_cbor: [u8; RANDOM_CBOR_LEN],
) {
    // First step: decode the public nationality and its private copy, two-letter CBOR text
    // strings (62 c1 c2), and check that they match
    let code: [u8; 2] = decode_text(nationality_cbor);
    let codep: [u8; 2] = decode_text(nationalityp_cbor);
    assert(code == codep, "Public input nationality does not match expected value.");
    // Second step: check that the list is a CBOR array of n two-letter text strings,
    // 8n (62 c1 c2)*n with 1 <= n <= 5; in_list[i] marks the n entries of the array
    let mut in_list = [false; Nationalities];
    let mut list_cbor_len: u32 = 0;
    for k in 1..(Nationalities + 1) {
        let is_n = list_cbor[0] == 0x80 + k as u8;
        if is_n {
            list_cbor_len = 1 + 3 * k;
        }
        for i in 0..k {
            if is_n {
                in_list[i] = true;
            }
        }
    }
    assert(list_cbor_len != 0, "The list is not a CBOR array of 1 to 5 codes.");
    for i in 0..Nationalities {
        if in_list[i] {
            assert(
                list_cbor[1 + 3 * i] == 0x62,
                "List entry is not a two-letter CBOR text string.",
            );
        }
    }
    // Third step: calculate the hash of IssuerSignedItemBytes
    let list_hash = poseidon_item_digest(
        digest_id_cbor,
        random_cbor,
        ELEMENT_ID,
        list_cbor,
        list_cbor_len,
    );
    // Fourth step: check whether the provided hash, a CBOR byte string as in the MSO, matches
    let hash: [u8; 32] = decode_digest(hash_cbor);
    assert(list_hash == field_from_be_bytes(hash), "Hash verification has failed.");
    // Fifth step: check if nationality is one of the codes of the list
    let mut found = false;
    for i in 0..Nationalities {
        if in_list[i] & (list_cbor[2 + 3 * i] == code[0]) & (list_cbor[3 + 3 * i] == code[1]) {
            found = true;
        }
    }
    assert(found, "Nationality is not in the list.");
}
