// ISO/IEC 18013-5 version of the poseidon int circuit: the hash is the Poseidon digest (not an ISO 18013-5 algorithm) of the
// age_in_years item, whose elementValue is a CBOR unsigned integer.
// Every input is CBOR-encoded: the attribute, digestID and random as in the issuer's item, the
// public inputs and their private copies as CBOR values of their natural type, and the hash as
// the MSO stores it in valueDigests (see ../../iso/lib).
// Poseidon is not an ISO 18013-5 digest algorithm: no issuer produces this hash, it
// only measures the cost of a SNARK-friendly hash over the same bytes.
use iso::{decode_digest, decode_uint, field_from_be_bytes, MAX_UINT_LEN, RANDOM_CBOR_LEN};
use iso_poseidon::poseidon_item_digest;

global ELEMENT_ID: [u8; 12] = "age_in_years".as_bytes();

fn main(
    x_cbor: [u8; MAX_UINT_LEN],
    yp_cbor: [u8; MAX_UINT_LEN],
    y_cbor: pub [u8; MAX_UINT_LEN],
    hash_cbor: pub [u8; 34],
    digest_id_cbor: [u8; MAX_UINT_LEN],
    random_cbor: [u8; RANDOM_CBOR_LEN],
) {
    // First step: decode the public y and its private copy, CBOR unsigned integers, and check
    // that they match
    let (y, _, _) = decode_uint(y_cbor);
    let (yp, _, _) = decode_uint(yp_cbor);
    assert(y == yp, "Public input y does not match expected value.");
    // Second step: decode x, a CBOR unsigned integer whose length is given by its head
    let (x, x_cbor_len, _) = decode_uint(x_cbor);
    // Third step: calculate the hash of IssuerSignedItemBytes
    let x_hash = poseidon_item_digest(digest_id_cbor, random_cbor, ELEMENT_ID, x_cbor, x_cbor_len);
    // Fourth step: check whether the provided hash, a CBOR byte string as in the MSO, matches
    let hash: [u8; 32] = decode_digest(hash_cbor);
    assert(x_hash == field_from_be_bytes(hash), "Hash verification has failed.");
    // Fifth step: check if x > y
    assert(x > y, "x is not greater than y.");
}
