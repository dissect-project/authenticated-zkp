// ISO/IEC 18013-5 version of the base int circuit: the private attribute is the elementValue of
// the age_in_years item, with no hash binding.
// Every input is CBOR-encoded: the attribute, digestID and random as in the issuer's item, the
// public inputs and their private copies as CBOR values of their natural type, and the hash as
// the MSO stores it in valueDigests (see ../../iso/lib).
use iso::{decode_uint, MAX_UINT_LEN};

fn main(x_cbor: [u8; MAX_UINT_LEN], yp_cbor: [u8; MAX_UINT_LEN], y_cbor: pub [u8; MAX_UINT_LEN]) {
    // First step: decode the public y and its private copy, CBOR unsigned integers, and check
    // that they match
    let (y, _, _) = decode_uint(y_cbor);
    let (yp, _, _) = decode_uint(yp_cbor);
    assert(y == yp, "Public input y does not match expected value.");
    // Second step: decode x, a CBOR unsigned integer whose length is given by its head
    let (x, x_cbor_len, _) = decode_uint(x_cbor);
    // Third step: check if x > y
    assert(x > y, "x is not greater than y.");
}
