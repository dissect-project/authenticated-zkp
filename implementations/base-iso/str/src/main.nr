// ISO/IEC 18013-5 version of the base str circuit: the private attribute is the elementValue of
// the resident_address item, with no hash binding.
// Every input is CBOR-encoded: the attribute, digestID and random as in the issuer's item, the
// public inputs and their private copies as CBOR values of their natural type, and the hash as
// the MSO stores it in valueDigests (see ../../iso/lib).
use iso::decode_text;

global STRSIZE: u32 = 57;
global SUBSTRSIZE: u32 = 10;

fn contains(string: [u8; STRSIZE], substring: [u8; SUBSTRSIZE]) -> bool {
    let mut found = false;
    for i in 0..(STRSIZE - SUBSTRSIZE + 1) {
        let mut match_found = true;
        for j in 0..SUBSTRSIZE {
            if string[i + j] != substring[j] {
                match_found = false;
            }
        }
        if match_found {
            found = true;
        }
    }
    found
}

fn main(
    x_cbor: [u8; STRSIZE + 2],
    yp_cbor: [u8; SUBSTRSIZE + 1],
    y_cbor: pub [u8; SUBSTRSIZE + 1],
) {
    // First step: decode the public substring and its private copy, CBOR text strings of
    // SUBSTRSIZE bytes (6A <y>), and check that they match
    let y: [u8; SUBSTRSIZE] = decode_text(y_cbor);
    let yp: [u8; SUBSTRSIZE] = decode_text(yp_cbor);
    assert(y == yp, "Provided substring does not match the public one.");
    // Second step: check that x is a CBOR text string of STRSIZE bytes, 78 39 <x>, and decode it
    assert(
        (x_cbor[0] == 0x78) & (x_cbor[1] == STRSIZE as u8),
        "x is not a 57-byte CBOR text string.",
    );
    let mut x = [0; STRSIZE];
    for i in 0..STRSIZE {
        x[i] = x_cbor[2 + i];
    }
    // Third step: check if x contains y
    assert(contains(x, y), "Substring verification has failed.");
}
