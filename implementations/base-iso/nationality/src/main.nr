// ISO/IEC 18013-5 version of the base nationality circuit: the private attribute is the elementValue of
// the nationality item, with no hash binding.
// Every input is CBOR-encoded: the attribute, digestID and random as in the issuer's item, the
// public inputs and their private copies as CBOR values of their natural type, and the hash as
// the MSO stores it in valueDigests (see ../../iso/lib).
use iso::decode_text;

global Nationalities: u32 = 5; // Maximum number of allowed nationalities
// 8n (62 c1 c2)*n
global LIST_CBOR_LEN: u32 = 1 + 3 * Nationalities;

fn main(list_cbor: [u8; LIST_CBOR_LEN], nationalityp_cbor: [u8; 3], nationality_cbor: pub [u8; 3]) {
    // First step: decode the public nationality and its private copy, two-letter CBOR text
    // strings (62 c1 c2), and check that they match
    let code: [u8; 2] = decode_text(nationality_cbor);
    let codep: [u8; 2] = decode_text(nationalityp_cbor);
    assert(code == codep, "Public input nationality does not match expected value.");
    // Second step: check that the list is a CBOR array of n two-letter text strings,
    // 8n (62 c1 c2)*n with 1 <= n <= 5; in_list[i] marks the n entries of the array
    let mut in_list = [false; Nationalities];
    let mut is_array = false;
    for k in 1..(Nationalities + 1) {
        let is_n = list_cbor[0] == 0x80 + k as u8;
        if is_n {
            is_array = true;
        }
        for i in 0..k {
            if is_n {
                in_list[i] = true;
            }
        }
    }
    assert(is_array, "The list is not a CBOR array of 1 to 5 codes.");
    for i in 0..Nationalities {
        if in_list[i] {
            assert(
                list_cbor[1 + 3 * i] == 0x62,
                "List entry is not a two-letter CBOR text string.",
            );
        }
    }
    // Third step: check if nationality is one of the codes of the list
    let mut found = false;
    for i in 0..Nationalities {
        if in_list[i] & (list_cbor[2 + 3 * i] == code[0]) & (list_cbor[3 + 3 * i] == code[1]) {
            found = true;
        }
    }
    assert(found, "Nationality is not in the list.");
}
