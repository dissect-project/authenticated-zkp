// base variant, car rental: driving_privileges (an array of maps) holds a privilege of `category`
// issued on or before `held_since` and valid until at least `return_date`.
// Only the predicate is checked, on the elementValue exactly as the issuer encoded it: no digest
// and no signature, the reference for the cost of authentication in the other variants.
use iso::predicates;

global V: u32 = 384; // maximum size of the elementValue

fn main(
    category_cbor: pub [u8; 4], // CBOR text string of 1 to 3 characters, zero-padded
    held_since_cbor: pub [u8; 14], // CBOR full-date
    return_date_cbor: pub [u8; 14], // CBOR full-date
    value: [u8; V], // the CBOR-encoded elementValue, zero-padded
    value_len: u32,
) {
    predicates::rental(
        value,
        value_len,
        category_cbor,
        held_since_cbor,
        return_date_cbor,
    );
}
