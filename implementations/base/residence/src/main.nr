// base variant, resident discount: resident_postal_code (a text string, ZIP or ZIP+4) is a ZIP code
// in [zip_min, zip_max].
// Only the predicate is checked, on the elementValue exactly as the issuer encoded it: no digest
// and no signature, the reference for the cost of authentication in the other variants.
use iso::predicates;

global V: u32 = 11; // maximum size of the elementValue

fn main(
    zip_min_cbor: pub [u8; 6], // CBOR text string of 5 digits
    zip_max_cbor: pub [u8; 6], // CBOR text string of 5 digits
    value: [u8; V], // the CBOR-encoded elementValue, zero-padded
    value_len: u32,
) {
    predicates::residence(value, value_len, zip_min_cbor, zip_max_cbor);
}
