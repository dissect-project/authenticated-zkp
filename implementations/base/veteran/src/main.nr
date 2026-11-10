// base variant, veteran discount: veteran (AAMVA namespace, an unsigned integer) is 1.
// Only the predicate is checked, on the elementValue exactly as the issuer encoded it: no digest
// and no signature, the reference for the cost of authentication in the other variants.
use iso::predicates;

global V: u32 = 9; // maximum size of the elementValue

fn main(
    value: [u8; V], // the CBOR-encoded elementValue, zero-padded
    value_len: u32,
) {
    predicates::veteran(value, value_len);
}
