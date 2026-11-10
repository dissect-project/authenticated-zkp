// base variant, age verification (online alcohol sale): the holder is at least `threshold` years old
// today, from birth_date (a CBOR full-date).
// Only the predicate is checked, on the elementValue exactly as the issuer encoded it: no digest
// and no signature, the reference for the cost of authentication in the other variants.
use iso::{MAX_UINT_LEN, predicates};

global V: u32 = 14; // maximum size of the elementValue

fn main(
    today_cbor: pub [u8; 14], // CBOR full-date: D9 03 EC 6A <YYYY-MM-DD>
    threshold_cbor: pub [u8; MAX_UINT_LEN], // CBOR unsigned integer, zero-padded
    value: [u8; V], // the CBOR-encoded elementValue, zero-padded
    value_len: u32,
) {
    predicates::age(value, value_len, today_cbor, threshold_cbor);
}
