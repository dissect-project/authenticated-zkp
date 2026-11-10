// sha256-iso variant, age verification (online alcohol sale): the holder is at least `threshold` years old
// today, from birth_date (a CBOR full-date).
// The private IssuerSignedItemBytes, as issued, is parsed (../../common/lib) and its SHA256 digest
// is checked against the public digest (as the MSO stores it in valueDigests); the predicate is
// checked on the elementValue it holds.
use iso::{
    decode_digest, decode_text, item_value, MAX_UINT_LEN, parse_item, predicates,
    sha256_item_digest,
};

global N: u32 = 128; // maximum size of IssuerSignedItemBytes
global V: u32 = 14; // maximum size of the elementValue

fn main(
    element_id_cbor: pub [u8; 11], // CBOR text string "birth_date"
    hash_cbor: pub [u8; 34], // CBOR byte string, as in valueDigests
    today_cbor: pub [u8; 14], // CBOR full-date: D9 03 EC 6A <YYYY-MM-DD>
    threshold_cbor: pub [u8; MAX_UINT_LEN], // CBOR unsigned integer, zero-padded
    item: [u8; N], // IssuerSignedItemBytes as issued, zero-padded
    item_len: u32,
) {
    let element_id: [u8; 10] = decode_text(element_id_cbor);
    let parsed = parse_item(item, item_len, element_id);
    let value: [u8; V] = item_value(item, parsed);
    let value_len = parsed.value_len;
    predicates::age(value, value_len, today_cbor, threshold_cbor);
    let hash: [u8; 32] = decode_digest(hash_cbor);
    assert(sha256_item_digest(item, item_len) == hash, "Hash verification has failed");
}
