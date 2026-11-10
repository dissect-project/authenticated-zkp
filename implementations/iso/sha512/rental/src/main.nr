// sha512-iso variant, car rental: driving_privileges (an array of maps) holds a privilege of `category`
// issued on or before `held_since` and valid until at least `return_date`.
// The private IssuerSignedItemBytes, as issued, is parsed (../../common/lib) and its SHA512 digest
// is checked against the public digest (as the MSO stores it in valueDigests); the predicate is
// checked on the elementValue it holds.
use iso::{decode_digest, decode_text, item_value, parse_item, predicates};
use iso_sha512::sha512_item_digest;

global N: u32 = 512; // maximum size of IssuerSignedItemBytes
global V: u32 = 384; // maximum size of the elementValue

fn main(
    element_id_cbor: pub [u8; 19], // CBOR text string "driving_privileges"
    hash_cbor: pub [u8; 66], // CBOR byte string, as in valueDigests
    category_cbor: pub [u8; 4], // CBOR text string of 1 to 3 characters, zero-padded
    held_since_cbor: pub [u8; 14], // CBOR full-date
    return_date_cbor: pub [u8; 14], // CBOR full-date
    item: [u8; N], // IssuerSignedItemBytes as issued, zero-padded
    item_len: u32,
) {
    let element_id: [u8; 18] = decode_text(element_id_cbor);
    let parsed = parse_item(item, item_len, element_id);
    let value: [u8; V] = item_value(item, parsed);
    let value_len = parsed.value_len;
    predicates::rental(
        value,
        value_len,
        category_cbor,
        held_since_cbor,
        return_date_cbor,
    );
    let hash: [u8; 64] = decode_digest(hash_cbor);
    assert(sha512_item_digest(item, item_len) == hash, "Hash verification has failed");
}
