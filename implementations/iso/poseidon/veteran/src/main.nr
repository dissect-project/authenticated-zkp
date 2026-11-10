// poseidon-iso variant, veteran discount: veteran (AAMVA namespace, an unsigned integer) is 1.
// The private IssuerSignedItemBytes, as issued, is parsed (../../common/lib) and its Poseidon digest
// is checked against the public digest (as the MSO stores it in valueDigests); the predicate is
// checked on the elementValue it holds.
use iso::{decode_digest, decode_text, field_from_be_bytes, item_value, parse_item, predicates};
use iso_poseidon::poseidon_item_digest;

global N: u32 = 128; // maximum size of IssuerSignedItemBytes
global V: u32 = 9; // maximum size of the elementValue

fn main(
    element_id_cbor: pub [u8; 8], // CBOR text string "veteran"
    hash_cbor: pub [u8; 34], // CBOR byte string, as in valueDigests
    item: [u8; N], // IssuerSignedItemBytes as issued, zero-padded
    item_len: u32,
) {
    let element_id: [u8; 7] = decode_text(element_id_cbor);
    let parsed = parse_item(item, item_len, element_id);
    let value: [u8; V] = item_value(item, parsed);
    let value_len = parsed.value_len;
    predicates::veteran(value, value_len);
    let hash: [u8; 32] = decode_digest(hash_cbor);
    assert(
        poseidon_item_digest(item, item_len) == field_from_be_bytes(hash),
        "Hash verification has failed",
    );
}
