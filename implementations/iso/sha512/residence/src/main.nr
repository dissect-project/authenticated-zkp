// sha512-iso variant, resident discount: resident_postal_code (a text string, ZIP or ZIP+4) is a ZIP code
// in [zip_min, zip_max].
// The SHA512 digest of the private IssuerSignedItemBytes, as issued, is checked against the public
// digest (as the MSO stores it in valueDigests); the item is then parsed (../../common/lib) and the
// predicate is checked on the elementValue it holds.
use iso::{decode_digest, decode_text, item_value, parse_item, predicates};
use iso_sha512::sha512_item_digest;

global N: u32 = 128; // maximum size of IssuerSignedItemBytes
global V: u32 = 11; // maximum size of the elementValue

fn main(
    element_id_cbor: pub [u8; 21], // CBOR text string "resident_postal_code"
    hash_cbor: pub [u8; 66], // CBOR byte string, as in valueDigests
    zip_min_cbor: pub [u8; 6], // CBOR text string of 5 digits
    zip_max_cbor: pub [u8; 6], // CBOR text string of 5 digits
    item: [u8; N], // IssuerSignedItemBytes as issued, zero-padded
    item_len: u32,
) {
    let hash: [u8; 64] = decode_digest(hash_cbor);
    assert(sha512_item_digest(item, item_len) == hash, "Hash verification has failed");
    let element_id: [u8; 20] = decode_text(element_id_cbor);
    let parsed = parse_item(item, item_len, element_id);
    let value: [u8; V] = item_value(item, parsed);
    let value_len = parsed.value_len;
    predicates::residence(value, value_len, zip_min_cbor, zip_max_cbor);
}
