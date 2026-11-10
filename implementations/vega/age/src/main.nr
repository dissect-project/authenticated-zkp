// VegaSC mdoc presentation (see ../lib), age verification (online alcohol sale): the holder is at least `threshold` years old
// today, from birth_date (a CBOR full-date).
use iso::{decode_text, item_value, MAX_UINT_LEN, predicates};
use vega::{Mdoc, MSO_BLOCKS, MSO_PADDED_LEN, N_LOOKUPS, TODAY_CBOR_LEN, verify_mdoc};

global N: u32 = 128; // maximum size of IssuerSignedItemBytes
global V: u32 = 14; // maximum size of the elementValue
global L: u32 = 3; // SHA-256 blocks of the largest item

fn main(
    // ---------------- public statement ----------------
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],
    h_dev: pub [u8; 32], // digest signed by the device
    today_cbor: pub [u8; TODAY_CBOR_LEN], // CBOR full-date: D9 03 EC 6A <YYYY-MM-DD>
    element_id_cbor: pub [u8; 11], // CBOR text string "birth_date"
    threshold_cbor: pub [u8; MAX_UINT_LEN], // CBOR unsigned integer, zero-padded
    // ---------------- private witness ----------------
    signed: [u8; MSO_PADDED_LEN],
    signed_len: u32,
    b_mso: [Field; MSO_BLOCKS],
    addr: [u32; N_LOOKUPS],
    vals: [u8; N_LOOKUPS],
    issuer_sig: [u8; 64],
    item: [u8; N], // IssuerSignedItemBytes as issued, zero-padded
    item_len: u32,
    b_item: [Field; L],
    device_sig: [u8; 64],
) {
    let element_id: [u8; 10] = decode_text(element_id_cbor);
    let mdoc =
        Mdoc { signed, signed_len, b_mso, addr, vals, issuer_sig, item, item_len, device_sig };
    let parsed = verify_mdoc(
        issuer_pk_x,
        issuer_pk_y,
        h_dev,
        today_cbor,
        element_id,
        b_item,
        mdoc,
    );
    let value: [u8; V] = item_value(item, parsed);
    let value_len = parsed.value_len;
    predicates::age(value, value_len, today_cbor, threshold_cbor);
}
