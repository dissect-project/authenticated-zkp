// Longfellow mdoc presentation (see ../lib), car rental: driving_privileges (an array of maps) holds a privilege of `category`
// issued on or before `held_since` and valid until at least `return_date`.
use iso::{decode_text, item_value, predicates};
use longfellow::{MAX_DA_LEN, MAX_SIGNED_LEN, MAX_TR_LEN, Mdoc, NOW_CBOR_LEN, verify_mdoc};

global N: u32 = 512; // maximum size of IssuerSignedItemBytes
global V: u32 = 384; // maximum size of the elementValue

fn main(
    // ---------------- public statement ----------------
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],
    tr: pub [u8; MAX_TR_LEN], // CBOR-encoded SessionTranscript, zero-padded
    tr_len: pub u32,
    now_cbor: pub [u8; NOW_CBOR_LEN], // CBOR tdate: C0 74 <YYYY-MM-DDTHH:MM:SSZ>
    namespace_cbor: pub [u8; 18], // CBOR text string "org.iso.18013.5.1"
    element_id_cbor: pub [u8; 19], // CBOR text string "driving_privileges"
    category_cbor: pub [u8; 4], // CBOR text string of 1 to 3 characters, zero-padded
    held_since_cbor: pub [u8; 14], // CBOR full-date
    return_date_cbor: pub [u8; 14], // CBOR full-date
    // ---------------- private witness ----------------
    signed: [u8; MAX_SIGNED_LEN],
    signed_len: u32,
    issuer_sig: [u8; 64],
    item: [u8; N], // IssuerSignedItemBytes as issued, zero-padded
    item_len: u32,
    ns_off: u32,
    digest_off: u32,
    dk_off: u32,
    vf_off: u32,
    vu_off: u32,
    dt_off: u32,
    da_off: u32,
    device_sig: [u8; 64],
    device_msg: [u8; MAX_DA_LEN],
    device_msg_len: u32,
) {
    let element_id: [u8; 18] = decode_text(element_id_cbor);
    let mdoc = Mdoc {
        signed,
        signed_len,
        issuer_sig,
        item,
        item_len,
        ns_off,
        digest_off,
        dk_off,
        vf_off,
        vu_off,
        dt_off,
        da_off,
        device_sig,
        device_msg,
        device_msg_len,
    };
    let parsed = verify_mdoc(
        issuer_pk_x,
        issuer_pk_y,
        tr,
        tr_len,
        now_cbor,
        namespace_cbor,
        element_id,
        mdoc,
    );
    let value: [u8; V] = item_value(item, parsed);
    let value_len = parsed.value_len;
    predicates::rental(
        value,
        value_len,
        category_cbor,
        held_since_cbor,
        return_date_cbor,
    );
}
