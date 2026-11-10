// Longfellow mdoc presentation (see ../lib), veteran discount: veteran (AAMVA namespace, an unsigned integer) is 1.
use iso::{decode_text, item_value, predicates};
use longfellow::{MAX_DA_LEN, MAX_SIGNED_LEN, MAX_TR_LEN, Mdoc, NOW_CBOR_LEN, verify_mdoc};

global N: u32 = 128; // maximum size of IssuerSignedItemBytes
global V: u32 = 9; // maximum size of the elementValue

fn main(
    // ---------------- public statement ----------------
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],
    tr: pub [u8; MAX_TR_LEN], // CBOR-encoded SessionTranscript, zero-padded
    tr_len: pub u32,
    now_cbor: pub [u8; NOW_CBOR_LEN], // CBOR tdate: C0 74 <YYYY-MM-DDTHH:MM:SSZ>
    namespace_cbor: pub [u8; 24], // CBOR text string "org.iso.18013.5.1.aamva"
    element_id_cbor: pub [u8; 8], // CBOR text string "veteran"
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
    let element_id: [u8; 7] = decode_text(element_id_cbor);
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
    predicates::veteran(value, value_len);
}
