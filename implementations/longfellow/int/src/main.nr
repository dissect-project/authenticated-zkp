// Longfellow mdoc presentation (see ../lib) with the `int` predicate:
// the private age_in_years x is greater than the public y.
// Every input that is CBOR in the mdoc or a public parameter is CBOR-encoded, as in the ISO
// variants: the item fields (digestID, random, elementValue), now (tdate), the elementIdentifier
// and the predicate's public input. Keys, signatures and parser offsets are not CBOR data.
use iso::{decode_text, decode_uint, MAX_UINT_LEN, RANDOM_CBOR_LEN};
use longfellow::{MAX_DA_LEN, MAX_SIGNED_LEN, MAX_TR_LEN, Mdoc, NOW_CBOR_LEN, verify_mdoc};

fn main(
    // ---------------- public statement ----------------
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],
    tr: pub [u8; MAX_TR_LEN], // CBOR-encoded SessionTranscript, zero-padded
    tr_len: pub u32,
    now_cbor: pub [u8; NOW_CBOR_LEN], // CBOR tdate: C0 74 <YYYY-MM-DDTHH:MM:SSZ>
    element_id_cbor: pub [u8; 13], // CBOR text string "age_in_years"
    y_cbor: pub [u8; MAX_UINT_LEN], // CBOR unsigned integer
    // ---------------- private witness ----------------
    x_cbor: [u8; MAX_UINT_LEN], // CBOR unsigned integer, any encoding, zero-padded
    signed: [u8; MAX_SIGNED_LEN],
    signed_len: u32,
    issuer_sig: [u8; 64],
    digest_id_cbor: [u8; MAX_UINT_LEN], // as encoded in the item
    random_cbor: [u8; RANDOM_CBOR_LEN], // as encoded in the item
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
    let element_id: [u8; 12] = decode_text(element_id_cbor);
    let (y, _, _) = decode_uint(y_cbor);
    let (x, x_cbor_len, _) = decode_uint(x_cbor);
    let mdoc = Mdoc {
        signed,
        signed_len,
        issuer_sig,
        digest_id_cbor,
        random_cbor,
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
    verify_mdoc(
        issuer_pk_x,
        issuer_pk_y,
        tr,
        tr_len,
        now_cbor,
        element_id,
        x_cbor,
        x_cbor_len,
        mdoc,
    );
    assert(x > y, "x is not greater than y.");
}
