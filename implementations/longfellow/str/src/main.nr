// Longfellow mdoc presentation (see ../lib) with the `str` predicate:
// the private resident_address x contains the public substring y.
// Every input that is CBOR in the mdoc or a public parameter is CBOR-encoded, as in the ISO
// variants: the item fields (digestID, random, elementValue), now (tdate), the elementIdentifier
// and the predicate's public input. Keys, signatures and parser offsets are not CBOR data.
use iso::{decode_text, MAX_UINT_LEN, RANDOM_CBOR_LEN};
use longfellow::{MAX_DA_LEN, MAX_SIGNED_LEN, MAX_TR_LEN, Mdoc, NOW_CBOR_LEN, verify_mdoc};

global STRSIZE: u32 = 57;
global SUBSTRSIZE: u32 = 10;

fn contains(string: [u8; STRSIZE], substring: [u8; SUBSTRSIZE]) -> bool {
    let mut found = false;
    for i in 0..(STRSIZE - SUBSTRSIZE + 1) {
        let mut match_found = true;
        for j in 0..SUBSTRSIZE {
            if string[i + j] != substring[j] {
                match_found = false;
            }
        }
        if match_found {
            found = true;
        }
    }
    found
}

fn main(
    // ---------------- public statement ----------------
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],
    tr: pub [u8; MAX_TR_LEN], // CBOR-encoded SessionTranscript, zero-padded
    tr_len: pub u32,
    now_cbor: pub [u8; NOW_CBOR_LEN], // CBOR tdate: C0 74 <YYYY-MM-DDTHH:MM:SSZ>
    element_id_cbor: pub [u8; 17], // CBOR text string "resident_address"
    y_cbor: pub [u8; SUBSTRSIZE + 1], // CBOR text string 6A <y>
    // ---------------- private witness ----------------
    x_cbor: [u8; STRSIZE + 2], // CBOR text string 78 39 <x>
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
    let element_id: [u8; 16] = decode_text(element_id_cbor);
    let y: [u8; SUBSTRSIZE] = decode_text(y_cbor);
    assert(
        (x_cbor[0] == 0x78) & (x_cbor[1] == STRSIZE as u8),
        "x is not a 57-byte CBOR text string.",
    );
    let mut x = [0; STRSIZE];
    for i in 0..STRSIZE {
        x[i] = x_cbor[2 + i];
    }
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
        STRSIZE + 2,
        mdoc,
    );
    assert(contains(x, y), "Substring verification has failed.");
}
