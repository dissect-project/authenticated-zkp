// Longfellow mdoc presentation (see ../lib) with the `nationality` predicate:
// the public nationality is one of the codes of the private nationality list.
// Every input that is CBOR in the mdoc or a public parameter is CBOR-encoded, as in the ISO
// variants: the item fields (digestID, random, elementValue), now (tdate), the elementIdentifier
// and the predicate's public input. Keys, signatures and parser offsets are not CBOR data.
use iso::{decode_text, MAX_UINT_LEN, RANDOM_CBOR_LEN};
use longfellow::{MAX_DA_LEN, MAX_SIGNED_LEN, MAX_TR_LEN, Mdoc, NOW_CBOR_LEN, verify_mdoc};

global Nationalities: u32 = 5; // Maximum number of allowed nationalities
global LIST_CBOR_LEN: u32 = 1 + 3 * Nationalities;

fn main(
    // ---------------- public statement ----------------
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],
    tr: pub [u8; MAX_TR_LEN], // CBOR-encoded SessionTranscript, zero-padded
    tr_len: pub u32,
    now_cbor: pub [u8; NOW_CBOR_LEN], // CBOR tdate: C0 74 <YYYY-MM-DDTHH:MM:SSZ>
    element_id_cbor: pub [u8; 12], // CBOR text string "nationality"
    nationality_cbor: pub [u8; 3], // CBOR text string 62 c1 c2
    // ---------------- private witness ----------------
    list_cbor: [u8; LIST_CBOR_LEN], // CBOR array of 1 to 5 two-letter text strings, zero-padded
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
    let element_id: [u8; 11] = decode_text(element_id_cbor);
    let code: [u8; 2] = decode_text(nationality_cbor);
    // the list is a CBOR array of n two-letter text strings, 8n (62 c1 c2)*n with 1 <= n <= 5;
    // in_list[i] marks the n entries of the array
    let mut in_list = [false; Nationalities];
    let mut list_cbor_len: u32 = 0;
    for k in 1..(Nationalities + 1) {
        let is_n = list_cbor[0] == 0x80 + k as u8;
        if is_n {
            list_cbor_len = 1 + 3 * k;
        }
        for i in 0..k {
            if is_n {
                in_list[i] = true;
            }
        }
    }
    assert(list_cbor_len != 0, "The list is not a CBOR array of 1 to 5 codes.");
    for i in 0..Nationalities {
        if in_list[i] {
            assert(
                list_cbor[1 + 3 * i] == 0x62,
                "List entry is not a two-letter CBOR text string.",
            );
        }
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
        list_cbor,
        list_cbor_len,
        mdoc,
    );
    let mut found = false;
    for i in 0..Nationalities {
        if in_list[i] & (list_cbor[2 + 3 * i] == code[0]) & (list_cbor[3 + 3 * i] == code[1]) {
            found = true;
        }
    }
    assert(found, "Nationality is not in the list.");
}
