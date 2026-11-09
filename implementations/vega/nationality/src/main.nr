// VegaSC mdoc presentation (see ../lib) with the `nationality` predicate:
// the public nationality is one of the codes of the private nationality list.
// Every input that is CBOR in the mdoc or a public parameter is CBOR-encoded, as in the ISO
// variants: the item fields (digestID, random, elementValue), today (full-date), the
// elementIdentifier and the predicate's public input. Keys, signatures, digests, lookup
// addresses and selectors are not CBOR data.
use iso::{decode_text, MAX_UINT_LEN, RANDOM_CBOR_LEN};
use vega::{Mdoc, MSO_BLOCKS, MSO_PADDED_LEN, N_LOOKUPS, TODAY_CBOR_LEN, verify_mdoc};

global Nationalities: u32 = 5; // Maximum number of allowed nationalities
global LIST_CBOR_LEN: u32 = 1 + 3 * Nationalities;

fn main(
    // ---------------- public statement ----------------
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],
    h_dev: pub [u8; 32], // digest signed by the device
    today_cbor: pub [u8; TODAY_CBOR_LEN], // CBOR full-date: D9 03 EC 6A <YYYY-MM-DD>
    element_id_cbor: pub [u8; 12], // CBOR text string "nationality"
    nationality_cbor: pub [u8; 3], // CBOR text string 62 c1 c2
    // ---------------- private witness ----------------
    list_cbor: [u8; LIST_CBOR_LEN], // CBOR array of 1 to 5 two-letter text strings, zero-padded
    signed: [u8; MSO_PADDED_LEN],
    signed_len: u32,
    b_mso: [Field; MSO_BLOCKS],
    addr: [u32; N_LOOKUPS],
    vals: [u8; N_LOOKUPS],
    issuer_sig: [u8; 64],
    digest_id_cbor: [u8; MAX_UINT_LEN], // as encoded in the item
    random_cbor: [u8; RANDOM_CBOR_LEN], // as encoded in the item
    b_item: [Field; 2],
    device_sig: [u8; 64],
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
        b_mso,
        addr,
        vals,
        issuer_sig,
        digest_id_cbor,
        random_cbor,
        device_sig,
    };
    verify_mdoc(
        issuer_pk_x,
        issuer_pk_y,
        h_dev,
        today_cbor,
        element_id,
        list_cbor,
        list_cbor_len,
        b_item,
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
