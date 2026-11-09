// VegaSC mdoc presentation (see ../lib) with the `str` predicate:
// the private resident_address x contains the public substring y.
// Every input that is CBOR in the mdoc or a public parameter is CBOR-encoded, as in the ISO
// variants: the item fields (digestID, random, elementValue), today (full-date), the
// elementIdentifier and the predicate's public input. Keys, signatures, digests, lookup
// addresses and selectors are not CBOR data.
use iso::{decode_text, MAX_UINT_LEN, RANDOM_CBOR_LEN};
use vega::{Mdoc, MSO_BLOCKS, MSO_PADDED_LEN, N_LOOKUPS, TODAY_CBOR_LEN, verify_mdoc};

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
    h_dev: pub [u8; 32], // digest signed by the device
    today_cbor: pub [u8; TODAY_CBOR_LEN], // CBOR full-date: D9 03 EC 6A <YYYY-MM-DD>
    element_id_cbor: pub [u8; 17], // CBOR text string "resident_address"
    y_cbor: pub [u8; SUBSTRSIZE + 1], // CBOR text string 6A <y>
    // ---------------- private witness ----------------
    x_cbor: [u8; STRSIZE + 2], // CBOR text string 78 39 <x>
    signed: [u8; MSO_PADDED_LEN],
    signed_len: u32,
    b_mso: [Field; MSO_BLOCKS],
    addr: [u32; N_LOOKUPS],
    vals: [u8; N_LOOKUPS],
    issuer_sig: [u8; 64],
    digest_id_cbor: [u8; MAX_UINT_LEN], // as encoded in the item
    random_cbor: [u8; RANDOM_CBOR_LEN], // as encoded in the item
    b_item: [Field; 3],
    device_sig: [u8; 64],
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
        x_cbor,
        STRSIZE + 2,
        b_item,
        mdoc,
    );
    assert(contains(x, y), "Substring verification has failed.");
}
