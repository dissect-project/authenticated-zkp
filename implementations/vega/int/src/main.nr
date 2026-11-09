// VegaSC mdoc presentation (see ../lib) with the `int` predicate:
// the private age_in_years x is greater than the public y.
// Every input that is CBOR in the mdoc or a public parameter is CBOR-encoded, as in the ISO
// variants: the item fields (digestID, random, elementValue), today (full-date), the
// elementIdentifier and the predicate's public input. Keys, signatures, digests, lookup
// addresses and selectors are not CBOR data.
use iso::{decode_text, decode_uint, MAX_UINT_LEN, RANDOM_CBOR_LEN};
use vega::{Mdoc, MSO_BLOCKS, MSO_PADDED_LEN, N_LOOKUPS, TODAY_CBOR_LEN, verify_mdoc};

fn main(
    // ---------------- public statement ----------------
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],
    h_dev: pub [u8; 32], // digest signed by the device
    today_cbor: pub [u8; TODAY_CBOR_LEN], // CBOR full-date: D9 03 EC 6A <YYYY-MM-DD>
    element_id_cbor: pub [u8; 13], // CBOR text string "age_in_years"
    y_cbor: pub [u8; MAX_UINT_LEN], // CBOR unsigned integer
    // ---------------- private witness ----------------
    x_cbor: [u8; MAX_UINT_LEN], // CBOR unsigned integer, any encoding, zero-padded
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
    let element_id: [u8; 12] = decode_text(element_id_cbor);
    let (y, _, _) = decode_uint(y_cbor);
    let (x, x_cbor_len, _) = decode_uint(x_cbor);
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
        x_cbor_len,
        b_item,
        mdoc,
    );
    assert(x > y, "x is not greater than y.");
}
