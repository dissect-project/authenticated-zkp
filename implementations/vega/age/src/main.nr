// VegaSC mdoc presentation (see ../lib) with the `age` predicate, the scenario of the paper
// (Figure 9a, step 4): the age computed from the private birth_date at the public date is at
// least the public threshold.
// Every input that is CBOR in the mdoc or a public parameter is CBOR-encoded, as in the ISO
// variants: the item fields (digestID, random, elementValue), today (full-date), the
// elementIdentifier and the predicate's public input. Keys, signatures, digests, lookup
// addresses and selectors are not CBOR data.
use iso::{decode_full_date, decode_text, decode_uint, MAX_UINT_LEN, RANDOM_CBOR_LEN};
use vega::{Mdoc, MSO_BLOCKS, MSO_PADDED_LEN, N_LOOKUPS, TODAY_CBOR_LEN, verify_mdoc};

fn parse_u8_pair(b1: u8, b2: u8) -> u8 {
    let b1_field: Field = b1.into();
    let b2_field: Field = b2.into();

    let ten: Field = 10;
    let forty_eight: Field = 48;

    let result: Field = (b1_field - forty_eight) * ten + (b2_field - forty_eight);
    assert(result as u8 < 100, "Parsed value out of range");

    result as u8
}

fn parse_year(b1: u8, b2: u8, b3: u8, b4: u8) -> u8 {
    let b1_f: Field = b1.into();
    let b2_f: Field = b2.into();
    let b3_f: Field = b3.into();
    let b4_f: Field = b4.into();

    let forty_eight = 48;
    let ten = 10;
    let hundred = 100;

    let y1 = (b3_f - forty_eight) * ten + (b4_f - forty_eight); // last two digits
    let century_check = (b1_f - forty_eight) * ten + (b2_f - forty_eight); // '19' or '20'

    let year = if century_check == 19 {
        y1
    } else if century_check == 20 {
        y1 + hundred
    } else {
        assert(false, "Unsupported century");
        0.into() // dummy value for type safety
    };

    assert(year as u8 < 255, "Year out of u8 bounds");
    year as u8
}

fn calculate_age(dob: [u8; 10], today: [u8; 10]) -> u8 {
    let dob_day: u8 = parse_u8_pair(dob[0], dob[1]);
    let dob_month: u8 = parse_u8_pair(dob[3], dob[4]);
    let dob_year: u8 = parse_year(dob[6], dob[7], dob[8], dob[9]);

    let today_day: u8 = parse_u8_pair(today[0], today[1]);
    let today_month: u8 = parse_u8_pair(today[3], today[4]);
    let today_year: u8 = parse_year(today[6], today[7], today[8], today[9]);

    assert(today_year >= dob_year, "DOB is in the future");
    let mut age: u8 = today_year - dob_year;

    if (today_month < dob_month) | ((today_month == dob_month) & (today_day < dob_day)) {
        age -= 1;
    }

    assert(age < 255, "Age out of u8 range");

    age
}

fn main(
    // ---------------- public statement ----------------
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],
    h_dev: pub [u8; 32], // digest signed by the device
    today_cbor: pub [u8; TODAY_CBOR_LEN], // CBOR full-date: D9 03 EC 6A <YYYY-MM-DD>
    element_id_cbor: pub [u8; 11], // CBOR text string "birth_date"
    age_cbor: pub [u8; MAX_UINT_LEN], // CBOR unsigned integer
    // ---------------- private witness ----------------
    dob_cbor: [u8; 14], // full-date: D9 03 EC 6A <YYYY-MM-DD>
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
    let element_id: [u8; 10] = decode_text(element_id_cbor);
    let (age, _, _) = decode_uint(age_cbor);
    let dob_dmy = decode_full_date(dob_cbor);
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
        dob_cbor,
        14,
        b_item,
        mdoc,
    );
    // today as DD/MM/YYYY for calculate_age
    let today = decode_full_date(today_cbor);
    let calculated_age: u8 = calculate_age(dob_dmy, today);
    assert(calculated_age as u64 >= age, "Age verification has failed.");
}
