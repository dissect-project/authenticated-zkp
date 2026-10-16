// Longfellow mdoc presentation (see ../lib) with the `age` predicate:
// the age computed from the private birth_date at the date of `now` is at least the public age.
// Every input that is CBOR in the mdoc or a public parameter is CBOR-encoded, as in the ISO
// variants: the item fields (digestID, random, elementValue), now (tdate), the elementIdentifier
// and the predicate's public input. Keys, signatures and parser offsets are not CBOR data.
use iso::{decode_full_date, decode_text, decode_uint, MAX_UINT_LEN, RANDOM_CBOR_LEN};
use longfellow::{
    decode_tdate, MAX_DA_LEN, MAX_SIGNED_LEN, MAX_TR_LEN, Mdoc, NOW_CBOR_LEN, verify_mdoc,
};

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
    tr: pub [u8; MAX_TR_LEN], // CBOR-encoded SessionTranscript, zero-padded
    tr_len: pub u32,
    now_cbor: pub [u8; NOW_CBOR_LEN], // CBOR tdate: C0 74 <YYYY-MM-DDTHH:MM:SSZ>
    element_id_cbor: pub [u8; 11], // CBOR text string "birth_date"
    age_cbor: pub [u8; MAX_UINT_LEN], // CBOR unsigned integer
    // ---------------- private witness ----------------
    dob_cbor: [u8; 14], // full-date: D9 03 EC 6A <YYYY-MM-DD>
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
    let element_id: [u8; 10] = decode_text(element_id_cbor);
    let (age, _, _) = decode_uint(age_cbor);
    let dob_dmy = decode_full_date(dob_cbor);
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
        dob_cbor,
        14,
        mdoc,
    );
    // today is the date of now, as DD/MM/YYYY for calculate_age
    let now = decode_tdate(now_cbor);
    let today = [now[8], now[9], 0x2f, now[5], now[6], 0x2f, now[0], now[1], now[2], now[3]];
    let calculated_age: u8 = calculate_age(dob_dmy, today);
    assert(calculated_age as u64 >= age, "Age verification has failed.");
}
