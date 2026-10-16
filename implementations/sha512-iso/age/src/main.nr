// ISO/IEC 18013-5 version of the sha512 age circuit: the hash is the SHA-512 digest of the
// birth_date item, whose elementValue is a full-date 1004("YYYY-MM-DD").
// Every input is CBOR-encoded: the attribute, digestID and random as in the issuer's item, the
// public inputs and their private copies as CBOR values of their natural type, and the hash as
// the MSO stores it in valueDigests (see ../../iso/lib).
use iso::{decode_digest, decode_full_date, decode_uint, MAX_UINT_LEN, RANDOM_CBOR_LEN};
use iso_sha512::sha512_item_digest;

global ELEMENT_ID: [u8; 10] = "birth_date".as_bytes();
// D9 03 EC 6A <YYYY-MM-DD>
global DATE_CBOR_LEN: u32 = 14;

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
    dob_cbor: [u8; DATE_CBOR_LEN],
    todayp_cbor: [u8; DATE_CBOR_LEN],
    agep_cbor: [u8; MAX_UINT_LEN],
    today_cbor: pub [u8; DATE_CBOR_LEN],
    age_cbor: pub [u8; MAX_UINT_LEN],
    hash_cbor: pub [u8; 66],
    digest_id_cbor: [u8; MAX_UINT_LEN],
    random_cbor: [u8; RANDOM_CBOR_LEN],
) {
    // First step: decode the public today and age and their private copies (CBOR full-dates and
    // unsigned integers) and check that they match
    let today = decode_full_date(today_cbor);
    let todayp = decode_full_date(todayp_cbor);
    assert(today == todayp, "Public input today's date does not match expected value.");
    let (age, _, _) = decode_uint(age_cbor);
    let (agep, _, _) = decode_uint(agep_cbor);
    assert(age == agep, "Public input age does not match expected value.");
    // Second step: decode the date of birth, a CBOR full-date (D9 03 EC 6A "YYYY-MM-DD")
    let dob_dmy = decode_full_date(dob_cbor);
    // Third step: calculate the hash of IssuerSignedItemBytes
    let dob_hash = sha512_item_digest(
        digest_id_cbor,
        random_cbor,
        ELEMENT_ID,
        dob_cbor,
        DATE_CBOR_LEN,
    );
    // Fourth step: check whether the provided hash, a CBOR byte string as in the MSO, matches
    let hash: [u8; 64] = decode_digest(hash_cbor);
    assert(dob_hash == hash, "Hash verification has failed.");
    // Fifth step: calculate age from today's date ("DD/MM/YYYY")
    let calculated_age: u8 = calculate_age(dob_dmy, today);
    // Sixth step: check wether calculated ages is above the limit
    assert(calculated_age as u64 >= age, "Age verification has failed.");
}
