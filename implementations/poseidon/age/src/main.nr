use poseidon::poseidon::bn254::hash_2;

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
    dob: [u8; 10],
    todayp: [u8; 10],
    agep: u8,
    today: pub [u8; 10],
    age: pub u8,
    hash: pub [u8; 32],
    salt: [u8; 16],
) {
    // First step: check that public inputs are correct
    assert(today == todayp, "Public input today's date does not match expected value.");
    assert(age == agep, "Public input age does not match expected value.");
    // Second step: convert salt and DOB into single Field elements (big-endian packing)
    let mut dob_field: Field = 0;
    for i in 0..10 {
        dob_field = (dob_field * 256) + (dob[i] as Field);
    }
    let mut salt_field: Field = 0;
    for i in 0..16 {
        salt_field = (salt_field * 256) + (salt[i] as Field);
    }
    // Third step: calculate the hash of the date of birth
    let dob_hash = hash_2([salt_field, dob_field]);
    // Convert the 32-byte input hash into a Field for comparison
    let mut expected_hash_field: Field = 0;
    for i in 0..32 {
        expected_hash_field = (expected_hash_field * 256) + (hash[i] as Field);
    }
    // Fourth step: check wether the provided hash matches the one calculated
    assert(dob_hash == expected_hash_field, "Hash verification has failed.");
    // Fifth step: calculate age from today's date
    let calculated_age: u8 = calculate_age(dob, today);
    // Sixth step: check wether calculated ages is above the limit
    assert(calculated_age >= age, "Age verification has failed.");
}
