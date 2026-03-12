use mimc::mimc_bn254;

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

fn main(dob: [u8; 10], today: pub [u8; 10], age: pub u8, hash: pub [u8; 32], salt: pub [u8; 16]) {
    // First step: prepend the salt to the date of birth into a Field array
    let mut input: [Field; 26] = [0; 26];
    for i in 0..16 {
        // Cast u8 to Field
        input[i] = salt[i] as Field;
    }
    for i in 0..10 {
        // Cast u8 to Field
        input[16 + i] = dob[i] as Field;
    }
    // Second step: calculate the hash of the date of birth
    let dob_hash = mimc_bn254(input);
    // Third step: convert the Field hash back into a 32-byte array (Big-Endian)
    // and check whether the provided hash matches the one calculated
    let dob_hash_bytes: [u8; 32] = dob_hash.to_be_bytes();
    assert(dob_hash_bytes == hash, "Hash verification has failed.");
    // Fourth step: calculate age from today's date
    let calculated_age: u8 = calculate_age(dob, today);
    // Fifth step: check whether calculated age is above the limit
    assert(calculated_age >= age, "Age verification has failed.");
}


#[test]
fn test_main() {

    // Test that passes both hash and age verification
    main([50,49,47,48,55,47,50,48,50,53], [49,54,47,48,56,47,49,57,57,57], 20,  [20,115,63,130,241,133,53,135,23,232,2,239,35,51,232,11,208,129,217,235,253,56,190,93,134,211,202,152,252,110,223,23], [110,35,223,147,182,54,91,117,189,6,75,96,206,24,207,176]);

    // Test that fails in age verification
    //main([49,54,47,48,56,47,49,57,57,57], [50,49,47,48,55,47,50,48,50,53], 30, [21,54,128,97,5,129,171,144,86,195,86,153,56,252,12,10,34,131,70,192,177,146,24,172,207,234,101,166,42,217,120,89], [31,230,203,155,87,9,60,127,138,57,159,187,227,67,7,241]);

    // Test that fails in hash verification
    //main([49,54,47,48,56,47,49,57,57,57], [50,49,47,48,55,47,50,48,50,53], 20, [20,54,128,97,5,129,171,144,86,195,86,153,56,252,12,10,34,131,70,192,177,146,24,172,207,234,101,166,42,217,120,89], [31,230,203,155,87,9,60,127,138,57,159,187,227,67,7,241]);
}