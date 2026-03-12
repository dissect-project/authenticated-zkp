use sha512::sha512::digest;

global Nationalities: u32 = 5; // Maximum number of allowed nationalities

fn main(list: [str<2>; Nationalities], nationality: pub str<2>, hash: pub [u8; 64], salt: pub [u8; 16]) {
    // First step: prepend the salt to the date of birth
    let mut input: [u8; 26] = [0; 26];
    for i in 0..16 {
        input[i] = salt[i];
    }
    for i in 0..Nationalities {
        let code = list[i];
        input[16 + i * 2] = code.as_bytes()[0];
        input[16 + i * 2 + 1] = code.as_bytes()[1];
    }
    // Second step: calculate the hash of the list
    let dob_hash = digest(input);
    // Third step: check wether the provided hash matches the one calculated
    assert(dob_hash == hash, "Hash verification has failed.");
    // Fourth step: check if nationality is in the list
    let mut found = false;
    for i in 0..Nationalities {
        if (list[i].as_bytes()[0] == nationality.as_bytes()[0]) &
        (list[i].as_bytes()[1] == nationality.as_bytes()[1]) {
            found = true;
        }
    }
    assert(found, "Nationality is not in the list.");
}

#[test]
fn test_main() {
    // Test that passes both hash and age verification
    main(["PT", "EN", "--", "--", "--"], "PT", [112, 45, 248, 110, 146, 25, 207, 147, 131, 134, 165, 166, 174, 162, 149, 2, 191, 227, 13, 23, 50, 97, 250, 57, 204, 11, 81, 51, 117, 44, 163, 153, 93, 226, 47, 94, 46, 84, 204, 187, 64, 40, 111, 192, 14, 78, 219, 126, 9, 222, 99, 144, 10, 91, 35, 246, 5, 1, 142, 13, 152, 21, 54, 71]
, [40, 24, 210, 90, 217, 193, 151, 158, 168, 40, 129, 222, 75, 51, 222, 53]);

    // Test that fails in nationality verification
    //main(["PT", "EN", "--", "--", "--"], "ES", [48,43,58,181,190,239,85,210,133,139,50,250,131,111,8,110,105,38,46,10,75,113,147,4,169,230,223,236,109,201,63,219], [173,228,221,143,141,161,107,184,44,123,53,131,219,255,63,19]);

    // Test that fails in hash verification
    //main(["PT", "EN", "--", "--", "--"], "PT", [49,43,58,181,190,239,85,210,133,139,50,250,131,111,8,110,105,38,46,10,75,113,147,4,169,230,223,236,109,201,63,219], [173,228,221,143,141,161,107,184,44,123,53,131,219,255,63,19]);

}