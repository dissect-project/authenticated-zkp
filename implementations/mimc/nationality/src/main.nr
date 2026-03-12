use mimc::mimc_bn254;

global Nationalities: u32 = 5; // Maximum number of allowed nationalities

fn main(list: [str<2>; Nationalities], nationality: pub str<2>, hash: pub [u8; 32], salt: pub [u8; 16]) {
    // First step: prepend the salt to the integer
    let mut input: [Field; 26] = [0; 26];
    for i in 0..16 {
        // Cast u8 to Field
        input[i] = salt[i] as Field;
    }
    for i in 0..Nationalities {
        // Cast u8 to Field
        let code = list[i];
        input[16 + i * 2] = code.as_bytes()[0] as Field;
        input[16 + i * 2 + 1] = code.as_bytes()[1] as Field;
    }
    // Second step: calculate the hash of the nationality
    let nationality_hash = mimc_bn254(input);
    // Third step: convert the Field hash back into a 32-byte array (Big-Endian)
    // and check whether the provided hash matches the one calculated
    let nationality_hash_bytes: [u8; 32] = nationality_hash.to_be_bytes();
    // Fourth step: check wether the provided hash matches the one calculated
    assert(nationality_hash_bytes == hash, "Hash verification has failed.");
    // Fifth step: check if nationality is in the list
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
    main(["PT", "EN", "--", "--", "--"], "PT", [48,43,58,181,190,239,85,210,133,139,50,250,131,111,8,110,105,38,46,10,75,113,147,4,169,230,223,236,109,201,63,219], [173,228,221,143,141,161,107,184,44,123,53,131,219,255,63,19]);

    // Test that fails in nationality verification
    //main(["PT", "EN", "--", "--", "--"], "ES", [48,43,58,181,190,239,85,210,133,139,50,250,131,111,8,110,105,38,46,10,75,113,147,4,169,230,223,236,109,201,63,219], [173,228,221,143,141,161,107,184,44,123,53,131,219,255,63,19]);

    // Test that fails in hash verification
    //main(["PT", "EN", "--", "--", "--"], "PT", [49,43,58,181,190,239,85,210,133,139,50,250,131,111,8,110,105,38,46,10,75,113,147,4,169,230,223,236,109,201,63,219], [173,228,221,143,141,161,107,184,44,123,53,131,219,255,63,19]);

}