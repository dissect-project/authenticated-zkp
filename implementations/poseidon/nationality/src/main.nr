use poseidon::poseidon::bn254::hash_2;

global Nationalities: u32 = 5; // Maximum number of allowed nationalities

fn main(list: [str<2>; Nationalities], nationality: pub str<2>, hash: pub [u8; 32], salt: pub [u8; 16]) {
    // First step: convert salt and nationality into single Field elements (big-endian packing)
    let mut nationality_field: Field = 0;
    for i in 0..Nationalities {
        nationality_field = (nationality_field * 65536) + ((list[i].as_bytes()[0] as Field) * 256) + (list[i].as_bytes()[1] as Field);
    }
    let mut salt_field: Field = 0;
    for i in 0..16 {
        salt_field = (salt_field * 256) + (salt[i] as Field);
    }
    // Second step: calculate the hash of the nationality
    let nationality_hash = hash_2([salt_field,nationality_field]);
    // Convert the 32-byte input hash into a Field for comparison
    let mut expected_hash_field: Field = 0;
    for i in 0..32 {
        expected_hash_field = (expected_hash_field * 256) + (hash[i] as Field);
    }
    // Third step: check wether the provided hash matches the one calculated
    assert(nationality_hash == expected_hash_field, "Hash verification has failed.");
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
    main(["PT", "EN", "--", "--", "--"], "PT", [48,43,58,181,190,239,85,210,133,139,50,250,131,111,8,110,105,38,46,10,75,113,147,4,169,230,223,236,109,201,63,219], [173,228,221,143,141,161,107,184,44,123,53,131,219,255,63,19]);

    // Test that fails in nationality verification
    //main(["PT", "EN", "--", "--", "--"], "ES", [48,43,58,181,190,239,85,210,133,139,50,250,131,111,8,110,105,38,46,10,75,113,147,4,169,230,223,236,109,201,63,219], [173,228,221,143,141,161,107,184,44,123,53,131,219,255,63,19]);

    // Test that fails in hash verification
    //main(["PT", "EN", "--", "--", "--"], "PT", [49,43,58,181,190,239,85,210,133,139,50,250,131,111,8,110,105,38,46,10,75,113,147,4,169,230,223,236,109,201,63,219], [173,228,221,143,141,161,107,184,44,123,53,131,219,255,63,19]);

}