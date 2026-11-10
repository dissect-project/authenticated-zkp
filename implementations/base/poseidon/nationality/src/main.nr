use poseidon::poseidon::bn254::hash_2;

global Nationalities: u32 = 5; // Maximum number of allowed nationalities

fn main(
    list: [str<2>; Nationalities],
    nationalityp: str<2>,
    nationality: pub str<2>,
    hash: pub [u8; 32],
    salt: [u8; 16],
) {
    // First step: check that public inputs are correct
    assert(nationality == nationalityp, "Public input nationality does not match expected value.");
    // Second step: convert salt and nationality into single Field elements (big-endian packing)
    let mut nationality_field: Field = 0;
    for i in 0..Nationalities {
        nationality_field = (nationality_field * 65536)
            + ((list[i].as_bytes()[0] as Field) * 256)
            + (list[i].as_bytes()[1] as Field);
    }
    let mut salt_field: Field = 0;
    for i in 0..16 {
        salt_field = (salt_field * 256) + (salt[i] as Field);
    }
    // Third step: calculate the hash of the nationality
    let nationality_hash = hash_2([salt_field, nationality_field]);
    // Convert the 32-byte input hash into a Field for comparison
    let mut expected_hash_field: Field = 0;
    for i in 0..32 {
        expected_hash_field = (expected_hash_field * 256) + (hash[i] as Field);
    }
    // Fourth step: check wether the provided hash matches the one calculated
    assert(nationality_hash == expected_hash_field, "Hash verification has failed.");
    // Fifth step: check if nationality is in the list
    let mut found = false;
    for i in 0..Nationalities {
        if (list[i].as_bytes()[0] == nationality.as_bytes()[0])
            & (list[i].as_bytes()[1] == nationality.as_bytes()[1]) {
            found = true;
        }
    }
    assert(found, "Nationality is not in the list.");
}
