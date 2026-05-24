use sha512::sha512::digest;

global Nationalities: u32 = 5; // Maximum number of allowed nationalities

fn main(
    list: [str<2>; Nationalities],
    nationalityp: str<2>,
    nationality: pub str<2>,
    hash: pub [u8; 64],
    salt: [u8; 16],
) {
    // First step: check that public inputs are correct
    assert(nationalityp == nationality, "Public input nationality does not match expected value.");
    // Second step: prepend the salt to the date of birth
    let mut input: [u8; 26] = [0; 26];
    for i in 0..16 {
        input[i] = salt[i];
    }
    for i in 0..Nationalities {
        let code = list[i];
        input[16 + i * 2] = code.as_bytes()[0];
        input[16 + i * 2 + 1] = code.as_bytes()[1];
    }
    // Third step: calculate the hash of the list
    let dob_hash = digest(input);
    // Fourth step: check wether the provided hash matches the one calculated
    assert(dob_hash == hash, "Hash verification has failed.");
    // Fifth step: check if nationality is in the list
    let mut found = false;
    for i in 0..Nationalities {
        if (list[i].as_bytes()[0] == nationality.as_bytes()[0])
            & (list[i].as_bytes()[1] == nationality.as_bytes()[1]) {
            found = true;
        }
    }
    // Sixth step: assert that the nationality is in the list
    assert(found, "Nationality is not in the list.");
}
