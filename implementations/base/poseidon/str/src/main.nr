use poseidon::poseidon::bn254::hash_2;

global STRSIZE: u32 = 57;
global SUBSTRSIZE: u32 = 10;

fn contains(string: str<STRSIZE>, substring: str<SUBSTRSIZE>) -> bool {
    let string_bytes = string.as_bytes();
    let substring_bytes = substring.as_bytes();
    let string_len = 57;
    let substring_len = 10;

    let mut found = false;

    for i in 0..(string_len - substring_len + 1) {
        let mut match_found = true;
        for j in 0..substring_len {
            if string_bytes[i + j] != substring_bytes[j] {
                match_found = false;
            }
        }
        if match_found {
            found = true;
        }
    }

    found
}

fn main(
    x: str<STRSIZE>,
    yp: str<SUBSTRSIZE>,
    y: pub str<SUBSTRSIZE>,
    hash: pub [u8; 32],
    salt: [u8; 16],
) {
    // First step: check that public inputs are correct
    assert(y == yp, "Public input substring does not match expected value.");
    // Second step: convert salt and string into single Field elements (big-endian packing)
    let mut str_field: Field = 0;
    for i in 0..STRSIZE {
        str_field = (str_field * 256) + (x.as_bytes()[i] as Field);
    }
    let mut salt_field: Field = 0;
    for i in 0..16 {
        salt_field = (salt_field * 256) + (salt[i] as Field);
    }
    // Third step: calculate the hash of the date of birth
    let str_hash = hash_2([salt_field, str_field]);
    // Convert the 32-byte input hash into a Field for comparison
    let mut expected_hash_field: Field = 0;
    for i in 0..32 {
        expected_hash_field = (expected_hash_field * 256) + (hash[i] as Field);
    }
    // Fourth step: check wether the provided hash matches the one calculated
    assert(str_hash == expected_hash_field, "Hash verification has failed.");
    // Fifth step: check if x contains y
    assert(contains(x, y), "Substring verification has failed.");
}
