use poseidon::poseidon::bn254::hash_2;

global MAX_STRSIZE: u32 = 150;
global MAX_SUBSTRSIZE: u32 = 8;

fn contains(
    string: [u8; MAX_STRSIZE],
    string_len: u32,
    substring: [u8; MAX_SUBSTRSIZE],
    substring_len: u32,
) -> bool {
    let mut found = false;

    for i in 0..(MAX_STRSIZE - MAX_SUBSTRSIZE + 1) {
        if i + substring_len <= string_len {
            let mut match_found = true;
            for j in 0..MAX_SUBSTRSIZE {
                if j < substring_len {
                    if string[i + j] != substring[j] {
                        match_found = false;
                    }
                }
            }
            if match_found {
                found = true;
            }
        }
    }

    found
}

fn bytes_to_field(bytes: [u8; MAX_STRSIZE], len: u32) -> Field {
    let mut result: Field = 0;
    for i in 0..MAX_STRSIZE {
        if i < len {
            result = result * 256 + bytes[i] as Field;
        }
    }
    result
}

fn salt_to_field(salt: [u8; 16]) -> Field {
    let mut result: Field = 0;
    for i in 0..16 {
        result = result * 256 + salt[i] as Field;
    }
    result
}

fn main(
    x: [u8; MAX_STRSIZE],
    x_len: u32,
    yp: [u8; MAX_SUBSTRSIZE],
    y: pub [u8; MAX_SUBSTRSIZE],
    y_len: pub u32,
    hash: pub [u8; 32],
    salt: [u8; 16],
) {
    // First step: check that inputs do not exceed maximum sizes
    assert(x_len <= MAX_STRSIZE, "String exceeds maximum size.");
    assert(y_len <= MAX_SUBSTRSIZE, "Substring exceeds maximum size.");
    // Second step: check that public inputs are correct
    assert(y == yp, "Public input y does not match expected value.");
    // Third step: convert salt and x content to Field elements
    let salt_field = salt_to_field(salt);
    let x_field = bytes_to_field(x, x_len);
    // Fourth step: compute Poseidon hash
    let computed_hash = hash_2([salt_field, x_field]);
    // Fifth step: convert the expected hash from [u8; 32] to Field for comparison
    let mut hash_field: Field = 0;
    for i in 0..32 {
        hash_field = hash_field * 256 + hash[i] as Field;
    }
    // Sixth step: verify hash and substring
    assert(computed_hash == hash_field, "Hash verification has failed.");
    assert(contains(x, x_len, y, y_len), "Substring verification has failed.");
}
