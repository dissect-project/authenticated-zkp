use sha512::sha512::sha512_var;

global MAX_STRSIZE: u32 = 512;
global MAX_SUBSTRSIZE: u32 = 8;
global SALT_SIZE: u32 = 16;
global MAX_INPUT_SIZE: u32 = MAX_STRSIZE + SALT_SIZE;

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

fn main(
    x: [u8; MAX_STRSIZE],
    x_len: u32,
    yp: [u8; MAX_SUBSTRSIZE],
    y: pub [u8; MAX_SUBSTRSIZE],
    y_len: pub u32,
    hash: pub [u8; 64],
    salt: [u8; SALT_SIZE],
) {
    // First step: check that inputs do not exceed maximum sizes
    assert(x_len <= MAX_STRSIZE, "String exceeds maximum size.");
    assert(y_len <= MAX_SUBSTRSIZE, "Substring exceeds maximum size.");
    // Second step: check that public inputs are correct
    assert(y == yp, "Public input y does not match expected value.");
    // Third step: Build salt || x (only the real content, zeros elsewhere)
    let mut input: BoundedVec<u8, MAX_INPUT_SIZE> = BoundedVec::new();
    for i in 0..SALT_SIZE {
        input.push(salt[i]);
    }
    for i in 0..MAX_STRSIZE {
        if i < x_len {
            input.push(x[i]);
        }
    }
    // Fourth step: Hash only salt || x[0..x_len], not the trailing zeros
    let computed_hash = sha512_var(input);
    // Fifth step: Verify hash and substring
    assert(computed_hash == hash, "Hash verification has failed.");
    // Sixth step: check if x contains y
    assert(contains(x, x_len, y, y_len), "Substring verification has failed.");
}
