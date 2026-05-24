global MAX_STRSIZE: u32 = 512; // maximum string capacity
global MAX_SUBSTRSIZE: u32 = 8; // maximum substring capacity

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
    yp: pub [u8; MAX_SUBSTRSIZE],
    y: pub [u8; MAX_SUBSTRSIZE],
    y_len: pub u32,
) {
    // First step: check that inputs do not exceed maximum sizes
    assert(x_len <= MAX_STRSIZE, "String exceeds maximum size.");
    assert(y_len <= MAX_SUBSTRSIZE, "Substring exceeds maximum size.");
    // Second step: check that public inputs are correct
    assert(y == yp, "Public input y does not match expected value.");
    // Third step: check if x contains y
    assert(contains(x, x_len, y, y_len), "Substring verification has failed.");
}
