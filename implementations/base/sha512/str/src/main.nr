use sha512::sha512::digest;

global STRSIZE: u32 = 57;
global SUBSTRSIZE: u32 = 10;
global INPUTSIZE: u32 = STRSIZE + 16; // 16 bytes for the salt

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
    yp: pub str<SUBSTRSIZE>,
    y: pub str<SUBSTRSIZE>,
    hash: pub [u8; 64],
    salt: [u8; 16],
) {
    // First step: check that public inputs are correct
    assert(yp == y, "Public input y does not match expected value.");
    // Second step: prepend the salt to the date of birth
    let mut input: [u8; INPUTSIZE] = [0; INPUTSIZE];
    for i in 0..16 {
        input[i] = salt[i];
    }
    for i in 0..STRSIZE {
        input[16 + i] = x.as_bytes()[i];
    }
    // Third step: calculate the hash of the number
    let str_hash = digest(input);
    // Fourth step: check wether the provided hash matches the one calculated
    assert(str_hash == hash, "Hash verification has failed.");
    // Fifth step: check if x contains y
    assert(contains(x, y), "Substring verification has failed.");
}
