use sha256::digest;

global N: u32 = 1;

fn main(x: u32, x_bytes: [u8; N], yp: u32, y: pub u32, hash: pub [u8; 32], salt: [u8; 16]) {
    // First step: check that public inputs are correct
    assert(y == yp, "Public input y does not match expected value.");
    // Second step: prepend the salt to the string
    let mut input: [u8; 16 + N] = [0; 16 + N];
    for i in 0..16 {
        input[i] = salt[i];
    }
    for i in 0..N {
        input[16 + i] = x_bytes[i];
    }
    // Third step: calculate the hash of the string
    let string_hash = digest(input);
    // Fourth step: check whether the provided hash matches the one calculated
    assert(string_hash == hash, "Hash verification has failed.");
    // Fifth step: check if x > y
    assert(x > y, "x is not greater than y.");
}
