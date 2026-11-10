use sha512::sha512::digest;

fn main(x: u32, yp: u32, y: pub u32, hash: pub [u8; 64], salt: [u8; 16]) {
    // First step: check that public inputs are correct
    assert(yp == y, "Public input y does not match expected value.");
    // Second step: prepend the salt to the integer
    let mut input: [u8; 17] = [0; 17];
    for i in 0..16 {
        input[i] = salt[i];
    }
    input[16] = (x as u8);
    // Third step: calculate the hash of the number
    let int_hash = digest(input);
    // Fourth step: check wether the provided hash matches the one calculated
    assert(int_hash == hash, "Hash verification has failed.");
    // Fifth step: check if x > y
    assert(x > y, "x is not greater than y.");
}
