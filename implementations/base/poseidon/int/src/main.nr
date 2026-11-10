use poseidon::poseidon::bn254::hash_2;

fn main(x: u32, yp: u32, y: pub u32, hash: pub [u8; 32], salt: [u8; 16]) {
    // First step: check that public inputs are correct
    assert(y == yp, "Public input y does not match expected value.");
    // Second step: convert salt and x into single Field elements (big-endian packing)
    let mut salt_field: Field = 0;
    for i in 0..16 {
        salt_field = (salt_field * 256) + (salt[i] as Field);
    }
    // Convert the 32-byte input hash into a Field for comparison
    let mut expected_hash_field: Field = 0;
    for i in 0..32 {
        expected_hash_field = (expected_hash_field * 256) + (hash[i] as Field);
    }
    // Third step: calculate the hash of the number
    let int_hash = hash_2([salt_field, x as Field]);
    // Fourth step: check wether the provided hash matches the one calculated
    assert(int_hash == expected_hash_field, "Hash verification has failed.");
    // Fifth step: check if x > y
    assert(x > y, "x is not greater than y.");
}
