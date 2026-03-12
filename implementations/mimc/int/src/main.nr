use mimc::mimc_bn254;

fn main(x: u32, y: pub u32, hash: pub [u8; 32], salt: pub [u8; 16]) {
    // First step: prepend the salt to the integer
    let mut input: [Field; 17] = [0; 17];
    for i in 0..16 {
        // Cast u8 to Field
        input[i] = salt[i] as Field;
    }
    for i in 0..1 {
        // Cast u8 to Field
        input[16 + i] = x as Field;
    }
    // Second step: calculate the hash of the integer
    let int_hash = mimc_bn254(input);
    // Third step: convert the Field hash back into a 32-byte array (Big-Endian)
    // and check whether the provided hash matches the one calculated
    let int_hash_bytes: [u8; 32] = int_hash.to_be_bytes();
    // Fourth step: check wether the provided hash matches the one calculated
    assert(int_hash_bytes == hash, "Hash verification has failed.");
    // Fifth step: check if x > y
    assert(x > y, "x is not greater than y.");
}

#[test]
fn test_main() {
    // Test that passes both hash and age verification
    main(7, 5, [9,54,97,252,56,52,235,248,35,18,144,157,233,35,146,136,188,88,123,28,66,133,200,134,240,51,248,198,248,187,35,125], [110,35,223,147,182,54,91,117,189,6,75,96,206,24,207,176]);
    
    // Test that fails in int verification
    //main(7, 10, [191, 178, 238, 207, 133, 176, 207, 53, 73, 80, 211, 245, 221, 30, 120, 117, 26, 81, 107, 39, 241, 70, 241, 153, 148, 169, 176, 145, 215, 8, 62, 125], [70, 32, 72, 151, 47, 201, 204, 171, 113, 221, 46, 91, 108, 145, 20, 140]);

    // Test that fails in hash verification
    //main(7, 5, [192, 178, 238, 207, 133, 176, 207, 53, 73, 80, 211, 245, 221, 30, 120, 117, 26, 81, 107, 39, 241, 70, 241, 153, 148, 169, 176, 145, 215, 8, 62, 125], [70, 32, 72, 151, 47, 201, 204, 171, 113, 221, 46, 91, 108, 145, 20, 140]);
}
