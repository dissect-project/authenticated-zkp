use sha256::digest;

fn main(x: u32, y: pub u32, hash: pub [u8; 32], salt: pub [u8; 16]) {
    // First step: prepend the salt to the integer
    let mut input: [u8; 17] = [0; 17];
    for i in 0..16 {
        input[i] = salt[i];
    }
    input[16] = (x as u8);
    // Second step: calculate the hash of the number
    let int_hash = digest(input);
    // Third step: check wether the provided hash matches the one calculated
    assert(int_hash == hash, "Hash verification has failed.");
    // Fourth step: check if x > y
    assert(x > y, "x is not greater than y.");
}

#[test]
fn test_main() {
    // Test that passes both hash and age verification
    main(7, 5, [191, 178, 238, 207, 133, 176, 207, 53, 73, 80, 211, 245, 221, 30, 120, 117, 26, 81, 107, 39, 241, 70, 241, 153, 148, 169, 176, 145, 215, 8, 62, 125], [70, 32, 72, 151, 47, 201, 204, 171, 113, 221, 46, 91, 108, 145, 20, 140]);
    
    // Test that fails in int verification
    //main(7, 10, [191, 178, 238, 207, 133, 176, 207, 53, 73, 80, 211, 245, 221, 30, 120, 117, 26, 81, 107, 39, 241, 70, 241, 153, 148, 169, 176, 145, 215, 8, 62, 125], [70, 32, 72, 151, 47, 201, 204, 171, 113, 221, 46, 91, 108, 145, 20, 140]);

    // Test that fails in hash verification
    //main(7, 5, [192, 178, 238, 207, 133, 176, 207, 53, 73, 80, 211, 245, 221, 30, 120, 117, 26, 81, 107, 39, 241, 70, 241, 153, 148, 169, 176, 145, 215, 8, 62, 125], [70, 32, 72, 151, 47, 201, 204, 171, 113, 221, 46, 91, 108, 145, 20, 140]);
}
