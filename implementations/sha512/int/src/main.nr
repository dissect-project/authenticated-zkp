use sha512::sha512::digest;

fn main(x: u32, y: pub u32, hash: pub [u8; 64], salt: pub [u8; 16]) {
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
    main(7, 5, [212, 144, 208, 22, 51, 70, 2, 85, 164, 194, 33, 127, 61, 76, 40, 139, 19, 109, 204, 187, 152, 252, 108, 206, 80, 8, 93, 231, 39, 41, 179, 1, 220, 3, 217, 223, 96, 55, 12, 98, 67, 144, 245, 95, 181, 54, 63, 22, 131, 42, 72, 69, 247, 146, 58, 55, 69, 92, 168, 38, 176, 170, 202, 7], [26, 122, 106, 208, 50, 147, 202, 136, 5, 66, 59, 226, 119, 39, 178, 131]);
    
    // Test that fails in int verification
    //main(7, 10, [191, 178, 238, 207, 133, 176, 207, 53, 73, 80, 211, 245, 221, 30, 120, 117, 26, 81, 107, 39, 241, 70, 241, 153, 148, 169, 176, 145, 215, 8, 62, 125], [70, 32, 72, 151, 47, 201, 204, 171, 113, 221, 46, 91, 108, 145, 20, 140]);

    // Test that fails in hash verification
    //main(7, 5, [192, 178, 238, 207, 133, 176, 207, 53, 73, 80, 211, 245, 221, 30, 120, 117, 26, 81, 107, 39, 241, 70, 241, 153, 148, 169, 176, 145, 215, 8, 62, 125], [70, 32, 72, 151, 47, 201, 204, 171, 113, 221, 46, 91, 108, 145, 20, 140]);
}
