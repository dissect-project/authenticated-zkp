use sha256::digest;

// Customize this value for your specific string size before compiling
global N: u32 = 5;  // Size of the input string

fn main(x: [u8; N], y: pub u32, hash: pub [u8; 32], salt: pub [u8; 16]) {
    // First step: prepend the salt to the string
    let mut input: [u8; 16 + N] = [0; 16 + N];
    for i in 0..16 {
        input[i] = salt[i];
    }
    for i in 0..N {
        input[16 + i] = x[i];
    }
    // Second step: calculate the hash of the string
    let string_hash = digest(input);
    // Third step: check whether the provided hash matches the one calculated
    assert(string_hash == hash, "Hash verification has failed.");
    // Fourth step: check if string length > y
    assert(N > y, "String length is not greater than y.");
}

#[test]
fn test_main() {
    // Example: Test with a 5-byte string "hello" (ASCII: [104, 101, 108, 108, 111])
    // You'll need to calculate the correct hash for your test data
    // Test that passes both hash and string length verification
    main([104, 101, 108, 108, 111], 3, [191, 178, 238, 207, 133, 176, 207, 53, 73, 80, 211, 245, 221, 30, 120, 117, 26, 81, 107, 39, 241, 70, 241, 153, 148, 169, 176, 145, 215, 8, 62, 125], [70, 32, 72, 151, 47, 201, 204, 171, 113, 221, 46, 91, 108, 145, 20, 140]);

    // Test that fails in length verification
    //main([104, 101, 108, 108, 111], 10, [191, 178, 238, 207, 133, 176, 207, 53, 73, 80, 211, 245, 221, 30, 120, 117, 26, 81, 107, 39, 241, 70, 241, 153, 148, 169, 176, 145, 215, 8, 62, 125], [70, 32, 72, 151, 47, 201, 204, 171, 113, 221, 46, 91, 108, 145, 20, 140]);

    // Test that fails in hash verification
    //main([104, 101, 108, 108, 111], 3, [192, 178, 238, 207, 133, 176, 207, 53, 73, 80, 211, 245, 221, 30, 120, 117, 26, 81, 107, 39, 241, 70, 241, 153, 148, 169, 176, 145, 215, 8, 62, 125], [70, 32, 72, 151, 47, 201, 204, 171, 113, 221, 46, 91, 108, 145, 20, 140]);
}
