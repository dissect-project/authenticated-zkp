use mimc::mimc_bn254;


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


fn main(x: str<STRSIZE>, y: pub str<SUBSTRSIZE>, hash: pub [u8; 32], salt: pub [u8; 16]) {
    // First step: prepend the salt to the string into a Field array
    let mut input: [Field; INPUTSIZE] = [0; INPUTSIZE];
    for i in 0..16 {
        // Cast u8 to Field
        input[i] = salt[i] as Field;
    }
    for i in 0..10 {
        // Cast u8 to Field
        input[16 + i] = x.as_bytes()[i] as Field;
    }
    // Second step: calculate the hash of the number
    let str_hash = mimc_bn254(input);
    // Third step: convert the Field hash back into a 32-byte array (Big-Endian)
    // and check whether the provided hash matches the one calculated
    let str_hash_bytes: [u8; 32] = str_hash.to_be_bytes();
    // Fourth step: check wether the provided hash matches the one calculated
    assert(str_hash_bytes == hash, "Hash verification has failed.");
    // Fifth step: check if x contains y
    assert(contains(x, y), "Substring verification has failed.");
    
}

#[test]
fn test_main() {
    // Test that passes both hash and string verification
    main("42 Fictional Way, Smithfield, Dublin 7, D07 F4K3, Ireland", "Smithfield", [71, 87, 130, 27, 232, 27, 59, 184, 139, 215, 175, 163, 14, 83, 132, 108, 15, 213, 229, 4, 177, 186, 180, 111, 89, 89, 133, 193, 162, 203, 161, 112],[78, 89, 32, 99, 38, 140, 152, 79, 207, 255, 245, 138, 28, 119, 131, 94]);

    // Test that fails in string verification
    //main("one two three four", "yes", [124, 30, 118, 43, 116, 145, 122, 223, 197, 103, 24, 189, 179, 12, 62, 157, 203, 179, 198, 228, 67, 161, 91, 66, 166, 116, 199, 50, 84, 9, 254, 43],[78, 222, 201, 33, 29, 157, 101, 252, 1, 249, 198, 61, 137, 115, 134, 86]);

    // Test that fails in hash verification
    //main("one two three four", "two", [125, 30, 118, 43, 116, 145, 122, 223, 197, 103, 24, 189, 179, 12, 62, 157, 203, 179, 198, 228, 67, 161, 91, 66, 166, 116, 199, 50, 84, 9, 254, 43],[78, 222, 201, 33, 29, 157, 101, 252, 1, 249, 198, 61, 137, 115, 134, 86]);
}
