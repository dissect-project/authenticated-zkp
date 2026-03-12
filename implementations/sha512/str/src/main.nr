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


fn main(x: str<STRSIZE>, y: pub str<SUBSTRSIZE>, hash: pub [u8; 64], salt: pub [u8; 16]) {
    // First step: prepend the salt to the date of birth
    let mut input: [u8; INPUTSIZE] = [0; INPUTSIZE];
    for i in 0..16 {
        input[i] = salt[i];
    }
    for i in 0..STRSIZE {
        input[16 + i] = x.as_bytes()[i];
    }
    // Second step: calculate the hash of the number
    let str_hash = digest(input);
    // Third step: check wether the provided hash matches the one calculated
    assert(str_hash == hash, "Hash verification has failed.");
    // Fourth step: check if x contains y
    assert(contains(x, y), "Substring verification has failed.");
    
}

#[test]
fn test_main() {
    // Test that passes both hash and string verification
    main("42 Fictional Way, Smithfield, Dublin 7, D07 F4K3, Ireland", "Smithfield", [229, 14, 214, 197, 5, 10, 110, 204, 112, 224, 86, 113, 211, 183, 108, 4, 18, 19, 168, 218, 166, 210, 230, 162, 4, 0, 108, 243, 111, 162, 21, 83, 130, 248, 31, 191, 51, 97, 16, 115, 133, 208, 50, 144, 73, 244, 92, 138, 199, 190, 46, 157, 49, 235, 76, 159, 118, 156, 83, 44, 222, 86, 169, 204],[202, 196, 16, 202, 111, 42, 127, 87, 212, 122, 100, 82, 97, 56, 63, 11]);

    // Test that fails in string verification
    //main("one two three four", "yes", [124, 30, 118, 43, 116, 145, 122, 223, 197, 103, 24, 189, 179, 12, 62, 157, 203, 179, 198, 228, 67, 161, 91, 66, 166, 116, 199, 50, 84, 9, 254, 43],[78, 222, 201, 33, 29, 157, 101, 252, 1, 249, 198, 61, 137, 115, 134, 86]);

    // Test that fails in hash verification
    //main("one two three four", "two", [125, 30, 118, 43, 116, 145, 122, 223, 197, 103, 24, 189, 179, 12, 62, 157, 203, 179, 198, 228, 67, 161, 91, 66, 166, 116, 199, 50, 84, 9, 254, 43],[78, 222, 201, 33, 29, 157, 101, 252, 1, 249, 198, 61, 137, 115, 134, 86]);
}
