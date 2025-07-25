use sha256::digest;


global STRSIZE: u32 = 18;
global SUBSTRSIZE: u32 = 3;
global INPUTSIZE: u32 = STRSIZE + 16; // 16 bytes for the salt

fn contains(string: str<STRSIZE>, substring: str<SUBSTRSIZE>) -> bool {
    let string_bytes = string.as_bytes();
    let substring_bytes = substring.as_bytes();
    let string_len = 10;
    let substring_len = 2;

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
    main("one two three four", "two", [124, 30, 118, 43, 116, 145, 122, 223, 197, 103, 24, 189, 179, 12, 62, 157, 203, 179, 198, 228, 67, 161, 91, 66, 166, 116, 199, 50, 84, 9, 254, 43],[78, 222, 201, 33, 29, 157, 101, 252, 1, 249, 198, 61, 137, 115, 134, 86]);

    // Test that fails in string verification
    //main("one two three four", "yes", [124, 30, 118, 43, 116, 145, 122, 223, 197, 103, 24, 189, 179, 12, 62, 157, 203, 179, 198, 228, 67, 161, 91, 66, 166, 116, 199, 50, 84, 9, 254, 43],[78, 222, 201, 33, 29, 157, 101, 252, 1, 249, 198, 61, 137, 115, 134, 86]);

    // Test that fails in hash verification
    //main("one two three four", "two", [125, 30, 118, 43, 116, 145, 122, 223, 197, 103, 24, 189, 179, 12, 62, 157, 203, 179, 198, 228, 67, 161, 91, 66, 166, 116, 199, 50, 84, 9, 254, 43],[78, 222, 201, 33, 29, 157, 101, 252, 1, 249, 198, 61, 137, 115, 134, 86]);
}
