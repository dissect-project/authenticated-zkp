global STRSIZE: u32 = 57;
global SUBSTRSIZE: u32 = 10;

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

fn main(x: str<STRSIZE>, yp: pub str<SUBSTRSIZE>, y: pub str<SUBSTRSIZE>) {
    // First step: check that public inputs are correct
    assert(y == yp, "Public input y does not match expected value.");
    // Second step: check if x contains y
    assert(contains(x, y), "Substring verification has failed.");
}

#[test]
fn test_main() {
    // Test that it passes substring verification
    main(
        "42 Fictional Way, Smithfield, Dublin 7, D07 F4K3, Ireland",
        "Smithfield",
        "Smithfield",
    );
}
