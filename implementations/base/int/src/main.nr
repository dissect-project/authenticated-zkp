fn main(x: u32, y: pub u32) {
    // First step: prepend the salt to the integer (skip)
    // Second step: calculate the hash of the number (skip)
    // Third step: check wether the provided hash matches the one calculated (skip)
    // Fourth step: check if x > y
    assert(x > y, "x is not greater than y.");
}

#[test]
fn test_main() {
    // Test that passes both hash and age verification
    main(7, 5);
    // Test that fails in int verification
    //main(7, 10);
    // Test that fails in hash verification
    //main(7, 5);
}
