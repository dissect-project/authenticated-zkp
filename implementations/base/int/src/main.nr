fn main(x: u32, yp: u32, y: pub u32) {
    // First step: check that public inputs are correct
    assert(y == yp, "Public input y does not match expected value.");
    // Second step: check if x > y
    assert(x > y, "x is not greater than y.");
}

#[test]
fn test_main() {
    // Test that it passes age verification
    main(7, 5, 5);
}
