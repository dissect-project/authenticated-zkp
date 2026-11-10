global Nationalities: u32 = 5; // Maximum number of allowed nationalities

fn main(list: [str<2>; Nationalities], nationalityp: pub str<2>, nationality: pub str<2>) {
    // First step: check that public inputs are correct
    assert(nationality == nationalityp, "Public input nationality does not match expected value.");
    // Second step: check if nationality is in the list
    let mut found = false;
    for i in 0..Nationalities {
        if (list[i].as_bytes()[0] == nationality.as_bytes()[0])
            & (list[i].as_bytes()[1] == nationality.as_bytes()[1]) {
            found = true;
        }
    }
    assert(found, "Nationality is not in the list.");
}

#[test]
fn test_main() {
    // Test that it passes list verification
    main(["PT", "EN", "--", "--", "--"], "PT", "PT");
}
