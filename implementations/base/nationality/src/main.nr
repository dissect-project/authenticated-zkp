global Nationalities: u32 = 5; // Maximum number of allowed nationalities

fn main(list: [str<2>; Nationalities], nationality: pub str<2>) {
    // First step: prepend the salt to the date of birth (skip)
    // Second step: calculate the hash of the list (skip)
    // Third step: check wether the provided hash matches the one calculated (skip)
    // Fourth step: check if nationality is in the list
    let mut found = false;
    for i in 0..Nationalities {
        if (list[i].as_bytes()[0] == nationality.as_bytes()[0]) &
        (list[i].as_bytes()[1] == nationality.as_bytes()[1]) {
            found = true;
        }
    }
    assert(found, "Nationality is not in the list.");
}

#[test]
fn test_main() {
    // Test that passes both hash and age verification
    main(["PT", "EN", "--", "--", "--"], "PT");
    // Test that fails in nationality verification
    //main(["PT", "EN", "--", "--", "--"], "ES");
    // Test that fails in hash verification
    //main(["PT", "EN", "--", "--", "--"], "PT");

}