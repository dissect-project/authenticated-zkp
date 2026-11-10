// The predicates of the four test scenarios, shared by every variant. Each takes the
// elementValue exactly as the issuer encoded it (value[0..value_len], zero-padded to V bytes),
// checks that it is exactly one CBOR item of the element's type, and checks the predicate against
// the CBOR-encoded public parameters.
//
//   age        birth_date (full-date)              the holder is at least `threshold` years old today
//   rental     driving_privileges (array of maps)  a privilege of `category` issued on or before
//                                                  `held_since` and expiring on or after `return_date`
//   residence  resident_postal_code (text string)  the 5-digit ZIP code (ZIP or ZIP+4) is in
//                                                  [zip_min, zip_max]
//   veteran    veteran (uint, AAMVA namespace)      the value is 1
use crate::{cbor, decode_full_date, decode_uint, MAX_UINT_LEN};

// Maximum number of CBOR tokens of a driving_privileges value
pub global RENTAL_TOKENS: u32 = 64;

// birth_date: the holder turned `threshold` on or before today. Dates as YYYYMMDD: the holder is
// at least t years old iff birth + t * 10000 <= today.
pub fn age<let V: u32>(
    value: [u8; V],
    value_len: u32,
    today_cbor: [u8; 14],
    threshold_cbor: [u8; MAX_UINT_LEN],
) {
    assert(value_len == 14, "birth_date is not a CBOR full-date");
    let birth = decode_full_date(value, 0);
    let today = decode_full_date(today_cbor, 0);
    let (threshold, _, _) = decode_uint(threshold_cbor);
    assert(threshold < 200, "Invalid age threshold");
    assert(birth + threshold as u32 * 10000 <= today, "Age verification has failed");
}

// veteran: the uint 1
pub fn veteran<let V: u32>(value: [u8; V], value_len: u32) {
    let (v, len, _) = decode_uint(value);
    assert(len == value_len, "veteran is not a CBOR unsigned integer");
    assert(v == 1, "Veteran verification has failed");
}

// A 5-digit ASCII number at s[off..off + 5]
fn five_digits<let N: u32>(s: [u8; N], off: u32) -> u32 {
    let mut n: u32 = 0;
    for i in 0..5 {
        let c = s[off + i];
        assert((c >= 48) & (c <= 57), "Not a ZIP code");
        n = n * 10 + (c - 48) as u32;
    }
    n
}

// resident_postal_code: a text string holding a US ZIP code, "NNNNN" or ZIP+4 "NNNNN-NNNN", whose
// 5-digit ZIP is within [zip_min, zip_max] (each a 5-character text string)
pub fn residence<let V: u32>(
    value: [u8; V],
    value_len: u32,
    zip_min_cbor: [u8; 6],
    zip_max_cbor: [u8; 6],
) {
    assert(V >= 11);
    let n = value_len - 1;
    assert(value[0] == 0x60 + n as u8, "resident_postal_code is not a CBOR text string");
    assert((n == 5) | (n == 10), "Not a US ZIP code");
    let zip = five_digits(value, 1);
    if n == 10 {
        assert(value[6] == 45, "Not a US ZIP+4 code");
        for i in 7..11 {
            assert((value[i] >= 48) & (value[i] <= 57), "Not a US ZIP+4 code");
        }
    }
    assert((zip_min_cbor[0] == 0x65) & (zip_max_cbor[0] == 0x65), "Invalid ZIP range");
    let lo = five_digits(zip_min_cbor, 1);
    let hi = five_digits(zip_max_cbor, 1);
    assert((lo <= zip) & (zip <= hi), "Residence verification has failed");
}

// Keys of a DrivingPrivilege (ISO/IEC 18013-5 7.2.4) as CBOR text strings
global KEY_CATEGORY: [u8; 22] = [
    0x75, 0x76, 0x65, 0x68, 0x69, 0x63, 0x6c, 0x65, 0x5f, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72,
    0x79, 0x5f, 0x63, 0x6f, 0x64, 0x65,
]; // "vehicle_category_code"
global KEY_ISSUE: [u8; 11] = [0x6a, 0x69, 0x73, 0x73, 0x75, 0x65, 0x5f, 0x64, 0x61, 0x74, 0x65]; // "issue_date"
global KEY_EXPIRY: [u8; 12] =
    [0x6b, 0x65, 0x78, 0x70, 0x69, 0x72, 0x79, 0x5f, 0x64, 0x61, 0x74, 0x65]; // "expiry_date"

// Offsets of the vehicle_category_code, issue_date and expiry_date keys of the privilege of
// `category`, computed outside the circuit (a hint)
unconstrained fn find_privilege<let N: u32, let T: u32>(
    buf: [u8; N],
    toks: cbor::Tokens<T>,
    category: [u8; 4],
) -> (u32, u32, u32) {
    let mut found = (0, 0, 0);
    for j in 0..T {
        let off = toks.start[j];
        let mut is_cat = off + 26 < N;
        if is_cat {
            for k in 0..22 {
                is_cat &= buf[off + k] == KEY_CATEGORY[k];
            }
            let n = (category[0] - 0x60) as u32;
            for k in 0..4 {
                if k <= n {
                    is_cat &= buf[off + 22 + k] == category[k];
                }
            }
        }
        if is_cat & ((toks.rem[j] as u8) & 1 == 1) {
            let map = toks.par[j];
            let mut issue = 0;
            let mut expiry = 0;
            for i in 0..T {
                let o = toks.start[i];
                if (toks.par[i] == map) & (o + 12 < N) {
                    let mut is_issue = true;
                    for k in 0..11 {
                        is_issue &= buf[o + k] == KEY_ISSUE[k];
                    }
                    let mut is_expiry = true;
                    for k in 0..12 {
                        is_expiry &= buf[o + k] == KEY_EXPIRY[k];
                    }
                    if is_issue {
                        issue = o;
                    }
                    if is_expiry {
                        expiry = o;
                    }
                }
            }
            found = (off, issue, expiry);
        }
    }
    found
}

// driving_privileges: an array of DrivingPrivilege maps, one of which has vehicle_category_code
// `category` (a text string of 1 to 3 characters), issue_date <= held_since and
// expiry_date >= return_date. The value is parsed in the circuit (cbor::parse), so the three
// entries are keys of the same map, an element of the array, and the map's keys may be in any
// order and include others (e.g. codes).
pub fn rental<let V: u32>(
    value: [u8; V],
    value_len: u32,
    category_cbor: [u8; 4],
    held_since_cbor: [u8; 14],
    return_date_cbor: [u8; 14],
) {
    assert(value_len <= V, "driving_privileges exceeds the maximum size");
    let mut buf: [u8; V + 40] = [0; V + 40];
    for i in 0..V {
        buf[i] = value[i];
    }
    let toks: cbor::Tokens<RENTAL_TOKENS> = cbor::parse(buf, 0, value_len);
    assert(buf[0] >> 5 == 4, "driving_privileges is not an array");
    let n = category_cbor[0] - 0x60;
    assert((n >= 1) & (n <= 3), "Invalid vehicle category");

    // Safety: the offsets are checked below
    let (cat, issue, expiry) = unsafe { find_privilege(buf, toks, category_cbor) };
    let jc = toks.at(cat, "No privilege of the category");
    cbor::check_at(buf, cat, KEY_CATEGORY, "No privilege of the category");
    for k in 0..4 {
        if k <= n as u32 {
            assert(buf[cat + 22 + k] == category_cbor[k], "No privilege of the category");
        }
    }
    // the privilege map is an element of the array, and the three keys are its keys
    let map = toks.par[jc];
    let map_off = map as u32;
    let jm = toks.at(map_off, "Invalid driving privilege");
    assert((map_off != 0) & (toks.par[jm] == 0), "Invalid driving privilege");
    assert(buf[map_off] >> 5 == 5, "Invalid driving privilege");
    toks.assert_key_of(jc, map, "Invalid driving privilege");
    let ji = toks.at(issue, "The privilege has no issue_date");
    cbor::check_at(buf, issue, KEY_ISSUE, "The privilege has no issue_date");
    toks.assert_key_of(ji, map, "The privilege has no issue_date");
    let je = toks.at(expiry, "The privilege has no expiry_date");
    cbor::check_at(buf, expiry, KEY_EXPIRY, "The privilege has no expiry_date");
    toks.assert_key_of(je, map, "The privilege has no expiry_date");

    let issued = decode_full_date(buf, issue + 11);
    let expires = decode_full_date(buf, expiry + 12);
    assert(issued <= decode_full_date(held_since_cbor, 0), "Privilege held for too short a time");
    assert(expires >= decode_full_date(return_date_cbor, 0), "Privilege expires before the return");
}
