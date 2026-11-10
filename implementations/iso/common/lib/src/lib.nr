use std::hash::sha256_compression;

// ISO/IEC 18013-5 (9.1.2.4): the MSO digest of a data element is
//   h = H(IssuerSignedItemBytes), IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
//   IssuerSignedItem = { "digestID": uint, "random": bstr, "elementIdentifier": tstr, "elementValue": any }
// encoded with the keys in this order, as in the examples of Annex D. The standard allows
// H = SHA-256, SHA-384 or SHA-512; poseidon_item_digest applies Poseidon to the same bytes for
// comparison (in ../poseidon), which no ISO issuer produces; SHA-512 is in ../sha512.
//
// The circuits receive each field already CBOR-encoded, as it appears in the issuer's item
// (digestID, random and elementValue), and the library checks that each field is exactly one
// CBOR data item of the expected type. That makes the split of the item into fields unique, so
// a prover cannot move bytes from one field to another while keeping the same hash.
pub global RANDOM_LEN: u32 = 16; // the minimum allowed by the standard
// bstr head of random: 0x40 + length below 24 bytes, 58 LL from 24 to 255 bytes
global RANDOM_HEAD_LEN: u32 = if RANDOM_LEN < 24 { 1 } else { 2 };
// random as a CBOR bstr: head and bytes
pub global RANDOM_CBOR_LEN: u32 = RANDOM_HEAD_LEN + RANDOM_LEN;

// D8 18 58 LL A4 68 "digestID"
pub global HEAD_LEN: u32 = 14;
// A CBOR uint (digestID or an integer elementValue) takes at most 9 bytes
pub global MAX_UINT_LEN: u32 = 9;
// 66 "random" <random as CBOR> 71 "elementIdentifier"
pub global RANDOM_PART_LEN: u32 = 7 + RANDOM_CBOR_LEN + 18;
// 6C "elementValue"
pub global VALUE_KEY_LEN: u32 = 13;

// Decodes the CBOR unsigned integer (major type 0) at the start of field, in any of its encodings
// (1, 2, 3, 5 or 9 bytes, preferred or not; bytes after it are ignored). Returns the value, its
// encoded length and one-hot flags for the lengths 1, 2, 3, 5 and 9.
pub fn decode_uint<let N: u32>(field: [u8; N]) -> (u64, u32, [bool; 5]) {
    assert(N >= MAX_UINT_LEN);
    let b0 = field[0];
    assert(b0 >> 5 == 0, "Not a CBOR unsigned integer");
    let ai = b0 & 0x1f;
    let flags = [ai < 24, ai == 24, ai == 25, ai == 26, ai == 27];
    let lens = [1, 2, 3, 5, 9];
    let mut len = 0;
    for s in 0..5 {
        len += flags[s] as u32 * lens[s];
    }
    assert(len != 0, "Invalid CBOR integer head");
    // big-endian argument after the head, selected by length
    let mut v: Field = ai as Field;
    let mut arg: Field = 0;
    for i in 1..MAX_UINT_LEN {
        arg = arg * 256 + field[i] as Field;
        for s in 1..5 {
            if i == lens[s] - 1 {
                v += flags[s] as Field * (arg - ai as Field);
            }
        }
    }
    (v as u64, len, flags)
}

// Decodes a CBOR full-date (RFC 8943), tag 1004 over a 10-byte text string "YYYY-MM-DD", i.e.
// D9 03 EC 6A <date>, and returns the date as "DD/MM/YYYY"
pub fn decode_full_date(cbor: [u8; 14]) -> [u8; 10] {
    let prefix = [0xD9, 0x03, 0xEC, 0x6A];
    for i in 0..4 {
        assert(cbor[i] == prefix[i], "Not a CBOR full-date");
    }
    assert((cbor[8] == 45) & (cbor[11] == 45), "Not a YYYY-MM-DD date");
    [cbor[12], cbor[13], 47, cbor[9], cbor[10], 47, cbor[4], cbor[5], cbor[6], cbor[7]]
}

// Decodes cbor, which must be exactly a CBOR text string of N < 24 bytes (head 0x60 + N)
pub fn decode_text<let N: u32, let M: u32>(cbor: [u8; M]) -> [u8; N] {
    assert(N < 24);
    assert(M == N + 1);
    assert(cbor[0] == 0x60 + N as u8, "Not a CBOR text string of the expected length");
    let mut out = [0; N];
    for i in 0..N {
        out[i] = cbor[1 + i];
    }
    out
}

// Decodes a digest as the MSO stores it in valueDigests: cbor must be exactly a CBOR byte string
// of N bytes, 24 <= N < 256 (head 58 NN)
pub fn decode_digest<let N: u32, let M: u32>(cbor: [u8; M]) -> [u8; N] {
    assert((N >= 24) & (N < 256));
    assert(M == N + 2);
    assert((cbor[0] == 0x58) & (cbor[1] == N as u8), "Not a CBOR byte string of the digest length");
    let mut out = [0; N];
    for i in 0..N {
        out[i] = cbor[2 + i];
    }
    out
}

// Checks that random is a CBOR bstr of RANDOM_LEN bytes (preferred head)
pub fn check_random(random: [u8; RANDOM_CBOR_LEN]) {
    if RANDOM_LEN < 24 {
        assert(random[0] == 0x40 + RANDOM_LEN as u8, "random is not a 16-byte CBOR bstr");
    } else {
        assert(random[0] == 0x58, "random is not a CBOR bstr");
        assert(random[1] == RANDOM_LEN as u8, "random has the wrong length");
    }
}

// src[i - shift] for the flagged shift of 1, 2, 3, 5 or 9, or 0 when out of range
fn shifted<let N: u32>(src: [Field; N], flags: [bool; 5], i: u32) -> Field {
    let shifts = [1, 2, 3, 5, 9];
    let mut out = 0;
    for s in 0..5 {
        if i >= shifts[s] {
            if i - shifts[s] < N {
                out += flags[s] as Field * src[i - shifts[s]];
            }
        }
    }
    out
}

// IssuerSignedItemBytes from the CBOR-encoded digestID, random and elementValue (value[0..value_len])
// and the constant elementIdentifier `element_id` (a tstr shorter than 24 bytes), followed by the
// byte `marker` (0x80 for SHA-2 padding) and zeros. digestID and random are checked to be a
// single CBOR uint and bstr, and the length of digestID is taken from its encoding; the caller
// checks that the elementValue is a single item of the expected type and passes its length. Each byte is a selection over the five
// possible digestID lengths rather than a write at a variable offset. Returns the bytes and the
// length of the item.
pub fn issuer_signed_item<let E: u32, let V: u32>(
    digest_id: [u8; MAX_UINT_LEN],
    random: [u8; RANDOM_CBOR_LEN],
    element_id: [u8; E],
    value: [u8; V],
    value_len: u32,
    marker: Field,
) -> ([Field; HEAD_LEN + MAX_UINT_LEN + RANDOM_PART_LEN + 1 + E + VALUE_KEY_LEN + V + 1], u32) {
    assert(E < 24);
    assert(value_len <= V);
    let (_, digest_id_len, id_flags) = decode_uint(digest_id);
    check_random(random);
    let len = HEAD_LEN + digest_id_len + RANDOM_PART_LEN + 1 + E + VALUE_KEY_LEN + value_len;
    // #6.24(bstr) with a one-byte length
    assert(len - 4 < 256, "IssuerSignedItem longer than 255 bytes");

    // Everything after the digestID, followed by the marker
    let mut tail = [0; RANDOM_PART_LEN + 1 + E + VALUE_KEY_LEN + V + 1];
    let mut k = 0;
    for c in [0x66].concat("random".as_bytes()) {
        tail[k] = c as Field;
        k += 1;
    }
    for i in 0..RANDOM_CBOR_LEN {
        tail[k] = random[i] as Field;
        k += 1;
    }
    for c in [0x71].concat("elementIdentifier".as_bytes()) {
        tail[k] = c as Field;
        k += 1;
    }
    assert(k == RANDOM_PART_LEN);
    tail[k] = 0x60 + E as Field;
    k += 1;
    for i in 0..E {
        tail[k] = element_id[i] as Field;
        k += 1;
    }
    for c in [0x6C].concat("elementValue".as_bytes()) {
        tail[k] = c as Field;
        k += 1;
    }
    for i in 0..(V + 1) {
        if i < V {
            tail[k + i] = (i < value_len) as Field * value[i] as Field;
        }
        tail[k + i] += (i == value_len) as Field * marker;
    }

    let mut msg = [0; HEAD_LEN + MAX_UINT_LEN + RANDOM_PART_LEN + 1 + E + VALUE_KEY_LEN + V + 1];
    let head = [0xD8, 0x18, 0x58, 0, 0xA4, 0x68].concat("digestID".as_bytes());
    for i in 0..HEAD_LEN {
        msg[i] = head[i] as Field;
    }
    msg[3] = (len - 4) as Field;
    // digestID, then the tail shifted by the length of the digestID
    for i in 0..(msg.len() - HEAD_LEN) {
        let mut c = shifted(tail, id_flags, i);
        if i < MAX_UINT_LEN {
            c += (i < digest_id_len) as Field * digest_id[i] as Field;
        }
        msg[HEAD_LEN + i] = c;
    }
    (msg, len)
}

// Merkle-Damgard padding: copies msg (which already holds the 0x80 byte) into BLOCKS blocks of
// B bytes and writes the length in bits into the last 8 bytes of the block where the message
// ends, given that the length field takes L bytes. Returns the padded message and a flag
// marking that last block.
pub fn md_pad<let N: u32, let B: u32, let L: u32, let BLOCKS: u32>(
    msg: [Field; N],
    len: u32,
) -> ([Field; B * BLOCKS], [bool; BLOCKS]) {
    assert(N <= B * BLOCKS);
    let mut padded = [0; B * BLOCKS];
    for i in 0..N {
        padded[i] = msg[i];
    }
    let bit_len: [u8; 8] = ((len * 8) as Field).to_be_bytes();
    let mut last = [false; BLOCKS];
    for b in 0..BLOCKS {
        last[b] = (len + 1 + L > B * b) & (len + 1 + L <= B * (b + 1));
        for j in 0..8 {
            padded[B * b + B - 8 + j] += last[b] as Field * bit_len[j] as Field;
        }
    }
    (padded, last)
}

// SHA-256(IssuerSignedItemBytes), hashing the padded item block by block
pub fn sha256_item_digest<let E: u32, let V: u32>(
    digest_id: [u8; MAX_UINT_LEN],
    random: [u8; RANDOM_CBOR_LEN],
    element_id: [u8; E],
    value: [u8; V],
    value_len: u32,
) -> [u8; 32] {
    let (item, len) = issuer_signed_item(digest_id, random, element_id, value, value_len, 0x80);
    let (msg, last): ([Field; 64 * ((HEAD_LEN + MAX_UINT_LEN + RANDOM_PART_LEN + 1 + E + VALUE_KEY_LEN + V + 1 + 8 + 63) / 64)], [bool; (HEAD_LEN + MAX_UINT_LEN + RANDOM_PART_LEN + 1 + E + VALUE_KEY_LEN + V + 1 + 8 + 63) / 64]) =
        md_pad::<_, 64, 8, _>(item, len);

    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut digest_state = [0; 8];
    for b in 0..last.len() {
        let mut words = [0; 16];
        for w in 0..16 {
            let mut word = 0;
            for j in 0..4 {
                word = word * 256 + msg[64 * b + 4 * w + j];
            }
            words[w] = word as u32;
        }
        state = sha256_compression(words, state);
        for w in 0..8 {
            digest_state[w] += last[b] as Field * state[w] as Field;
        }
    }
    let mut out = [0; 32];
    for w in 0..8 {
        let bytes: [u8; 4] = digest_state[w].to_be_bytes();
        for j in 0..4 {
            out[4 * w + j] = bytes[j];
        }
    }
    out
}

// A 32-byte big-endian public input as a Field
pub fn field_from_be_bytes(bytes: [u8; 32]) -> Field {
    let mut f = 0;
    for i in 0..32 {
        f = f * 256 + bytes[i] as Field;
    }
    f
}

// Items whose padding ends at or next to a block boundary, with 1- and 9-byte digestIDs
// (the latter in a non-preferred encoding), checked against Python's hashlib
#[test]
fn test_block_boundaries() {
    let random: [u8; RANDOM_CBOR_LEN] = [80, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    // 118-byte item, digestID 07
    let value: [u8; 64] = [
        88, 33, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
        117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert(
        sha256_item_digest(
            [7, 0, 0, 0, 0, 0, 0, 0, 0],
            random,
            "age_in_years".as_bytes(),
            value,
            35,
        )
            == [
                252, 104, 16, 123, 136, 35, 149, 160, 101, 106, 153, 103, 173, 1, 105, 196, 26, 136,
                168, 48, 226, 115, 1, 123, 252, 65, 139, 221, 198, 75, 168, 13,
            ],
    );
    // 119-byte item, digestID 07
    let value: [u8; 64] = [
        88, 34, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
        117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert(
        sha256_item_digest(
            [7, 0, 0, 0, 0, 0, 0, 0, 0],
            random,
            "age_in_years".as_bytes(),
            value,
            36,
        )
            == [
                75, 82, 118, 88, 218, 49, 255, 12, 224, 252, 236, 221, 25, 20, 38, 165, 46, 132,
                140, 92, 45, 91, 206, 55, 252, 69, 100, 66, 129, 130, 164, 221,
            ],
    );
    // 120-byte item, digestID 07
    let value: [u8; 64] = [
        88, 35, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
        117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert(
        sha256_item_digest(
            [7, 0, 0, 0, 0, 0, 0, 0, 0],
            random,
            "age_in_years".as_bytes(),
            value,
            37,
        )
            == [
                148, 56, 128, 63, 143, 49, 33, 228, 209, 95, 90, 42, 94, 36, 137, 126, 141, 105,
                243, 81, 66, 121, 110, 180, 77, 182, 37, 59, 159, 201, 8, 233,
            ],
    );
    // 118-byte item, digestID 1b0000000000000007
    let value: [u8; 64] = [
        88, 25, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
        117, 118, 119, 120, 121, 122, 123, 124, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert(
        sha256_item_digest(
            [27, 0, 0, 0, 0, 0, 0, 0, 7],
            random,
            "age_in_years".as_bytes(),
            value,
            27,
        )
            == [
                49, 7, 43, 231, 237, 79, 1, 12, 133, 86, 214, 167, 20, 40, 178, 35, 160, 168, 243,
                45, 32, 166, 149, 181, 234, 208, 209, 87, 149, 224, 13, 198,
            ],
    );
    // 119-byte item, digestID 1b0000000000000007
    let value: [u8; 64] = [
        88, 26, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
        117, 118, 119, 120, 121, 122, 123, 124, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert(
        sha256_item_digest(
            [27, 0, 0, 0, 0, 0, 0, 0, 7],
            random,
            "age_in_years".as_bytes(),
            value,
            28,
        )
            == [
                96, 236, 222, 93, 230, 183, 188, 246, 116, 204, 194, 251, 219, 246, 199, 97, 218,
                95, 6, 103, 4, 112, 56, 4, 196, 247, 212, 163, 93, 230, 36, 110,
            ],
    );
    // 120-byte item, digestID 1b0000000000000007
    let value: [u8; 64] = [
        88, 27, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
        117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert(
        sha256_item_digest(
            [27, 0, 0, 0, 0, 0, 0, 0, 7],
            random,
            "age_in_years".as_bytes(),
            value,
            29,
        )
            == [
                185, 58, 225, 18, 102, 13, 253, 142, 141, 251, 38, 152, 27, 33, 234, 146, 207, 158,
                116, 149, 170, 46, 254, 215, 48, 107, 52, 128, 34, 108, 39, 113,
            ],
    );
}
