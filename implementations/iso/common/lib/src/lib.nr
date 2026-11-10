use std::hash::sha256_compression;

pub mod cbor;
pub mod predicates;

// ISO/IEC 18013-5 (9.1.2.4): the MSO digest of a data element is
//   h = H(IssuerSignedItemBytes), IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
//   IssuerSignedItem = { "digestID": uint, "random": bstr, "elementIdentifier": tstr, "elementValue": any }
// The standard fixes neither the order of the four entries nor the length of random beyond a
// 16-byte minimum, and h is over the bytes exactly as the issuer encoded them. The circuits
// therefore receive IssuerSignedItemBytes as issued and parse it (parse_item): the four entries in
// any order, a random of MIN_RANDOM_LEN to MAX_RANDOM_LEN bytes, and items of up to 65535 bytes.
// The standard allows H = SHA-256, SHA-384 or SHA-512; SHA-512 is in ../sha512, and
// ../poseidon applies Poseidon to the same bytes for comparison, which no ISO issuer produces.

// A CBOR uint (digestID or an integer elementValue) takes at most 9 bytes
pub global MAX_UINT_LEN: u32 = 9;
pub global MIN_RANDOM_LEN: u32 = 16; // the minimum allowed by the standard
pub global MAX_RANDOM_LEN: u32 = 32;

// The four keys of IssuerSignedItem as CBOR text strings, each with a distinct first byte
global KEY_DIGEST_ID: [u8; 9] = [0x68, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x49, 0x44];
global KEY_RANDOM: [u8; 7] = [0x66, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d];
global KEY_ELEMENT_ID: [u8; 18] = [
    0x71, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69,
    0x65, 0x72,
];
global KEY_VALUE: [u8; 13] =
    [0x6c, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x56, 0x61, 0x6c, 0x75, 0x65];

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

// Decodes the CBOR full-date (RFC 8943) at cbor[off..], tag 1004 over a 10-byte text string
// "YYYY-MM-DD", i.e. D9 03 EC 6A <date>, as the number YYYYMMDD
pub fn decode_full_date<let N: u32>(cbor: [u8; N], off: u32) -> u32 {
    let prefix = [0xD9, 0x03, 0xEC, 0x6A];
    for i in 0..4 {
        assert(cbor[off + i] == prefix[i], "Not a CBOR full-date");
    }
    assert((cbor[off + 8] == 45) & (cbor[off + 11] == 45), "Not a YYYY-MM-DD date");
    let mut date: u32 = 0;
    for i in [4, 5, 6, 7, 9, 10, 12, 13] {
        let c = cbor[off + i];
        assert((c >= 48) & (c <= 57), "Not a YYYY-MM-DD date");
        date = date * 10 + (c - 48) as u32;
    }
    date
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

// The parsed IssuerSignedItemBytes: the digestID, and where the elementValue is in the item.
pub struct Item {
    pub digest_id: u64,
    pub value_off: u32,
    pub value_len: u32,
}

// Size of the CBOR data item at buf[off..], computed outside the circuit (a hint)
unconstrained fn cbor_item_len<let N: u32>(buf: [u8; N], off: u32) -> u32 {
    let mut pos = off;
    let mut left: u32 = 1;
    for _ in 0..N {
        if (left != 0) & (pos + 2 < N) {
            let b = buf[pos] as u32;
            let (major, ai) = (b / 32, b % 32);
            let (arg, head) = if ai < 24 {
                (ai, 1)
            } else if ai == 24 {
                (buf[pos + 1] as u32, 2)
            } else if ai == 25 {
                (buf[pos + 1] as u32 * 256 + buf[pos + 2] as u32, 3)
            } else if ai == 26 {
                (0, 5)
            } else {
                (0, 9)
            };
            left -= 1;
            pos += head;
            if (major == 2) | (major == 3) {
                pos += arg;
            }
            if major == 4 {
                left += arg;
            }
            if major == 5 {
                left += 2 * arg;
            }
            if major == 6 {
                left += 1;
            }
        }
    }
    pos - off
}

// Offsets of the four entries (digestID, random, elementIdentifier, elementValue), their order in
// the item, and the length of the elementValue, computed outside the circuit (a hint)
unconstrained fn item_layout<let N: u32>(item: [u8; N], first: u32) -> ([u32; 4], [u32; 4], u32) {
    let mut offs = [0; 4];
    let mut order = [0; 4];
    let mut value_len = 0;
    let mut pos = first;
    for j in 0..4 {
        if pos < N {
            let b = item[pos];
            let k = if b == KEY_DIGEST_ID[0] {
                0
            } else if b == KEY_RANDOM[0] {
                1
            } else if b == KEY_ELEMENT_ID[0] {
                2
            } else {
                3
            };
            let key_len = [9, 7, 18, 13][k];
            offs[k] = pos;
            order[j] = k;
            let len = cbor_item_len(item, pos + key_len);
            if k == 3 {
                value_len = len;
            }
            pos += key_len + len;
        }
    }
    (offs, order, value_len)
}

// Parses IssuerSignedItemBytes, item[0..len], as issued: #6.24(bstr) over a map of the four
// entries in any order, with the elementIdentifier `element_id` (a text string shorter than 24
// bytes). Checks the tag and bstr head, the map head, each key, digestID (a CBOR uint), random (a
// bstr of MIN_RANDOM_LEN to MAX_RANDOM_LEN bytes) and the elementIdentifier, and that the entries
// are contiguous and fill the map. The elementValue is what remains; the caller checks that
// item[value_off..value_off + value_len] is exactly one CBOR item of the expected type, which makes
// the split of the item into entries unique.
pub fn parse_item<let N: u32, let E: u32>(item: [u8; N], len: u32, element_id: [u8; E]) -> Item {
    assert(E < 24);
    assert(len <= N, "IssuerSignedItemBytes exceeds the maximum size");
    // reads past the item (within the bound) are zeros
    let mut buf: [u8; N + 64] = [0; N + 64];
    for i in 0..N {
        buf[i] = item[i];
    }
    // D8 18, then the bstr head: 58 LL or 59 LL LL
    assert((buf[0] == 0xD8) & (buf[1] == 0x18), "Not IssuerSignedItemBytes (#6.24)");
    let short = buf[2] == 0x58;
    assert(short | (buf[2] == 0x59), "Not IssuerSignedItemBytes (bstr head)");
    let first = if short { 5 } else { 6 };
    let inner = if short {
        buf[3] as u32
    } else {
        buf[3] as u32 * 256 + buf[4] as u32
    };
    assert(inner == len - (first - 1), "IssuerSignedItemBytes length mismatch");
    assert(buf[first - 1] == 0xA4, "IssuerSignedItem is not a map of 4 entries");

    // Safety: the offsets, order and value length are checked below
    let (offs, order, value_len) = unsafe { item_layout(buf, first) };

    // the keys
    for k in 0..9 {
        assert(buf[offs[0] + k] == KEY_DIGEST_ID[k], "Invalid digestID key");
    }
    for k in 0..7 {
        assert(buf[offs[1] + k] == KEY_RANDOM[k], "Invalid random key");
    }
    for k in 0..18 {
        assert(buf[offs[2] + k] == KEY_ELEMENT_ID[k], "Invalid elementIdentifier key");
    }
    for k in 0..13 {
        assert(buf[offs[3] + k] == KEY_VALUE[k], "Invalid elementValue key");
    }
    // digestID: a CBOR uint
    let mut id_bytes = [0; MAX_UINT_LEN];
    for k in 0..MAX_UINT_LEN {
        id_bytes[k] = buf[offs[0] + 9 + k];
    }
    let (digest_id, id_len, _) = decode_uint(id_bytes);
    // random: a bstr of MIN_RANDOM_LEN to MAX_RANDOM_LEN bytes, head 40+n (n < 24) or 58 n
    let rh = buf[offs[1] + 7];
    let r_short = (rh >= 0x40) & (rh < 0x58);
    assert(r_short | (rh == 0x58), "random is not a CBOR byte string");
    let r_len = if r_short {
        (rh - 0x40) as u32
    } else {
        buf[offs[1] + 8] as u32
    };
    assert(
        (r_len >= MIN_RANDOM_LEN) & (r_len <= MAX_RANDOM_LEN),
        "random has an unsupported length",
    );
    let r_head = if r_short { 1 } else { 2 };
    // elementIdentifier: the text string element_id
    assert(buf[offs[2] + 18] == 0x60 + E as u8, "Wrong elementIdentifier");
    for k in 0..E {
        assert(buf[offs[2] + 19 + k] == element_id[k], "Wrong elementIdentifier");
    }
    // the entries in the hinted order are contiguous and fill the map
    let seg = [9 + id_len, 7 + r_head + r_len, 19 + E, 13 + value_len];
    for i in 0..4 {
        assert(order[i] < 4, "Invalid entry order");
        for j in 0..i {
            assert(order[i] != order[j], "Invalid entry order");
        }
    }
    let mut pos = first;
    for j in 0..4 {
        assert(offs[order[j]] == pos, "IssuerSignedItem entries are not contiguous");
        pos += seg[order[j]];
    }
    assert(pos == len, "IssuerSignedItem entries do not fill the item");
    Item { digest_id, value_off: offs[3] + 13, value_len }
}

// The elementValue of a parsed item as an array of V bytes (zeros after value_len)
pub fn item_value<let N: u32, let V: u32>(item: [u8; N], parsed: Item) -> [u8; V] {
    assert(parsed.value_len <= V, "elementValue exceeds the maximum size");
    let mut buf: [u8; N + V] = [0; N + V];
    for i in 0..N {
        buf[i] = item[i];
    }
    let mut out = [0; V];
    for i in 0..V {
        out[i] = (i < parsed.value_len) as u8 * buf[parsed.value_off + i];
    }
    out
}

// item[0..len] followed by the byte `marker` (0x80 for SHA-2 padding) and zeros
pub fn item_message<let N: u32>(item: [u8; N], len: u32, marker: Field) -> [Field; N + 1] {
    let mut msg = [0; N + 1];
    for i in 0..N {
        msg[i] = (i < len) as Field * item[i] as Field;
    }
    for i in 0..(N + 1) {
        msg[i] += (i == len) as Field * marker;
    }
    msg
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

// SHA-256(item[0..len]), hashing the padded item block by block
pub fn sha256_item_digest<let N: u32>(item: [u8; N], len: u32) -> [u8; 32] {
    let (msg, last): ([Field; 64 * ((N + 1 + 8 + 63) / 64)], [bool; (N + 1 + 8 + 63) / 64]) =
        md_pad::<_, 64, 8, _>(item_message(item, len, 0x80), len);

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
