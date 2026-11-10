use iso::{item_message, md_pad};
use sha512::sha512_compression;
use std::ops::WrappingAdd;

// SHA-512(item[0..len]) of an IssuerSignedItemBytes as issued, hashing the padded item block by
// block
pub fn sha512_item_digest<let N: u32>(item: [u8; N], len: u32) -> [u8; 64] {
    let (msg, last): ([Field; 128 * ((N + 1 + 16 + 127) / 128)], [bool; (N + 1 + 16 + 127) / 128]) =
        md_pad::<_, 128, 16, _>(item_message(item, len, 0x80), len);

    let mut state: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    let mut digest_state = [0; 8];
    for b in 0..last.len() {
        let mut words = [0; 16];
        for w in 0..16 {
            let mut word = 0;
            for j in 0..8 {
                word = word * 256 + msg[128 * b + 8 * w + j];
            }
            words[w] = word as u64;
        }
        // sha512_compression returns the compressed state without the feed-forward
        let c = sha512_compression(words, state);
        for w in 0..8 {
            state[w] = state[w].wrapping_add(c[w]);
            digest_state[w] += last[b] as Field * state[w] as Field;
        }
    }
    let mut out = [0; 64];
    for w in 0..8 {
        let bytes: [u8; 8] = digest_state[w].to_be_bytes();
        for j in 0..8 {
            out[8 * w + j] = bytes[j];
        }
    }
    out
}
