use iso::{issuer_signed_item, MAX_UINT_LEN, RANDOM_CBOR_LEN};
use poseidon::poseidon::bn254::hash_9;

// An item has at most 259 bytes (a tag-24 bstr of up to 255 bytes), i.e. 9 chunks of 31 bytes
global POSEIDON_CHUNKS: u32 = 9;

// Poseidon of IssuerSignedItemBytes, zero-padded to 279 bytes and packed into 9 big-endian
// chunks of 31 bytes (each below the BN254 modulus). The item encodes its own length, so the
// zero padding is unambiguous. Circom-compatible: poseidon(chunks) in circomlibjs.
pub fn poseidon_bytes<let N: u32>(item: [Field; N]) -> Field {
    assert(N <= 31 * POSEIDON_CHUNKS);
    let mut chunks = [0; POSEIDON_CHUNKS];
    for c in 0..POSEIDON_CHUNKS {
        for j in 0..31 {
            let i = 31 * c + j;
            chunks[c] = chunks[c] * 256 + if i < N { item[i] } else { 0 };
        }
    }
    hash_9(chunks)
}

pub fn poseidon_item_digest<let E: u32, let V: u32>(
    digest_id: [u8; MAX_UINT_LEN],
    random: [u8; RANDOM_CBOR_LEN],
    element_id: [u8; E],
    value: [u8; V],
    value_len: u32,
) -> Field {
    let (item, _) = issuer_signed_item(digest_id, random, element_id, value, value_len, 0);
    poseidon_bytes(item)
}
