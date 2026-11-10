use iso::item_message;
use poseidon::poseidon::bn254::sponge;

// Poseidon is only a comparison here (no ISO issuer uses it): the item is zero-padded to
// 31 * POSEIDON_CHUNKS = 992 bytes, packed into big-endian chunks of 31 bytes (each below the
// BN254 modulus) and absorbed by the Poseidon sponge. The item encodes its own length, so the
// zero padding is unambiguous.
pub global POSEIDON_CHUNKS: u32 = 32;

pub fn poseidon_bytes<let N: u32>(item: [Field; N]) -> Field {
    assert(N <= 31 * POSEIDON_CHUNKS);
    let mut chunks = [0; POSEIDON_CHUNKS];
    for c in 0..POSEIDON_CHUNKS {
        for j in 0..31 {
            let i = 31 * c + j;
            chunks[c] = chunks[c] * 256 + if i < N { item[i] } else { 0 };
        }
    }
    sponge(chunks)
}

// Poseidon of item[0..len], an IssuerSignedItemBytes as issued
pub fn poseidon_item_digest<let N: u32>(item: [u8; N], len: u32) -> Field {
    poseidon_bytes(item_message(item, len, 0))
}
