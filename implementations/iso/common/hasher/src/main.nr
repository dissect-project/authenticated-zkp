// Prints the Poseidon digest of an IssuerSignedItemBytes (zero-padded to 279 bytes) as computed
// by the poseidon-iso circuits; used by ../generate.py.
use iso_poseidon::poseidon_bytes;

fn main(item: [u8; 279]) -> pub Field {
    let mut fields = [0; 279];
    for i in 0..279 {
        fields[i] = item[i] as Field;
    }
    poseidon_bytes(fields)
}
