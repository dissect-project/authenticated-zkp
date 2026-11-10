// Prints the Poseidon digest of an IssuerSignedItemBytes (zero-padded to 992 bytes) as computed
// by the poseidon-iso circuits; used by credentials/inputs.py.
use iso_poseidon::poseidon_bytes;

fn main(item: [u8; 992]) -> pub Field {
    let mut fields = [0; 992];
    for i in 0..992 {
        fields[i] = item[i] as Field;
    }
    poseidon_bytes(fields)
}
