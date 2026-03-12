#!/bin/bash

# Check for exactly two input arguments
if [ $# -ne 2 ]; then
  echo "Usage: $0 LIST (e.g. [PT,EN,ES]) NATIONALITY (e.g. ES)"
  exit 1
fi

LIST="$1"
NATIONALITY="$2"

# Clean LIST by removing square brackets and commas
clean_list=$(echo -n "$LIST" | tr -d '[],')

# Convert cleaned LIST and NATIONALITY to hex
list_hex=$(echo -n "$clean_list" | xxd -p -c 256)
nationality_hex=$(echo -n "$NATIONALITY" | xxd -p -c 256)

# Generate 16-byte (128-bit) random salt
salt_hex=$(openssl rand -hex 16)

# Compute Poseidon hash using circomlibjs (matches Noir's bn254 Poseidon)
# We treat the salt and the DOB as two separate BN254 Field elements.
# This corresponds to Noir's `std::hash::poseidon::bn254::hash_2([salt, dob])`
hash_hex=$(node -e "
const { buildPoseidon } = require('circomlibjs');
async function run() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    
    // Parse hex strings as BigInts
    const salt = BigInt('0x' + '$salt_hex');
    const list = BigInt('0x' + '$list_hex');
    
    // Compute Poseidon hash of the two Field elements
    const hash = poseidon([salt, list]);
    
    // Convert the result to a 32-byte big-endian hex string
    let hex = F.toString(hash, 16);
    console.log(hex.padStart(64, '0'));
}
run();
")

# Function: Convert hex string to ASCII decimal u8 array
hex_to_ascii_u8_array() {
  local hex=$1
  local arr="["
  for ((i=0; i<${#hex}; i+=2)); do
    byte_dec=$((16#${hex:$i:2}))
    arr+="$byte_dec, "
  done
  arr=${arr%, } # Remove trailing comma
  arr+="]"
  echo "$arr"
}

# Output all parts
echo "Input LIST (raw): $LIST"
echo "Cleaned LIST: $clean_list"
echo "LIST (ASCII u8 array): $(hex_to_ascii_u8_array "$list_hex")"
echo ""
echo "Input NATIONALITY: $NATIONALITY"
echo "NATIONALITY (ASCII u8 array): $(hex_to_ascii_u8_array "$nationality_hex")"
echo ""
echo "Salt (u8 array): $(hex_to_ascii_u8_array "$salt_hex")"
echo "Hash (u8 array): $(hex_to_ascii_u8_array "$hash_hex")"
