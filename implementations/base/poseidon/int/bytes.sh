#!/bin/bash

# Check for exactly two input arguments
if [ $# -ne 2 ]; then
  echo "Usage: $0 NUMBER1 NUMBER2"
  exit 1
fi

NUMBER1="$1"
NUMBER2="$2"

# Validate that both inputs are integers between 0–255 (for u8 compatibility)
if ! [[ "$NUMBER1" =~ ^[0-9]+$ && "$NUMBER1" -ge 0 && "$NUMBER1" -le 255 ]]; then
  echo "Error: NUMBER1 must be an integer between 0 and 255"
  exit 1
fi

if ! [[ "$NUMBER2" =~ ^[0-9]+$ && "$NUMBER2" -ge 0 && "$NUMBER2" -le 255 ]]; then
  echo "Error: NUMBER2 must be an integer between 0 and 255"
  exit 1
fi

# Generate 16-byte (128-bit) random salt
salt_hex=$(openssl rand -hex 16)

# Convert numbers to 2-digit hex (padded)
num1_hex=$(printf "%02x" "$NUMBER1")
num2_hex=$(printf "%02x" "$NUMBER2")

# Concatenate salt + numbers in hex
combined_hex="${salt_hex}${num1_hex}"

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
    const dob = BigInt('0x' + '$num1_hex');
    
    // Compute Poseidon hash of the two Field elements
    const hash = poseidon([salt, dob]);
    
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

# Output everything
echo "Number 1: $NUMBER1 → Hex: $num1_hex"
echo "Number 2: $NUMBER2 → Hex: $num2_hex"
echo "Salt (u8 array): $(hex_to_ascii_u8_array "$salt_hex")"
echo "Hash (u8 array): $(hex_to_ascii_u8_array "$hash_hex")"
