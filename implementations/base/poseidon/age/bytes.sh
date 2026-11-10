#!/bin/bash

# Check for exactly two input dates
if [ $# -ne 2 ]; then
  echo "Usage: $0 DOB(DD/MM/YYYY) TODAY(DD/MM/YYYY)"
  exit 1
fi

DOB="$1"
TODAY="$2"

# Validate date formats (basic regex, not strict validation)
if [[ ! "$DOB" =~ ^[0-9]{2}/[0-9]{2}/[0-9]{4}$ ]] || [[ ! "$TODAY" =~ ^[0-9]{2}/[0-9]{2}/[0-9]{4}$ ]]; then
  echo "Error: Dates must be in format DD/MM/YYYY"
  exit 1
fi

# Ensure Node.js and circomlibjs are available
if ! command -v node &> /dev/null; then
    echo "Error: Node.js is required to compute the Poseidon hash."
    exit 1
fi

if ! node -e "require('circomlibjs')" &> /dev/null; then
    echo "Error: 'circomlibjs' is not installed."
    echo "Please run: npm install circomlibjs"
    exit 1
fi

# Convert date string to hex-encoded ASCII
dob_hex=$(echo -n "$DOB" | xxd -p -c 256)
today_hex=$(echo -n "$TODAY" | xxd -p -c 256)

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
    const dob = BigInt('0x' + '$dob_hex');
    
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

# Output all parts
echo "Input DOB: $DOB"
echo "DOB (ASCII u8 array): $(hex_to_ascii_u8_array "$dob_hex")"
echo ""
echo "Input TODAY: $TODAY"
echo "TODAY (ASCII u8 array): $(hex_to_ascii_u8_array "$today_hex")"
echo ""
echo "Salt (u8 array): $(hex_to_ascii_u8_array "$salt_hex")"
echo "Hash (u8 array): $(hex_to_ascii_u8_array "$hash_hex")"
