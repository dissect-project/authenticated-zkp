#!/bin/bash

DOB="16/08/1999"
TODAY="21/07/2025"

# Convert date string to hex-encoded ASCII
dob_hex=$(echo -n "$DOB" | xxd -p -c 256)
today_hex=$(echo -n "$TODAY" | xxd -p -c 256)

# Generate 16-byte (128-bit) random salt
salt_hex="6e23df93b6365b75bd064b60ce18cfb0"

# ----------------- MODIFIED SECTION -----------------
# Hashed value is hardcoded due to Noir's underlying prover backend (Barretenberg),
# which uses a different MiMC implementation (with different parameters) than the
# ones find for example in circomlibjs
hash_u8_array="[20,115,63,130,241,133,53,135,23,232,2,239,35,51,232,11,208,129,217,235,253,56,190,93,134,211,202,152,252,110,223,23]"
# ----------------------------------------------------

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
echo "Hash (u8 array): $hash_u8_array"
