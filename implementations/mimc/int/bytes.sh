#!/bin/bash

NUMBER1=7
NUMBER2=5

# Generate 16-byte (128-bit) random salt
salt_hex="9b1bdba77e9b38571825a22f385af711"

# Convert numbers to 2-digit hex (padded)
num1_hex=$(printf "%02x" "$NUMBER1")
num2_hex=$(printf "%02x" "$NUMBER2")

# ----------------- MODIFIED SECTION -----------------
# Hashed value is hardcoded due to Noir's underlying prover backend (Barretenberg),
# which uses a different MiMC implementation (with different parameters) than the
# ones find for example in circomlibjs
hash_u8_array="[9, 54, 97, 252, 56, 52, 235, 248, 35, 18, 144, 157, 233, 35, 146, 136, 188, 88, 123, 28, 66, 133, 200, 134, 240, 51, 248, 198, 248, 187, 35, 125]"
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

# Output everything
echo "Number 1: $NUMBER1 → Hex: $num1_hex"
echo "Number 2: $NUMBER2 → Hex: $num2_hex"
echo "Salt (u8 array): $(hex_to_ascii_u8_array "$salt_hex")"
echo "Hash (u8 array): $hash_u8_array"
