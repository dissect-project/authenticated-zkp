#!/bin/bash

NUMBER1=7
NUMBER2=5

# Generate 16-byte (128-bit) random salt
salt_hex="6e23df93b6365b75bd064b60ce18cfb0"

# Convert numbers to 2-digit hex (padded)
num1_hex=$(printf "%02x" "$NUMBER1")
num2_hex=$(printf "%02x" "$NUMBER2")

# ----------------- MODIFIED SECTION -----------------
# Hashed value is hardcoded due to Noir's underlying prover backend (Barretenberg),
# which uses a different MiMC implementation (with different parameters) than the
# ones find for example in circomlibjs
hash_u8_array="[30,206,132,36,79,101,130,112,140,122,92,167,140,76,126,203,87,33,189,144,217,163,108,215,133,222,72,153,132,59,245,188]"
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
