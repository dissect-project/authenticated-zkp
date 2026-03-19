#!/bin/bash

# Generate 16-byte (128-bit) random salt
salt_hex="09c257951b514803e849365a606dac94"

# ----------------- MODIFIED SECTION -----------------
# Hashed value is hardcoded due to Noir's underlying prover backend (Barretenberg),
# which uses a different MiMC implementation (with different parameters) than the
# ones find for example in circomlibjs
hash_u8_array="[10,236,72,23,208,29,117,151,54,159,253,217,114,216,239,178,216,171,46,83,14,98,166,21,6,2,67,231,233,37,194,139]"
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

# Output all values
echo "Input STRING1: $STRING1"
echo "STRING1 (ASCII u8 array): $(hex_to_ascii_u8_array "$str1_hex")"
echo ""
echo "Input STRING2: $STRING2"
echo "STRING2 (ASCII u8 array): $(hex_to_ascii_u8_array "$str2_hex")"
echo ""
echo "Salt (u8 array): $(hex_to_ascii_u8_array "$salt_hex")"
echo "Hash (u8 array): $hash_u8_array"