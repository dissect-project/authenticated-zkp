#!/bin/bash

LIST="["PT","EN","--","--","--"]"
NATIONALITY=""EN""

# Clean LIST by removing square brackets and commas
clean_list=$(echo -n "$LIST" | tr -d '[],')

# Convert cleaned LIST and NATIONALITY to hex
list_hex=$(echo -n "$clean_list" | xxd -p -c 256)
nationality_hex=$(echo -n "$NATIONALITY" | xxd -p -c 256)

# Generate 16-byte (128-bit) random salt
salt_hex="6e23df93b6365b75bd064b60ce18cfb0"

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

# Output all parts
echo "Input LIST (raw): $LIST"
echo "Cleaned LIST: $clean_list"
echo "LIST (ASCII u8 array): $(hex_to_ascii_u8_array "$list_hex")"
echo ""
echo "Input NATIONALITY: $NATIONALITY"
echo "NATIONALITY (ASCII u8 array): $(hex_to_ascii_u8_array "$nationality_hex")"
echo ""
echo "Salt (u8 array): $(hex_to_ascii_u8_array "$salt_hex")"
echo "Hash (u8 array): $hash_u8_array"
