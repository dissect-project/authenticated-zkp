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

# Concatenate salt + cleaned list (both in hex), then hash
combined_hex="${salt_hex}${list_hex}"
hash_hex=$(echo -n "$combined_hex" | xxd -r -p | sha512sum | awk '{print $1}')

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
