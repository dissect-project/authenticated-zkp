#!/bin/bash

# Check for exactly two input arguments
if [ $# -ne 2 ]; then
  echo "Usage: $0 STRING1 STRING2"
  exit 1
fi

STRING1="$1"
STRING2="$2"

# Convert both strings to hex
str1_hex=$(echo -n "$STRING1" | xxd -p -c 256)
str2_hex=$(echo -n "$STRING2" | xxd -p -c 256)

# Generate 16-byte (128-bit) random salt
salt_hex=$(openssl rand -hex 16)

# Concatenate salt + string1 hex (can change this logic as needed)
combined_hex="${salt_hex}${str1_hex}"

# Hash the binary data
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

# Output all values
echo "Input STRING1: $STRING1"
echo "STRING1 (ASCII u8 array): $(hex_to_ascii_u8_array "$str1_hex")"
echo ""
echo "Input STRING2: $STRING2"
echo "STRING2 (ASCII u8 array): $(hex_to_ascii_u8_array "$str2_hex")"
echo ""
echo "Salt (u8 array): $(hex_to_ascii_u8_array "$salt_hex")"
echo "Hash (u8 array): $(hex_to_ascii_u8_array "$hash_hex")"