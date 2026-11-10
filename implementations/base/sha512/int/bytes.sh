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

# Output everything
echo "Number 1: $NUMBER1 → Hex: $num1_hex"
echo "Number 2: $NUMBER2 → Hex: $num2_hex"
echo "Salt (u8 array): $(hex_to_ascii_u8_array "$salt_hex")"
echo "Hash (u8 array): $(hex_to_ascii_u8_array "$hash_hex")"
