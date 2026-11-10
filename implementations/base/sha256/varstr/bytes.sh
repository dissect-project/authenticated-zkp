#!/bin/bash

MAX_STRSIZE=150
MAX_SUBSTRSIZE=8
SALT_SIZE=16

# Check for exactly two input arguments
if [ $# -ne 2 ]; then
  echo "Usage: $0 STRING1 STRING2"
  exit 1
fi

STRING1="$1"
STRING2="$2"

# Lengths of the actual strings
str1_len=${#STRING1}
str2_len=${#STRING2}

# Validate lengths
if [ $str1_len -gt $MAX_STRSIZE ]; then
  echo "Error: STRING1 exceeds MAX_STRSIZE ($MAX_STRSIZE)"
  exit 1
fi
if [ $str2_len -gt $MAX_SUBSTRSIZE ]; then
  echo "Error: STRING2 exceeds MAX_SUBSTRSIZE ($MAX_SUBSTRSIZE)"
  exit 1
fi

# Convert both strings to hex
str1_hex=$(echo -n "$STRING1" | xxd -p -c 256)
str2_hex=$(echo -n "$STRING2" | xxd -p -c 256)

# Generate 16-byte (128-bit) random salt
salt_hex=$(openssl rand -hex $SALT_SIZE)

# Hash over salt || real STRING1 content only (no padding)
hash_hex=$(printf '%s%s' "$salt_hex" "$str1_hex" | xxd -r -p | sha256sum | awk '{print $1}')

# Function: Convert hex string to u8 array
hex_to_u8_array() {
  local hex=$1
  local arr="["
  for ((i=0; i<${#hex}; i+=2)); do
    byte_dec=$((16#${hex:$i:2}))
    arr+="$byte_dec, "
  done
  arr=${arr%, }
  arr+="]"
  echo "$arr"
}

# Function: Pad a hex string with zero bytes to a target byte length
pad_hex_to_size() {
  local hex=$1
  local target=$2
  local current_bytes=$(( ${#hex} / 2 ))
  local pad_bytes=$(( target - current_bytes ))
  local padding=$(printf '%0*d' $(( pad_bytes * 2 )) 0)
  echo "${hex}${padding}"
}

# Pad STRING1 to MAX_STRSIZE and STRING2 to MAX_SUBSTRSIZE
str1_padded_hex=$(pad_hex_to_size "$str1_hex" $MAX_STRSIZE)
str2_padded_hex=$(pad_hex_to_size "$str2_hex" $MAX_SUBSTRSIZE)

# Output
echo "# Prover inputs for Noir circuit"
echo ""
echo "# Private string (x): \"$STRING1\" padded to $MAX_STRSIZE bytes"
echo "x = $(hex_to_u8_array "$str1_padded_hex")"
echo "x_len = $str1_len"
echo ""
echo "# Public substring (y): \"$STRING2\" padded to $MAX_SUBSTRSIZE bytes"
echo "y = $(hex_to_u8_array "$str2_padded_hex")"
echo "y_len = $str2_len"
echo ""
echo "# Salt (16 bytes, random)"
echo "salt = $(hex_to_u8_array "$salt_hex")"
echo ""
echo "# SHA-256 hash of salt || STRING1 (unpadded)"
echo "hash = $(hex_to_u8_array "$hash_hex")"
