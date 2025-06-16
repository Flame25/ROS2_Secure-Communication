#!/bin/bash
set -e

NODES=("attacker_node" "publisher_node" "subscriber_node")
BASE_DIR="src/secure_node/keys"

for NODE in "${NODES[@]}"; do
  NODE_DIR="$BASE_DIR/$NODE"
  echo "🔐 Generating RSA key pair for $NODE..."

  # Create directory if it doesn't exist
  mkdir -p "$NODE_DIR"

  # Remove old keys if they exist
  rm -f "$NODE_DIR/private.pem" "$NODE_DIR/public.pem"

  # Generate private key
  openssl genrsa -out "$NODE_DIR/private.pem" 2048

  # Generate public key
  openssl rsa -pubout -in "$NODE_DIR/private.pem" -out "$NODE_DIR/public.pem"

  # Quick validation
  openssl rsa -in "$NODE_DIR/private.pem" -check -noout > /dev/null
  echo "✅ $NODE key pair generated successfully."
done
