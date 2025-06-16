#!/bin/bash

set -e

NODES=("attacker_node" "publisher_node" "subscriber_node")
BASE_DIR="src/secure_node"

for NODE in "${NODES[@]}"; do
  NODE_DIR="$BASE_DIR/$NODE"
  echo "🔐 Generating RSA key pair for $NODE..."

  openssl genpkey -algorithm RSA -out "$NODE_DIR/private_key.pem" -pkeyopt rsa_keygen_bits:2048
  openssl rsa -pubout -in "$NODE_DIR/private_key.pem" -out "$NODE_DIR/public_key.pem"
done

echo "✅ All keys generated successfully."
