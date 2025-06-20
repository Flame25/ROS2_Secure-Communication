#!/bin/bash
set -e

# Define packages and their node directories
declare -A PACKAGES

# Format: ["base_directory"]="node1 node2 ..."
PACKAGES["src/secure_node/keys"]="attacker_node publisher_node subscriber_node"
PACKAGES["src/custom_nodes/keys"]="setpoint_node control_node attacker_node"

for BASE_DIR in "${!PACKAGES[@]}"; do
  NODES=${PACKAGES[$BASE_DIR]}
  for NODE in $NODES; do
    NODE_DIR="$BASE_DIR/$NODE"
    echo "🔐 Generating RSA key pair for $NODE in $BASE_DIR..."

    # Create directory if it doesn't exist
    mkdir -p "$NODE_DIR"

    # Generate RSA private key
    openssl genpkey -algorithm RSA -out "$NODE_DIR/private.pem" -pkeyopt rsa_keygen_bits:2048

    # Extract public key from private key
    openssl rsa -pubout -in "$NODE_DIR/private.pem" -out "$NODE_DIR/public.pem"
  done
done

echo "✅ All RSA keys generated successfully."
