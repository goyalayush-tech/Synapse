#!/bin/bash
# Build script for Synapse workspace
# Handles cross-compilation and feature flag testing

set -e

echo "Building Synapse workspace..."

# Default to release build
BUILD_TYPE="${1:-release}"

if [ "$BUILD_TYPE" = "release" ]; then
    cargo build --workspace --release
else
    cargo build --workspace
fi

echo "Build complete!"

