#!/bin/bash
# Test script for Synapse workspace
# Runs all tests with appropriate feature flags

set -e

echo "Running Synapse tests..."

# Run tests with default features
cargo test --workspace

# Run tests with mock-windows feature for cross-platform testing
cargo test --workspace --features mock-windows

echo "All tests passed!"

