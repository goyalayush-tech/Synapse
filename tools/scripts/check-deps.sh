#!/bin/bash
# Dependency update checker script

set -e

echo "Checking for dependency updates..."

# Check for outdated dependencies
cargo outdated || echo "cargo-outdated not installed, skipping"

# Check for security vulnerabilities
cargo audit || echo "cargo-audit not installed, skipping"

echo "Dependency check complete!"

