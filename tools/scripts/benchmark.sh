#!/bin/bash
# Benchmark runner script

set -e

echo "Running benchmarks..."

# Run benchmarks if they exist
if cargo bench --help > /dev/null 2>&1; then
    cargo bench
else
    echo "No benchmarks defined"
fi

echo "Benchmarks complete!"

