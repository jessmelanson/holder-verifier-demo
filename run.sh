#!/bin/bash

# Start the verifier server in the background
echo "Starting verifier..."
cargo run --bin verifier &
VERIFIER_PID=$!

# Wait briefly to let the server start up
sleep 1

# Run the holder client
echo "Running holder..."
cargo run --bin holder

# Optional: Stop the verifier server
kill $VERIFIER_PID 2>/dev/null

echo "Done."
