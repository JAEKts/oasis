#!/bin/bash
# OASIS Launch Script
# 
# Simple wrapper to launch OASIS with proper Python path configuration.

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Set PYTHONPATH to include src directory
export PYTHONPATH="$PROJECT_ROOT/src:$PYTHONPATH"

# Launch OASIS
echo "Starting OASIS..."
python3 -m oasis "$@"
