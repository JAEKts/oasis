#!/bin/bash
# OASIS CLI Launch Script
# 
# Simple wrapper to launch OASIS CLI with proper Python path configuration.

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Set PYTHONPATH to include src directory
export PYTHONPATH="$PROJECT_ROOT/src:$PYTHONPATH"

# Launch OASIS CLI
python3 -m oasis.cli.main "$@"
