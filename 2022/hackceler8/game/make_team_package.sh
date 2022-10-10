#!/bin/bash

set -e -x

cd "$(dirname "$0")"

PACKAGE_PATH="../releases/$(git branch --show-current).zip"

# Clean __pycache__
find . | grep -E "(/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf
# Clean other stuff
rm -rf persistent_state *.hc8 .DS_Store

# Clean an old package by the same name
rm -rf "$PACKAGE_PATH"

# Make the package
zip -r -y "$PACKAGE_PATH" -xi ./*

echo "Package generated at $PACKAGE_PATH"
