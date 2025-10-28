#!/bin/bash

# Build script for Password Manager

echo "Building Password Manager..."

# Create bin directory if it doesn't exist
mkdir -p bin

# Build the application
go build -o bin/pm .

if [ $? -eq 0 ]; then
    echo "Build successful! Binary created at bin/pm"
    echo ""
    echo "To install globally, run:"
    echo "  sudo cp bin/pm /usr/local/bin/"
    echo ""
    echo "To use the password manager:"
    echo "  ./bin/pm init    # Initialize the password manager"
    echo "  ./bin/pm add     # Add a new password entry"
    echo "  ./bin/pm list    # List all password entries"
    echo "  ./bin/pm get     # Retrieve a password entry"
    echo "  ./bin/pm update  # Update a password entry"
    echo "  ./bin/pm delete  # Delete a password entry"
    echo "  ./bin/pm generate # Generate a secure password"
else
    echo "Build failed!"
    exit 1
fi
