#!/bin/bash
# PowerPC Mettle Testing Script

set -e

TARGET=${1:-powerpc-linux-muslsf}
QEMU=qemu-ppc-static

echo "Testing PowerPC mettle for $TARGET..."

# Build PowerPC version
echo "Building $TARGET..."
make clean
make TARGET=$TARGET

# Test basic functionality
echo "Testing basic functionality..."
$QEMU build/$TARGET/bin/mettle --help

# Test debug mode
echo "Testing debug mode..."
$QEMU build/$TARGET/bin/mettle --debug 1 --uri test://localhost --background 0

# Test stack alignment
echo "Testing stack alignment..."
$QEMU build/$TARGET/bin/mettle --debug 2 --uri test://localhost 2>&1 | grep -i "stack\|alignment"

echo "PowerPC tests completed successfully!"
