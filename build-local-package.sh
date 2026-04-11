#!/bin/bash
# Build Debian package from local source directory

set -e

echo "=== Building libzrtpcpp package from local source ==="
echo ""

# Create orig tarball if needed
if [ ! -f "../libzrtpcpp_4.7.0.orig.tar.gz" ]; then
    echo "Creating upstream tarball..."
    tar -czf ../libzrtpcpp_4.7.0.orig.tar.gz --exclude=.git --exclude=debian --exclude=build --exclude=*.deb --exclude=*.changes --exclude=*.buildinfo --exclude=*.dsc -C .. $(basename $(pwd))
fi

# Check for build tools
if ! command -v dpkg-buildpackage &> /dev/null; then
    echo "Installing build tools..."
    sudo apt-get update
    sudo apt-get install -y devscripts debhelper build-essential
fi

# Check for dependencies
if ! dpkg -l | grep -q "libccrtp-dev"; then
    echo "Installing libccrtp-dev..."
    sudo apt-get install -y libccrtp-dev
fi

# Clean and build
echo "Building package..."
export LC_ALL=C.UTF-8
export LANG=C.UTF-8

# Use -b to build binary-only package (no source package)
if dpkg-buildpackage -b -us -uc; then
    echo ""
    echo "=== Package built successfully! ==="
    echo ""
    echo "Built packages:"
    ls -la ../*.deb
    
    echo ""
    echo "To install:"
    echo "  sudo dpkg -i ../*.deb"
    echo "  sudo apt-get install -f"
else
    echo ""
    echo "=== Build failed ==="
    exit 1
fi