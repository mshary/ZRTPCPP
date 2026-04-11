#!/bin/bash
# Build Debian package for libzrtpcpp - Fixed version

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ]; then
    print_error "This script must be run from the libzrtpcpp source directory"
    exit 1
fi

# Check if debian directory exists
if [ ! -d "debian" ]; then
    print_error "debian directory not found. Run the packaging script first."
    exit 1
fi

# Check for essential build tools
print_status "Checking for essential build tools..."

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        print_error "Command '$1' not found"
        return 1
    fi
    return 0
}

# Check dpkg-buildpackage and related tools
if ! check_tool "dpkg-buildpackage"; then
    print_error "dpkg-buildpackage not found. Install with:"
    print_error "  sudo apt-get install dpkg-dev"
    exit 1
fi

if ! check_tool "dh"; then
    print_error "dh (debhelper) not found. Install with:"
    print_error "  sudo apt-get install debhelper"
    exit 1
fi

if ! check_tool "cmake"; then
    print_error "cmake not found. Install with:"
    print_error "  sudo apt-get install cmake"
    exit 1
fi

if ! check_tool "pkg-config"; then
    print_error "pkg-config not found. Install with:"
    print_error "  sudo apt-get install pkg-config"
    exit 1
fi

# Check for library dependencies
print_status "Checking library dependencies..."
if ! dpkg -l | grep -q "libccrtp-dev"; then
    print_warning "libccrtp-dev is not installed."
    print_warning "Installing build dependencies..."
    sudo apt-get update
    sudo apt-get install -y libccrtp-dev
fi

# Clean previous builds
print_status "Cleaning previous builds..."
rm -rf ../libzrtpcpp_* ../*.deb ../*.changes ../*.buildinfo ../*.dsc 2>/dev/null || true
rm -rf build/ 2>/dev/null || true

# Create build directory
mkdir -p build

# Build the package
print_status "Building Debian package..."
print_status "This may take a few minutes..."

# Set locale to avoid perl warnings
export LC_ALL=C.UTF-8
export LANG=C.UTF-8

# Build the package
if dpkg-buildpackage -b -us -uc 2>&1 | tee build.log; then
    print_status "Package built successfully!"
else
    print_error "Package build failed. Check build.log for details."
    exit 1
fi

# Check for built packages
print_status "Checking built packages..."
BUILT_PACKAGES=$(ls ../*.deb 2>/dev/null | wc -l)
if [ "$BUILT_PACKAGES" -gt 0 ]; then
    print_status "Found $BUILT_PACKAGES .deb package(s):"
    ls -la ../*.deb
    echo ""
    
    # Show package info
    for pkg in ../*.deb; do
        if [[ "$pkg" != *"dbgsym"* ]]; then
            print_status "Package info for $(basename "$pkg"):"
            dpkg-deb -I "$pkg" | grep -E "Package:|Version:|Architecture:|Depends:" | sed 's/^/  /'
            echo ""
        fi
    done
    
    # Check if lintian is available
    if command -v lintian &> /dev/null; then
        print_status "Running lintian to check for packaging issues..."
        for pkg in ../*.deb; do
            if [[ "$pkg" != *"dbgsym"* ]]; then
                echo "Checking $(basename "$pkg")..."
                LC_ALL=C.UTF-8 LANG=C.UTF-8 lintian "$pkg" 2>&1 | grep -v "perl: warning" | grep -v "N:" || true
            fi
        done
    else
        print_warning "lintian not installed. Skipping package checks."
        print_warning "Install with: sudo apt-get install lintian"
    fi
    
    print_status "Packages are ready in the parent directory:"
    print_status "  $(cd .. && pwd)/"
    
    # Installation instructions
    echo ""
    print_status "To install the packages, run:"
    print_status "  sudo dpkg -i ../*.deb"
    print_status "  sudo apt-get install -f  # Fix any missing dependencies"
    
else
    print_error "No .deb packages were created."
    exit 1
fi

# Clean up
print_status "Cleaning up..."
rm -f build.log 2>/dev/null || true

print_status "Done!"