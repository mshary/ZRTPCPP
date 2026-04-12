#!/bin/bash
# Build Debian package for libzrtpcpp - Creates runtime and dev packages

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
    print_error "debian directory not found. Please ensure debian/ directory exists with packaging files."
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
    print_error "  sudo apt-get install dpkg-dev debhelper"
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
MISSING_DEPS=()

if ! dpkg -l | grep -q "libssl-dev"; then
    MISSING_DEPS+=("libssl-dev")
fi

if ! dpkg -l | grep -q "libsqlite3-dev"; then
    MISSING_DEPS+=("libsqlite3-dev")
fi

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    print_warning "Missing build dependencies: ${MISSING_DEPS[*]}"
    print_warning "Installing build dependencies..."
    sudo apt-get update
    sudo apt-get install -y "${MISSING_DEPS[@]}"
fi

# Clean previous builds
print_status "Cleaning previous builds..."
rm -rf ../libzrtpcpp_* ../*.deb ../*.changes ../*.buildinfo ../*.dsc 2>/dev/null || true
rm -rf build/ debian/tmp/ 2>/dev/null || true

# Create build directory
mkdir -p build

# Build the package
print_status "Building Debian packages..."
print_status "This will create:"
print_status "  - libzrtpcpp4 (runtime library)"
print_status "  - libzrtpcpp-dev (development files)"
print_status "This may take a few minutes..."

# Set locale to avoid perl warnings
export LC_ALL=C.UTF-8
export LANG=C.UTF-8

# Build the package
if dpkg-buildpackage -b -us -uc 2>&1 | tee build.log; then
    print_status "Packages built successfully!"
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
        if [[ "$pkg" != *"dbgsym"* ]] && [[ "$pkg" != *"udeb"* ]]; then
            print_status "Package info for $(basename "$pkg"):"
            dpkg-deb -I "$pkg" | grep -E "Package:|Version:|Architecture:|Depends:|Description:" | sed 's/^/  /'
            echo ""
            
            # List package contents
            print_status "Contents of $(basename "$pkg"):"
            dpkg-deb -c "$pkg" | head -20
            if [ $(dpkg-deb -c "$pkg" | wc -l) -gt 20 ]; then
                echo "  ... ($(dpkg-deb -c "$pkg" | wc -l) total files)"
            fi
            echo ""
        fi
    done
    
    # Check if lintian is available
    if command -v lintian &> /dev/null; then
        print_status "Running lintian to check for packaging issues..."
        for pkg in ../*.deb; do
            if [[ "$pkg" != *"dbgsym"* ]] && [[ "$pkg" != *"udeb"* ]]; then
                echo "Checking $(basename "$pkg")..."
                LC_ALL=C.UTF-8 LANG=C.UTF-8 lintian "$pkg" 2>&1 | grep -v "perl: warning" | grep -v "^N:" || true
                echo ""
            fi
        done
    else
        print_warning "lintian not installed. Skipping package quality checks."
        print_warning "Install with: sudo apt-get install lintian"
    fi
    
    print_status "Packages are ready in the parent directory:"
    print_status "  $(cd .. && pwd)/"
    
    # Installation instructions
    echo ""
    print_status "To install the packages, run:"
    print_status "  sudo dpkg -i ../libzrtpcpp4_*.deb ../libzrtpcpp-dev_*.deb"
    print_status "  sudo apt-get install -f  # Fix any missing dependencies"
    echo ""
    print_status "Or install them separately:"
    print_status "  Runtime only: sudo dpkg -i ../libzrtpcpp4_*.deb"
    print_status "  Development:  sudo dpkg -i ../libzrtpcpp-dev_*.deb"
    
else
    print_error "No .deb packages were created."
    exit 1
fi

# Clean up
print_status "Cleaning up..."
rm -f build.log 2>/dev/null || true

print_status "Done!"