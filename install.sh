#!/bin/sh
set -e

REPO="AbdumajidRashidov/mycop"
VERSION="${MYCOP_VERSION:-latest}"

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
    Linux)  OS_TARGET="unknown-linux-gnu" ;;
    Darwin) OS_TARGET="apple-darwin" ;;
    *)      echo "Error: Unsupported OS: $OS" >&2; exit 1 ;;
esac

case "$ARCH" in
    x86_64)        ARCH_TARGET="x86_64" ;;
    aarch64|arm64) ARCH_TARGET="aarch64" ;;
    *)             echo "Error: Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

TARGET="${ARCH_TARGET}-${OS_TARGET}"

if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/mycop-${TARGET}.tar.gz"
else
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/mycop-${TARGET}.tar.gz"
fi

INSTALL_DIR="${MYCOP_INSTALL_DIR:-/usr/local/bin}"

echo "Downloading mycop for ${TARGET}..."
curl -fsSL "$DOWNLOAD_URL" | tar xz -C /tmp
echo "Installing to ${INSTALL_DIR}..."
if [ -w "${INSTALL_DIR}" ]; then
    install -m 755 /tmp/mycop "${INSTALL_DIR}/mycop"
else
    echo "Elevated permissions required. You may be prompted for your password."
    sudo install -m 755 /tmp/mycop "${INSTALL_DIR}/mycop"
fi
rm -f /tmp/mycop
echo "mycop installed successfully! Run 'mycop --version' to verify."
