#!/bin/sh
# Installs ogl (og-local) on macOS and Linux.
# Usage: curl -fsSL https://raw.githubusercontent.com/outgate-ai/og-local/main/scripts/install.sh | sh
#
# Env overrides:
#   OGL_VERSION       tag to install (default: latest)
#   OGL_DOWNLOAD_URL  base URL for archives (default: GitHub releases)
#   OGL_CACHE_DIR     cache dir for the bundled runtime lib (matches the binary)
#   OGL_INSTALL_DIR   where to install the binary (default: /usr/local/bin)

main() {

set -eu

BINARY_NAME="ogl"
REPO="outgate-ai/og-local"
BASE_URL="${OGL_DOWNLOAD_URL:-https://github.com/${REPO}/releases}"

red="$( (/usr/bin/tput bold 2>/dev/null || :; /usr/bin/tput setaf 1 2>/dev/null || :) 2>&-)"
green="$( (/usr/bin/tput bold 2>/dev/null || :; /usr/bin/tput setaf 2 2>/dev/null || :) 2>&-)"
yellow="$( (/usr/bin/tput bold 2>/dev/null || :; /usr/bin/tput setaf 3 2>/dev/null || :) 2>&-)"
plain="$( (/usr/bin/tput sgr0 2>/dev/null || :) 2>&-)"

status() { echo ">>> $*" >&2; }
error()  { echo "${red}ERROR:${plain} $*" >&2; exit 1; }

TEMP_DIR=$(mktemp -d)
cleanup() { rm -rf "$TEMP_DIR"; }
trap cleanup EXIT

# -- Platform detection --

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin)  OS="darwin" ;;
    Linux)   OS="linux" ;;
    *)       error "Unsupported OS: $OS. Only macOS and Linux are supported (Windows: download from ${BASE_URL}/latest)." ;;
esac

case "$ARCH" in
    x86_64)        ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)             error "Unsupported architecture: $ARCH" ;;
esac

# Targets with a bundled ONNX Runtime (the detector works). Others install the
# pure-Go passthrough build.
ONNX_CAPABLE=no
case "${OS}-${ARCH}" in
    linux-amd64|linux-arm64|darwin-arm64) ONNX_CAPABLE=yes ;;
esac

# -- Resolve version (the archive filename embeds it, without a leading v) --

VERSION="${OGL_VERSION:-latest}"
if [ "$VERSION" = latest ]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | cut -d'"' -f4)"
    [ -n "$VERSION" ] || error "Could not resolve the latest release tag."
fi
NUM="${VERSION#v}"

# -- Download + extract --

ARCHIVE="${BINARY_NAME}_${NUM}_${OS}_${ARCH}.tar.gz"
if [ "$VERSION" = "${OGL_VERSION:-}" ] && [ "${OGL_DOWNLOAD_URL:-}" != "" ]; then
    URL="${BASE_URL}/${ARCHIVE}"            # local/snapshot testing: flat dir
else
    URL="${BASE_URL}/download/${VERSION}/${ARCHIVE}"
fi

status "Downloading ${BINARY_NAME} ${VERSION} for ${OS}/${ARCH}..."
if ! curl --fail --show-error --location --progress-bar -o "${TEMP_DIR}/a.tar.gz" "$URL"; then
    error "Download failed for ${OS}/${ARCH} (no published archive?). See ${BASE_URL}/latest."
fi
tar -xzf "${TEMP_DIR}/a.tar.gz" -C "$TEMP_DIR"

# -- Install the binary --

INSTALL_DIR="${OGL_INSTALL_DIR:-/usr/local/bin}"
mkdir -p "$INSTALL_DIR" 2>/dev/null || true
if [ -w "$INSTALL_DIR" ]; then
    mv "${TEMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
else
    status "Installing to ${INSTALL_DIR} (may require password)..."
    sudo mv "${TEMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
fi
chmod +x "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null || true

# -- Place the bundled ONNX Runtime where the binary looks for it --
# Mirror CacheRoot(): OGL_CACHE_DIR > XDG_CACHE_HOME/og-local > ~/.cache/og-local.

if [ "$ONNX_CAPABLE" = yes ] && [ -d "${TEMP_DIR}/lib" ]; then
    if [ -n "${OGL_CACHE_DIR:-}" ]; then
        CACHE="$OGL_CACHE_DIR"
    elif [ -n "${XDG_CACHE_HOME:-}" ]; then
        CACHE="${XDG_CACHE_HOME}/og-local"
    else
        CACHE="${HOME}/.cache/og-local"
    fi
    case "$OS" in darwin) LIB="libonnxruntime.dylib" ;; *) LIB="libonnxruntime.so" ;; esac
    RT_DIR="${CACHE}/runtime/${OS}-${ARCH}"
    mkdir -p "$RT_DIR"
    cp "${TEMP_DIR}/lib/${LIB}" "${RT_DIR}/${LIB}"
    status "Placed ONNX Runtime at ${RT_DIR}/${LIB}"
fi

# -- Verify + next steps --

if command -v ogl >/dev/null 2>&1; then
    echo ""
    echo "${green}ogl installed!${plain} ($(ogl version 2>/dev/null || echo "$VERSION"))"
    echo ""
    if [ "$ONNX_CAPABLE" = yes ]; then
        echo "Next:"
        echo "  ogl model pull          Download the detection model (~800MB, one-time)"
        echo "  ogl claude \"...\"        Run Claude through the local privacy proxy"
        echo "  ogl codex \"...\"         Run Codex through the local privacy proxy"
    else
        echo "${yellow}Note:${plain} ${OS}/${ARCH} ships the passthrough build — it forwards"
        echo "requests but does NOT redact. Redaction is available on linux/amd64,"
        echo "linux/arm64, and darwin/arm64."
    fi
    echo ""
else
    error "Installed but 'ogl' is not in PATH. Add ${INSTALL_DIR} to your PATH."
fi

}

# Wrap in main() so a partial download doesn't execute half the script.
main
