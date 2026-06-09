#!/bin/sh
# Build libtokenizers.a from source for a target with no upstream prebuilt.
#
#   build-tokenizers.sh <os/arch>
#
# Clones daulet/tokenizers at TOKENIZERS_VERSION and runs the same recipe as
# its release workflow: cargo build -p tokenizers-ffi for the Rust triple,
# then copies the staticlib to native/<os>-<arch>/libtokenizers.a. Skips the
# build when the output already exists (CI caches that file).
set -eu

TOKENIZERS_VERSION="${TOKENIZERS_VERSION:-v1.27.0}"
ROOT="${ROOT:-$(pwd)}"

TARGET="${1:?usage: build-tokenizers.sh <os/arch>}"
OS="${TARGET%/*}"
ARCH="${TARGET#*/}"

rust_triple() {
	case "$1" in
	windows/amd64) echo "x86_64-pc-windows-gnu" ;;
	*) echo "build-tokenizers: no rust triple mapped for $1" >&2; return 1 ;;
	esac
}

triple="$(rust_triple "$TARGET")"
out_dir="$ROOT/native/$OS-$ARCH"
out="$out_dir/libtokenizers.a"

if [ -f "$out" ]; then
	echo "build-tokenizers: $out already present, skipping build" >&2
	exit 0
fi
mkdir -p "$out_dir"

rustup target add "$triple" >&2

src="$(mktemp -d)"
trap 'rm -rf "$src"' EXIT
echo "build-tokenizers: building tokenizers-ffi ${TOKENIZERS_VERSION} for $triple" >&2
git clone --quiet --depth 1 --branch "$TOKENIZERS_VERSION" https://github.com/daulet/tokenizers "$src"
(cd "$src" && cargo build --release -p tokenizers-ffi --target "$triple" >&2)

cp "$src/target/$triple/release/libtokenizers_ffi.a" "$out"
echo "build-tokenizers: wrote $out" >&2
