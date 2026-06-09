#!/bin/sh
# Stage native libraries for an onnx-capable release build.
#
# For each target passed as an argument (os/arch, e.g. linux/amd64), this:
#   1. downloads libtokenizers.a (static, linked at build time) into
#      native/<os>-<arch>/  -> point CGO_LDFLAGS at it
#   2. downloads the ONNX Runtime shared library (dynamic, dlopen'd at runtime)
#      into staging/<os>-<arch>/lib/<libName>  -> goreleaser bundles it
#
# The two version pins below must match go.mod (daulet/tokenizers,
# yalue/onnxruntime_go) and the CI detector-build job.
set -eu

TOKENIZERS_VERSION="${TOKENIZERS_VERSION:-v1.27.0}"
ORT_VERSION="${ORT_VERSION:-1.26.0}"
ROOT="${ROOT:-$(pwd)}"
NATIVE_ROOT="$ROOT/native"
STAGING_ROOT="$ROOT/staging"

tokenizers_asset() {
	case "$1" in
	linux/amd64) echo "libtokenizers.linux-amd64.tar.gz" ;;
	linux/arm64) echo "libtokenizers.linux-arm64.tar.gz" ;;
	darwin/arm64) echo "libtokenizers.darwin-arm64.tar.gz" ;;
	*) echo "stage-native: no tokenizers build for $1" >&2; return 1 ;;
	esac
}

# Prints: onnxruntime asset, the dir it extracts to, and the bundled lib name.
ort_asset() {
	case "$1" in
	linux/amd64) echo "onnxruntime-linux-x64-${ORT_VERSION}.tgz onnxruntime-linux-x64-${ORT_VERSION} libonnxruntime.so" ;;
	linux/arm64) echo "onnxruntime-linux-aarch64-${ORT_VERSION}.tgz onnxruntime-linux-aarch64-${ORT_VERSION} libonnxruntime.so" ;;
	darwin/arm64) echo "onnxruntime-osx-arm64-${ORT_VERSION}.tgz onnxruntime-osx-arm64-${ORT_VERSION} libonnxruntime.dylib" ;;
	*) echo "stage-native: no onnxruntime build for $1" >&2; return 1 ;;
	esac
}

stage_target() {
	target="$1"
	os="${target%/*}"
	arch="${target#*/}"
	native_dir="$NATIVE_ROOT/$os-$arch"
	lib_dir="$STAGING_ROOT/$os-$arch/lib"
	mkdir -p "$native_dir" "$lib_dir"

	tok="$(tokenizers_asset "$target")"
	echo "stage-native: $target tokenizers -> $native_dir/libtokenizers.a" >&2
	curl -fsSL "https://github.com/daulet/tokenizers/releases/download/${TOKENIZERS_VERSION}/${tok}" | tar xz -C "$native_dir"

	set -- $(ort_asset "$target")
	ort_file="$1"; ort_dir="$2"; lib_name="$3"
	tmp="$(mktemp -d)"
	echo "stage-native: $target onnxruntime -> $lib_dir/$lib_name" >&2
	curl -fsSL "https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/${ort_file}" | tar xz -C "$tmp"
	# The linux tarball ships libonnxruntime.so.<ver>; the resolver and dlopen
	# want the bare name. Copy whichever exists to the bare name.
	if [ -f "$tmp/$ort_dir/lib/$lib_name" ]; then
		cp "$tmp/$ort_dir/lib/$lib_name" "$lib_dir/$lib_name"
	else
		cp "$tmp/$ort_dir/lib/${lib_name}.${ORT_VERSION}" "$lib_dir/$lib_name"
	fi
	rm -rf "$tmp"
}

if [ "$#" -eq 0 ]; then
	echo "usage: stage-native.sh <os/arch> [<os/arch> ...]" >&2
	exit 2
fi

for t in "$@"; do
	stage_target "$t"
done
