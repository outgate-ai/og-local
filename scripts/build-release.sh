#!/bin/sh
# Build and package one release target.
#
#   build-release.sh <os/arch>
#
# onnx-capable targets (linux/amd64, linux/arm64, darwin/arm64, windows/amd64)
# build with cgo + -tags onnx, linking the staged libtokenizers.a, and bundle
# the ONNX Runtime shared library under lib/ in the archive. Other targets
# build the pure-Go stub. Run scripts/stage-native.sh first for onnx targets.
#
# Output: dist/ogl_<version>_<os>_<arch>.{tar.gz,zip}  (version without leading v).
set -eu

TARGET="${1:?usage: build-release.sh <os/arch>}"
OS="${TARGET%/*}"
ARCH="${TARGET#*/}"
ROOT="${ROOT:-$(pwd)}"

VERSION="${OGL_RELEASE_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="${OGL_RELEASE_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"

stage="$ROOT/dist/stage/$OS-$ARCH"
rm -rf "$stage"
mkdir -p "$stage" "$ROOT/dist"

bin="ogl"
[ "$OS" = windows ] && bin="ogl.exe"

onnx_capable() {
	case "$1" in linux/amd64 | linux/arm64 | darwin/arm64 | windows/amd64) return 0 ;; *) return 1 ;; esac
}

echo "build-release: $TARGET version=$VERSION" >&2
if onnx_capable "$TARGET"; then
	case "$TARGET" in
	linux/arm64) export CC=aarch64-linux-gnu-gcc ;;
	windows/amd64)
		export CC=x86_64-w64-mingw32-gcc
		# Static MinGW runtime: without it the .exe needs libstdc++-6.dll,
		# libgcc_s_seh-1.dll, and libwinpthread-1.dll at runtime.
		LDFLAGS="$LDFLAGS -extldflags -static"
		;;
	esac
	CGO_ENABLED=1 \
		CGO_LDFLAGS="-L$ROOT/native/$OS-$ARCH" \
		GOOS="$OS" GOARCH="$ARCH" \
		go build -tags onnx -ldflags "$LDFLAGS" -o "$stage/$bin" ./cmd/ogl
	mkdir -p "$stage/lib"
	case "$OS" in
	darwin) lib=libonnxruntime.dylib ;;
	windows) lib=onnxruntime.dll ;;
	*) lib=libonnxruntime.so ;;
	esac
	cp "$ROOT/staging/$OS-$ARCH/lib/$lib" "$stage/lib/$lib"
else
	CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" \
		go build -ldflags "$LDFLAGS" -o "$stage/$bin" ./cmd/ogl
fi

cp "$ROOT/LICENSE" "$ROOT/README.md" "$stage/"

name="ogl_${VERSION#v}_${OS}_${ARCH}"
if [ "$OS" = windows ]; then
	(cd "$stage" && zip -q -r "$ROOT/dist/$name.zip" .)
	echo "dist/$name.zip"
else
	tar -czf "$ROOT/dist/$name.tar.gz" -C "$stage" .
	echo "dist/$name.tar.gz"
fi
