#!/bin/bash
set -ex

BUILD_DIR="$(pwd)/deps/"
DEPS_DIR="$BUILD_DIR/output"
# MUSL_PREFIX=""

CC="${MUSL_PREFIX}/bin/x86_64-unknown-linux-musl-clang"
AR="${MUSL_PREFIX}/bin/x86_64-unknown-linux-musl-ar"
RANLIB="${MUSL_PREFIX}/bin/x86_64-unknown-linux-musl-ranlib"

ZLIB_VER="1.3.2"
ZSTD_VER="1.5.7"

# Prepare directories
mkdir -p "$DEPS_DIR"
rm -rf "$BUILD_DIR/src"
mkdir -p "$BUILD_DIR/cache" "$BUILD_DIR/src" "$DEPS_DIR/lib" "$DEPS_DIR/include"

# zlib
curl -L -o "$BUILD_DIR/cache/zlib.tar.gz" "https://zlib.net/zlib-$ZLIB_VER.tar.gz"
tar zxvf "$BUILD_DIR/cache/zlib.tar.gz" -C "$BUILD_DIR/src"
cd "$BUILD_DIR/src/zlib-$ZLIB_VER"
CC="$CC" AR="$AR" RANLIB="$RANLIB" ./configure --static --prefix="$DEPS_DIR"
make -j$(nproc)
make install

# zstd
curl -L -o "$BUILD_DIR/cache/zstd.tar.gz" "https://github.com/facebook/zstd/releases/download/v$ZSTD_VER/zstd-$ZSTD_VER.tar.gz"
tar zxvf "$BUILD_DIR/cache/zstd.tar.gz" -C "$BUILD_DIR/src"
cd "$BUILD_DIR/src/zstd-$ZSTD_VER"
make -j$(nproc) -C lib libzstd.a install-static install-includes \
    CC="$CC" AR="$AR" \
    PREFIX="$DEPS_DIR" \
    LIBDIR="$DEPS_DIR/lib" \
    INCLUDEDIR="$DEPS_DIR/include"

# libelf
git clone https://github.com/arachsys/libelf.git "$BUILD_DIR/src/libelf"
cd "$BUILD_DIR/src/libelf"
make clean
make libelf.a \
    CC="$CC" \
    AR="$AR" \
    CFLAGS="-O2 -Wall -DHAVE_CONFIG_H -Iinclude -Isrc -I$DEPS_DIR/include"
cp libelf.a "$DEPS_DIR/lib/"
cp include/*.h "$DEPS_DIR/include/"

# libbpf
git clone https://github.com/libbpf/libbpf.git "$BUILD_DIR/src/libbpf"
cd "$BUILD_DIR/src/libbpf/src"
make install \
    BUILD_STATIC_ONLY=y \
    NO_PKG_CONFIG=1 \
    CC="$CC" \
    AR="$AR" \
    PREFIX="$DEPS_DIR" \
    LIBDIR="$DEPS_DIR/lib" \
    INCLUDEDIR="$DEPS_DIR/include" \
    EXTRA_CFLAGS="-I$DEPS_DIR/include" \
    LDFLAGS="-L$DEPS_DIR/lib"

echo "Done: $DEPS_DIR"
ls -lh "$DEPS_DIR/lib/"*.a
