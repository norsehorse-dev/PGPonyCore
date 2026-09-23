#!/usr/bin/env bash
#
# build-liboqs-ios.sh — cross-compile liboqs for iOS into liboqs.xcframework
#
# PGPony 8.0.0 Phase F (PQC / RFC 9980). This is F1a: get liboqs building and
# linking as an xcframework, ML-KEM-768 only. No crypto wrapper yet — this
# script just produces the binary + headers so Xcode can link them and a
# one-line smoke test (OQS_version) can run on device and simulator.
#
# Run this on your Mac (needs Xcode command-line tools + CMake). It has no
# network needs beyond the initial `git clone` of liboqs.
#
# Usage:
#   ./build-liboqs-ios.sh                 # clones liboqs at a pinned tag, builds
#   LIBOQS_SRC=/path/to/liboqs ./build-liboqs-ios.sh   # use an existing checkout
#
# Output:
#   ./build/liboqs.xcframework            # compare with Vendor/liboqs.xcframework
#                                          (expected hashes in Vendor/LIBOQS.md)
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
# Pin to a released tag so the wire format / API is reproducible. 0.14.0 is the
# first release carrying the final FIPS-203 ML-KEM (not the draft "Kyber").
# Bump deliberately, never float on main.
LIBOQS_TAG="${LIBOQS_TAG:-0.14.0}"
LIBOQS_REPO="https://github.com/open-quantum-safe/liboqs.git"
# 8.3.0: the tag is also pinned by commit, so a moved tag cannot change what
# is built. 94b421e... is liboqs 0.14.0.
LIBOQS_COMMIT="${LIBOQS_COMMIT:-94b421ebb82405c843dba4e9aa521a56ee5a333d}"

# 8.3.0: deterministic archives. ar records member timestamps unless this is
# set, which makes two builds of the same source differ byte for byte.
export ZERO_AR_DATE=1

# v8.2.0 §1: ML-KEM-768 (RFC 9980 alg 35, mandatory-to-implement) plus
# ML-KEM-1024 (alg 36, paired with X448; the curve half is hand-rolled in
# Sources/PGPonyCore/Primitives/X448.swift, liboqs only supplies the KEM). Rebuilding with this
# list and swapping the xcframework in Xcode is what turns the 1024
# primitive on; MLKEMService asserts algorithm availability and sizes at
# call time, so running against an old 768-only framework fails loudly,
# not silently.
OQS_ALGS="KEM_ml_kem_768;KEM_ml_kem_1024"

# iOS deployment target — match the app's (PGPony ships iOS 16+).
IOS_MIN="${IOS_MIN:-16.0}"

ROOT="$(cd "$(dirname "$0")" && pwd)"

# v8.2.0: intermediates moved OUT of the repo. The July build left its whole
# compile tree inside Scripts/build with ownership the desktop bridge set,
# which later made the tree undeletable without sudo and violated the house
# rule that scratch lives outside the working directory. Only the finished
# xcframework lands in Scripts/build now (Xcode links it from there);
# the clone, the per-slice CMake trees, staged headers and the fat sim lib
# all live under WORK and can be nuked at any time without touching the repo.
BUILD="${ROOT}/build"
WORK="${LIBOQS_WORK:-${HOME}/.pgpony-build/liboqs}"
SRC="${LIBOQS_SRC:-${WORK}/liboqs-src}"

rm -rf "${WORK}/device" "${WORK}/sim" "${WORK}/sim_arm" "${WORK}/sim_x86" \
       "${WORK}/headers" "${WORK}/liboqs-sim-universal.a" "${BUILD}/liboqs.xcframework"
mkdir -p "${BUILD}" "${WORK}"

# ---------------------------------------------------------------------------
# 0. Source
# ---------------------------------------------------------------------------
if [[ -n "${LIBOQS_SRC:-}" ]]; then
  echo "==> Using existing liboqs checkout: ${SRC}"
else
  if [[ ! -d "${SRC}/.git" ]]; then
    echo "==> Cloning liboqs ${LIBOQS_TAG}"
    git clone --depth 1 --branch "${LIBOQS_TAG}" "${LIBOQS_REPO}" "${SRC}"
  else
    echo "==> Reusing clone at ${SRC} (delete that directory to re-clone)"
  fi
fi
HEAD_COMMIT="$(git -C "${SRC}" rev-parse HEAD)"
if [[ "${HEAD_COMMIT}" != "${LIBOQS_COMMIT}" ]]; then
  echo "!! liboqs checkout is ${HEAD_COMMIT}, expected ${LIBOQS_COMMIT} (${LIBOQS_TAG})" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Shared CMake flags
#
#   CMAKE_SYSTEM_NAME=iOS           -> CMake's built-in Apple cross toolchain
#                                      (sets the right sysroot, ar, ranlib, etc.)
#   OQS_BUILD_ONLY_LIB=ON           -> skip tests/docs/prettyprint targets
#   OQS_MINIMAL_BUILD=<algs>        -> compile ONLY the algorithm(s) we ship
#   OQS_USE_OPENSSL=OFF             -> no OpenSSL dependency; liboqs uses its own
#                                      SHA3/SHAKE (which is all ML-KEM needs)
#   OQS_DIST_BUILD=OFF              -> single fixed target, no runtime CPU
#                                      dispatch. Cross-compiling can't run the
#                                      host's CPU probes against the target, so
#                                      a fixed baseline is the reliable choice.
#   BUILD_SHARED_LIBS=OFF           -> static liboqs.a (simplest to embed)
#   CMAKE_C_FLAGS "-fembed-bitcode" -> omitted; bitcode is deprecated/removed in
#                                      current Xcode. Add back only if you must.
# ---------------------------------------------------------------------------
common_flags=(
  -G "Unix Makefiles"
  -DCMAKE_SYSTEM_NAME=iOS
  -DCMAKE_OSX_DEPLOYMENT_TARGET="${IOS_MIN}"
  -DOQS_BUILD_ONLY_LIB=ON
  -DOQS_MINIMAL_BUILD="${OQS_ALGS}"
  -DOQS_USE_OPENSSL=OFF
  -DOQS_DIST_BUILD=OFF
  -DBUILD_SHARED_LIBS=OFF
  -DCMAKE_BUILD_TYPE=Release
)

build_slice () {   # $1 = label  $2 = sysroot  $3 = arch  $4 = processor
  local label="$1" sysroot="$2" arch="$3" proc="$4"
  local out="${WORK}/${label}"
  echo "==> Configuring ${label}  (sysroot=${sysroot}, arch=${arch}, processor=${proc})"
  rm -rf "${out}"
  cmake -S "${SRC}" -B "${out}" \
    "${common_flags[@]}" \
    -DCMAKE_OSX_SYSROOT="${sysroot}" \
    -DCMAKE_OSX_ARCHITECTURES="${arch}" \
    -DCMAKE_SYSTEM_PROCESSOR="${proc}"
  echo "==> Building ${label}"
  cmake --build "${out}" --config Release -j "$(sysctl -n hw.ncpu)"
}

# Setting CMAKE_SYSTEM_NAME=iOS puts CMake in cross-compile mode but leaves
# CMAKE_SYSTEM_PROCESSOR empty, and liboqs FATAL-errors when it can't identify
# the arch. So we pass the processor explicitly (liboqs matches "arm64" ->
# ARCH_ARM64v8, "x86_64" -> ARCH_X86_64).
#
# Each CMake build is a SINGLE arch so the processor is unambiguous. The
# SIMULATOR slice must be UNIVERSAL (arm64 + x86_64), otherwise a build for a
# destination that requires x86_64 (e.g. `generic/platform=iOS Simulator`, or
# Archive) fails to link with "missing architecture x86_64". So we build each
# sim arch separately and `lipo -create` them into one fat static lib.
#   - device        : iphoneos,        arm64
#   - simulator (2) : iphonesimulator, arm64  AND  x86_64  ->  lipo -> fat
# ---------------------------------------------------------------------------
build_slice device   iphoneos        arm64  arm64
build_slice sim_arm  iphonesimulator arm64  arm64
build_slice sim_x86  iphonesimulator x86_64 x86_64

# Resolve the static lib for a slice. Most liboqs versions emit it at
# <build>/lib/liboqs.a, but some put it at the build root — find it either way.
resolve_lib () {   # $1 = slice dir -> echoes the .a path
  local dir="$1" hit
  hit="$(find "${dir}" -name 'liboqs.a' -type f 2>/dev/null | head -n1)"
  [[ -n "${hit}" ]] || { echo "!! liboqs.a not found under ${dir}" >&2; exit 1; }
  echo "${hit}"
}
DEVICE_LIB="$(resolve_lib "${WORK}/device")"
SIM_ARM_LIB="$(resolve_lib "${WORK}/sim_arm")"
SIM_X86_LIB="$(resolve_lib "${WORK}/sim_x86")"

# Fuse the two simulator arches into one universal static lib.
SIM_LIB="${WORK}/liboqs-sim-universal.a"
echo "==> lipo: fusing simulator arm64 + x86_64 -> ${SIM_LIB}"
lipo -create "${SIM_ARM_LIB}" "${SIM_X86_LIB}" -output "${SIM_LIB}"
lipo -info "${SIM_LIB}"
echo "==> device lib: ${DEVICE_LIB}"
echo "==> sim lib:    ${SIM_LIB} (universal)"

[[ -e "${WORK}/device/include/oqs/oqs.h" ]] || {
  echo "!! generated header missing: ${WORK}/device/include/oqs/oqs.h"; exit 1; }

# ---------------------------------------------------------------------------
# Stage headers + a Clang module map so Swift can `import COQS` directly,
# no bridging header needed (works for the app AND the extension target).
# ---------------------------------------------------------------------------
HEADERS="${WORK}/headers"
rm -rf "${HEADERS}"
mkdir -p "${HEADERS}"
cp -R "${WORK}/device/include/oqs" "${HEADERS}/oqs"
cat > "${HEADERS}/module.modulemap" <<'MODMAP'
module COQS {
    header "oqs/oqs.h"
    header "oqs/sha3.h"
    export *
}
MODMAP

# ---------------------------------------------------------------------------
# 3. Assemble the xcframework
# ---------------------------------------------------------------------------
echo "==> Creating liboqs.xcframework"
xcodebuild -create-xcframework \
  -library "${DEVICE_LIB}" -headers "${HEADERS}" \
  -library "${SIM_LIB}"    -headers "${HEADERS}" \
  -output "${BUILD}/liboqs.xcframework"

echo
echo "==> Done."
echo "    ${BUILD}/liboqs.xcframework"
echo
echo "==> SHA-256 of the static libraries (compare with Vendor/LIBOQS.md in PGPonyCore):"
shasum -a 256 "${BUILD}/liboqs.xcframework/ios-arm64/liboqs.a" \
              "${BUILD}/liboqs.xcframework/ios-arm64_x86_64-simulator/liboqs-sim-universal.a"
echo
echo "    Sanity check the built symbols:"
echo "      nm -gU \"${DEVICE_LIB}\" | grep -E 'OQS_version|OQS_KEM_new|ml_kem_768|ml_kem_1024'"
