# liboqs

`Vendor/liboqs.xcframework` is liboqs 0.14.0 built for iOS, ML-KEM-768 and
ML-KEM-1024 only. The PQC sources reach it through the `COQS` module.

## Source

- Repository: https://github.com/open-quantum-safe/liboqs
- Tag: `0.14.0`
- Commit: `94b421ebb82405c843dba4e9aa521a56ee5a333d`

`Scripts/build-liboqs-ios.sh` checks out that commit and refuses any other.

## Build

`Scripts/build-liboqs-ios.sh` configures liboqs with CMake's iOS toolchain:
`OQS_MINIMAL_BUILD="KEM_ml_kem_768;KEM_ml_kem_1024"`, `OQS_USE_OPENSSL=OFF`,
`OQS_DIST_BUILD=OFF`, `OQS_BUILD_ONLY_LIB=ON`, static, Release. It builds a
device slice (arm64) and a simulator slice (arm64 and x86_64 combined with
`lipo`), then assembles the xcframework with `xcodebuild -create-xcframework`.
`ZERO_AR_DATE=1` keeps archive member timestamps out of the output, so two
builds of the same commit with the same Xcode give the same bytes.

## Expected hashes

SHA-256 of the static libraries in this repository:

| File | SHA-256 |
|---|---|
| `ios-arm64/liboqs.a` | `f3aeb25d4d1d2832a15ae2135c1d6fde9aff5227d9eda12e74da792dc13f3fce` |
| `ios-arm64_x86_64-simulator/liboqs-sim-universal.a` | `d852a6386833ea6b78c8bbb3d151a3ad303e626d6745c345ae370e1590ae0370` |

To check them:

```
shasum -a 256 Vendor/liboqs.xcframework/ios-arm64/liboqs.a Vendor/liboqs.xcframework/ios-arm64_x86_64-simulator/liboqs-sim-universal.a
```

To rebuild and compare, run `Scripts/build-liboqs-ios.sh` (Xcode command-line
tools and CMake), which prints the hashes of what it built. Compiler output can
differ between Xcode versions, so compare on the same Xcode release.

## Advisories

liboqs security advisories published after 0.14.0 concern LMS, XMSS and HQC.
None affects ML-KEM, and none of those algorithms is compiled into this build.
