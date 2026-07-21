// swift-tools-version: 5.9
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse
import PackageDescription

let package = Package(
    name: "PGPonyCore",
    platforms: [
        // iOS-only for now: the card transport uses CoreNFC. A future macOS target
        // would introduce an `OpenPGPCardTransport` seam (NFC on iOS, PC/SC via
        // CryptoTokenKit on macOS) — see README "Roadmap".
        .iOS("17.6") // string form (not .v17=17.0): matches the app floor; a core file uses a 17.x-only API
    ],
    products: [
        .library(name: "PGPonyCore", targets: ["PGPonyCore"])
    ],
    targets: [
        // Pinned liboqs build (ML-KEM) — the PQC sources import its COQS module.
        // Vendored so the package builds out of the box and auditors see the
        // exact binary the app links.
        .binaryTarget(
            name: "liboqs",
            path: "Vendor/liboqs.xcframework"
        ),
        .target(
            name: "PGPonyCore",
            dependencies: ["liboqs"],
            path: "Sources/PGPonyCore"
        ),
        .testTarget(
            name: "PGPonyCoreTests",
            dependencies: ["PGPonyCore"],
            path: "Tests/PGPonyCoreTests",
            resources: [
                // Lands as <bundle>/mime/*.eml, matching the tests' lookup
                // (url(forResource:withExtension:subdirectory: "mime")).
                .copy("Resources/mime")
            ]
        )
    ]
)
