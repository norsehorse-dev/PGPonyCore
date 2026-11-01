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
        .iOS("17.6") // string form (not .v17=17.0): matches the PGPony app deployment floor
    ],
    products: [
        .library(name: "PGPonyCore", targets: ["PGPonyCore"]),
        // The pairing protocol v1 (PGPony to PGPony on the local network).
        // Its own module: it shares no code with the OpenPGP core.
        .library(name: "PGPonyPair", targets: ["PGPonyPair"])
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
        .target(
            name: "PGPonyPair",
            path: "Sources/PGPonyPair"
        ),
        .testTarget(
            name: "PGPonyPairTests",
            dependencies: ["PGPonyPair"],
            path: "Tests/PGPonyPairTests",
            // Copies of the shared vector files the Android and desktop
            // implementation replays too; refreshed from there, never edited here.
            resources: [.copy("Vectors")]
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
