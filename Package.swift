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
        .iOS(.v17)
    ],
    products: [
        .library(name: "PGPonyCore", targets: ["PGPonyCore"])
    ],
    targets: [
        .target(
            name: "PGPonyCore",
            path: "Sources/PGPonyCore"
        ),
        .testTarget(
            name: "PGPonyCoreTests",
            dependencies: ["PGPonyCore"],
            path: "Tests/PGPonyCoreTests"
        )
    ]
)
