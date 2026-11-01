// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// ClassicalSubkeyTypesTests.swift
// PGPony
//
// 8.4.0 build 9 (plan 5l): the PGPony PIN at protected actions (routing and
// the attempt outcomes), the ML-DSA-87 + Ed448 signing subkey, RSA subkeys
// under a composite ML-DSA primary (Android 4.6.0 item 21), and the days left
// in Recently Deleted (Android 4.7.0 item 58).
//
// Ported from the app's Build9ExtrasTests.swift. The tests there that need the app's
// storage, models or secret-key unlock stay in the app.

import Foundation
import CryptoKit
import XCTest
@testable import PGPonyCore

@MainActor
final class ClassicalSubkeyTypesTests: XCTestCase {

    // MARK: - Helpers

    private func requireMLDSA() throws {
        guard MLDSAService.isAvailable else {
            throw XCTSkip("ML-DSA needs an iOS 26 runtime (CryptoKit MLDSA65 / MLDSA87); this simulator has none.")
        }
    }

    private func packets(_ data: Data) throws -> [ParsedPacket] {
        try OpenPGPPacketParser.parsePackets(data: Array(data))
    }

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Add Subkey types

    func testAddSubkeyTypesForBuild9() {
        typealias T = ClassicalSubkeyGen.SubkeyType
        XCTAssertEqual(T.v6MLDSA87Sign.v6AddOnlyKind, .mldsa87Sign)
        XCTAssertTrue(T.v6MLDSA87Sign.isV6)
        XCTAssertTrue(T.v6MLDSA87Sign.isSign)
        XCTAssertTrue(T.v6MLDSA87Sign.isPostQuantum)
        XCTAssertEqual(T.v6MLDSA87Sign.keyFlags, 0x02)
        XCTAssertEqual(T.v6MLDSA87Sign.modelAlgorithm, .v6MLDSA87)
        XCTAssertNil(T.v6MLDSA87Sign.v6Kind, "not part of the keygen set")
        XCTAssertNil(T.v6MLDSA65Sign.v6AddOnlyKind)

        XCTAssertEqual(T.v6RSA2048Sign.v6AddOnlyKind, .rsa(bits: 2048, keyFlags: 0x02))
        XCTAssertEqual(T.v6RSA4096Encrypt.v6AddOnlyKind, .rsa(bits: 4096, keyFlags: 0x0C))
        XCTAssertEqual(T.v6RSA2048Auth.v6AddOnlyKind, .rsa(bits: 2048, keyFlags: 0x20))
        for t in T.v6RSATypes {
            XCTAssertTrue(t.isV6, "\(t)")
            XCTAssertTrue(t.isV6RSA, "\(t)")
            XCTAssertFalse(t.isPostQuantum, "\(t)")
            XCTAssertNil(t.v6Kind, "\(t)")
        }
        XCTAssertFalse(T.rsa2048Sign.isV6RSA)
    }
}
