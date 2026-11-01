// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// GnuStubAndKeyServerTests.swift
// PGPony
//
// 8.4.0 build 6: a v4 secret key protected with iterated and salted S2K
// over a hash other than SHA-256 (SHA-1 is GnuPG's long-standing default,
// and most RSA keys made elsewhere use it) opens with its passphrase. The
// walker read SHA-256 for every key, so the export check called the right
// passphrase wrong (a tester report on build 5, RSA 4096 keys).
//
// Ported from the app's Build6Tests.swift. The tests there that need the app's
// storage, models or secret-key unlock stay in the app.

import Foundation
import CryptoKit
import XCTest
@testable import PGPonyCore

@MainActor
final class GnuStubAndKeyServerTests: XCTestCase {

    // MARK: - Offline primary (plan 1.3)

    /// A v4 Ed25519 secret body: the public part, then `tail`.
    private func ed25519SecretBody(tail: [UInt8]) -> [UInt8] {
        let oid: [UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]
        var body: [UInt8] = [4, 0x60, 0, 0, 0, 22, UInt8(oid.count)] + oid
        body += [0x01, 0x07, 0x40] + [UInt8](repeating: 0x11, count: 32)
        return body + tail
    }

    func testGnuStubModes() {
        let gnu = Array("GNU".utf8)
        XCTAssertEqual(OpenPGPPacketParser.gnuStub(secretBody: ed25519SecretBody(tail: [255, 0, 101, 2] + gnu + [1])), .offline)
        XCTAssertEqual(OpenPGPPacketParser.gnuStub(secretBody: ed25519SecretBody(tail: [255, 0, 101, 2] + gnu + [2, 16] + [UInt8](repeating: 0xAB, count: 16))), .divertToCard)
        XCTAssertNil(OpenPGPPacketParser.gnuStub(secretBody: ed25519SecretBody(tail: [254, 7, 3, 8] + [UInt8](repeating: 1, count: 9))))
        XCTAssertNil(OpenPGPPacketParser.gnuStub(secretBody: ed25519SecretBody(tail: [0, 0x01, 0x00, 0x05])))
    }

    // MARK: - Key server answers (Android 4.6.0 #18)

    func testKeyServerAnswerMustBeAKey() throws {
        let key = try Ed25519KeyGenerator.generate(name: "Server Check", email: "server@example.org",
                                                   passphrase: nil, expirationInterval: nil)
        let armored = Data(key.armoredPublicKey.utf8)
        XCTAssertNoThrow(try KeyServerService.validatedKey(armored, matching: nil))
        let fp = key.fingerprint.replacingOccurrences(of: " ", with: "").uppercased()
        XCTAssertNoThrow(try KeyServerService.validatedKey(armored, matching: fp))
        XCTAssertNoThrow(try KeyServerService.validatedKey(armored, matching: String(fp.suffix(16))))
        XCTAssertThrowsError(try KeyServerService.validatedKey(armored, matching: String(repeating: "A", count: 40)))
        XCTAssertThrowsError(try KeyServerService.validatedKey(Data("<html><body>Login</body></html>".utf8), matching: nil))
    }
}
