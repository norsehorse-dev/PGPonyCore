// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CardPINModeTests.swift
// PGPonyCoreTests
//
// 8.4.0 build 9 (plan 5l), the fix-up pass:
//   - a streamed (large-file) LibrePGP v5 Ed448 inline signature verifies,
//     now that the literal header reaches the verifier;
//   - an encryption subkey that is only expired is named as such, on the
//     native routes and the ObjectivePGP route, which never sees an expired
//     subkey (fixtures made by gpg 2.4.4 with a faked 2020 clock, neutral
//     example.invalid User IDs, Resources/build9-fixup);
//   - the remembered hardware key PIN check takes the PIN mode answer;
//   - an RFC 9580 Ed448 primary certifies: add and revoke a User ID, revoke
//     a subkey, certify another key. The same signatures, made by a Python
//     mirror of this code, were accepted by Sequoia (pysequoia 0.1.35), with
//     altered copies rejected as controls.
//
// Ported from the app's Build9FixupTests.swift. The tests there that need the app's
// storage, models or secret-key unlock stay in the app.

import XCTest
import CryptoKit
@testable import PGPonyCore

@MainActor
final class CardPINModeTests: XCTestCase {

    private func binary(_ data: Data) throws -> [UInt8] {
        let text = try XCTUnwrap(String(data: data, encoding: .utf8))
        return Array(try OpenPGPPacketParser.dearmor(text))
    }

    private func temporaryURL(_ name: String) -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("fx9-\(UUID().uuidString)-\(name)")
    }

    /// The gpg fixtures' encryption subkeys were made at 2020-01-01 00:00:00
    /// UTC with a one day lifetime.
    private let expiredAt = Date(timeIntervalSince1970: 1_577_923_200)

    // MARK: - PIN mode at the remembered hardware key PIN (item 4)

    func testRememberedCardPINCheckTakesThePINModeAnswer() async {
        let saved = CardPINCache.pinModeGate
        defer { CardPINCache.pinModeGate = saved }
        CardPINCache.pinModeGate = { _ in false }
        let refused = await CardPINCache.authenticate(reason: "test")
        XCTAssertFalse(refused, "a wrong or cancelled PGPony PIN never releases the remembered PIN")
        CardPINCache.pinModeGate = { _ in true }
        let allowed = await CardPINCache.authenticate(reason: "test")
        XCTAssertTrue(allowed)
    }
}
