// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CardRSALeTests.swift
// PGPony
//
// 8.4.0 build 7: RSA signing on an OpenPGP card asks for the response length
// the key's signature has. A YubiKey NEO (OpenPGP 2.0, over NFC) refused the
// 512-byte extended Le every RSA signature used with 0x6700 (a user report),
// so keys up to 2048 bits now ask with a short Le of 256.
//
// Ported from the app's Build7Tests.swift. The tests there that need the app's
// storage, models or secret-key unlock stay in the app.

import Foundation
import XCTest
@testable import PGPonyCore

/// A card that answers GET DATA for its signing attributes and refuses any
/// extended Le the way an OpenPGP 2.0 applet does.
private final class FakeRSACard: CardTransport {
    let kind: CardTransportKind = .nfc
    var isConnected = true
    let modulusBits: Int
    let acceptsExtendedLe: Bool
    var serveC1Directly = true
    private(set) var signLe: [Int] = []

    init(modulusBits: Int, acceptsExtendedLe: Bool) {
        self.modulusBits = modulusBits
        self.acceptsExtendedLe = acceptsExtendedLe
    }

    private var c1: [UInt8] {
        [0x01, UInt8(modulusBits >> 8), UInt8(modulusBits & 0xFF), 0x00, 0x20, 0x00]
    }

    func connect(alertMessage: String) async throws {}

    func send(_ apdu: APDU) async throws -> APDUResponse {
        if apdu.expectedResponseLength > 256 && !acceptsExtendedLe { return ([], 0x67, 0x00) }
        switch (apdu.instructionCode, apdu.p1Parameter, apdu.p2Parameter) {
        case (0xA4, 0x04, 0x00):
            return ([], 0x90, 0x00)
        case (0xCA, 0x00, 0xC1):
            return serveC1Directly ? (c1, 0x90, 0x00) : ([], 0x6A, 0x88)
        case (0xCA, 0x00, 0x6E):
            let inner: [UInt8] = [0xC1, UInt8(c1.count)] + c1
            let related: [UInt8] = [0x73, UInt8(inner.count)] + inner
            return ([0x6E, UInt8(related.count)] + related, 0x90, 0x00)
        case (0x2A, 0x9E, 0x9A):
            signLe.append(apdu.expectedResponseLength)
            return ([UInt8](repeating: 0xAB, count: modulusBits / 8), 0x90, 0x00)
        default:
            return ([], 0x6A, 0x88)
        }
    }

    func updateStatus(_ message: String) {}
    func disconnect(success: Bool, message: String?) {}
}

@MainActor
final class CardRSALeTests: XCTestCase {

    func testLeFollowsTheKeySize() {
        XCTAssertEqual(OpenPGPCardService.rsaSignatureLe(modulusBits: 1024), 256)
        XCTAssertEqual(OpenPGPCardService.rsaSignatureLe(modulusBits: 2048), 256)
        XCTAssertEqual(OpenPGPCardService.rsaSignatureLe(modulusBits: 3072), 512)
        XCTAssertEqual(OpenPGPCardService.rsaSignatureLe(modulusBits: 4096), 512)
        XCTAssertEqual(OpenPGPCardService.rsaSignatureLe(modulusBits: nil), 512)
    }

    func testA2048KeyOnAnOpenPGP2CardSigns() async throws {
        let card = FakeRSACard(modulusBits: 2048, acceptsExtendedLe: false)
        let service = try await OpenPGPCardService(transport: card).connect()
        let signature = try await service.signRSA(digestInfo: [UInt8](repeating: 1, count: 51))
        XCTAssertEqual(signature.count, 256)
        XCTAssertEqual(card.signLe, [256])
    }

    func testTheSizeComesFromApplicationDataWhenC1IsNotServed() async throws {
        let card = FakeRSACard(modulusBits: 2048, acceptsExtendedLe: false)
        card.serveC1Directly = false
        let service = try await OpenPGPCardService(transport: card).connect()
        let signature = try await service.signRSA(digestInfo: [UInt8](repeating: 1, count: 51))
        XCTAssertEqual(signature.count, 256)
        XCTAssertEqual(card.signLe, [256])
    }

    func testA4096KeyStillAsksForTheExtendedLength() async throws {
        let card = FakeRSACard(modulusBits: 4096, acceptsExtendedLe: true)
        let service = try await OpenPGPCardService(transport: card).connect()
        let signature = try await service.signRSA(digestInfo: [UInt8](repeating: 1, count: 51))
        XCTAssertEqual(signature.count, 512)
        XCTAssertEqual(card.signLe, [512])
    }

    // MARK: - EC keys ObjectivePGP would rewrite

    private func ecKey(algorithm: UInt8, oid: [UInt8]) -> Data {
        let body: [UInt8] = [4, 0x6A, 0xE2, 0x6B, 0x82, algorithm, UInt8(oid.count)] + oid + [0x00, 0x03, 0x04]
        return Data(OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 6, body: body))
    }
}
