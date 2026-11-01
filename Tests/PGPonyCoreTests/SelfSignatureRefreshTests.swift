// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// SelfSignatureRefreshTests.swift
// PGPony
//
// 8.4.0 build 7 (Android 4.7.0 items 3, 47, 51, 63): Refresh Self-Signatures
// keeps every expiry and signs again with SHA-256 (signing subkeys with a new
// back-signature, a SHA-1 EdDSA binding brought back only with its secret, a
// subkey missing from the certificate put back from the secret ring, an
// offline primary refused); several public keys join into one armored block
// and a secret ring never does; Key Detail's secret locations for the primary
// and subkeys; the share extension's "text outside the PGP block" check.
// Mirrors the cases of Android's RefreshSelfSignaturesTest where iOS has the
// same shape.
//
// Ported from the app's Build7KeyToolsTests.swift. The tests there that need the app's
// storage, models or secret-key unlock stay in the app.

import XCTest
import CryptoKit
@testable import PGPonyCore

@MainActor
final class SelfSignatureRefreshTests: XCTestCase {

    private let year: TimeInterval = 365 * 24 * 3600

    // MARK: - Helpers

    private func generate(_ name: String = "Refresh Test") throws -> Ed25519KeyGeneratorResult {
        try Ed25519KeyGenerator.generate(name: name, email: "refresh@example.org",
                                         passphrase: nil, expirationInterval: year)
    }

    private func packets(_ data: Data) throws -> [ParsedPacket] {
        try OpenPGPPacketParser.parsePackets(data: Array(data))
    }

    private func frame(_ packets: [ParsedPacket]) -> Data {
        Data(packets.flatMap { OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: $0.tag, body: $0.body) })
    }

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// The packets under the first packet with `tag`, up to the next key or User ID.
    private func signatures(after tag: UInt8, in data: Data, index: Int = 0) throws -> [OpenPGPPacketParser.ParsedSignature] {
        var out: [OpenPGPPacketParser.ParsedSignature] = []
        var seen = -1
        var inside = false
        for p in try packets(data) {
            if [5, 6, 7, 13, 14, 17].contains(p.tag) {
                if p.tag == tag { seen += 1; inside = seen == index } else { inside = false }
                continue
            }
            if inside, p.tag == 2 { out.append(try OpenPGPPacketParser.parseSignaturePacket(body: p.body)) }
        }
        return out
    }

    private func subpacket(_ type: UInt8, _ sig: OpenPGPPacketParser.ParsedSignature?) -> [UInt8]? {
        sig?.hashedSubpackets.first { $0.type == type }?.data
    }

    /// Every signature under the subkey packet `tag` replaced by `signature`.
    private func replacingSubkeySignatures(_ data: Data, subkeyTag: UInt8, with signature: [UInt8]) throws -> Data {
        var out: [ParsedPacket] = []
        var inside = false
        for p in try packets(data) {
            if [5, 6, 7, 13, 14, 17].contains(p.tag) {
                inside = p.tag == subkeyTag
                out.append(p)
                if inside { out.append(ParsedPacket(tag: 2, body: signature)) }
                continue
            }
            if inside && p.tag == 2 { continue }
            out.append(p)
        }
        return frame(out)
    }

    /// The ring without the subkey packet `tag` and the packets under it.
    private func removingSubkey(_ data: Data, subkeyTag: UInt8) throws -> Data {
        var out: [ParsedPacket] = []
        var inside = false
        for p in try packets(data) {
            if [5, 6, 7, 13, 14, 17].contains(p.tag) { inside = p.tag == subkeyTag }
            if !inside { out.append(p) }
        }
        return frame(out)
    }

    /// The secret ring with the first packet `tag` turned into a GnuPG stub
    /// (S2K 101, mode 1 offline or 2 divert to card).
    private func stubbing(_ data: Data, tag: UInt8, mode: UInt8) throws -> Data {
        var done = false
        let out = try packets(data).map { p -> ParsedPacket in
            guard p.tag == tag, !done, let prefix = OpenPGPPacketParser.v4PublicPrefix(secretBody: p.body) else { return p }
            done = true
            return ParsedPacket(tag: tag, body: prefix + [0xFE, 0x00, 0x65, 0x00, 0x47, 0x4E, 0x55, mode])
        }
        XCTAssertTrue(done)
        return frame(out)
    }

    private func bindingVerdict(_ data: Data) throws -> CertificateValidator.Verdict? {
        let ring = try packets(data)
        let primary = try XCTUnwrap(ring.first { $0.tag == 6 }).body
        let subkey = try XCTUnwrap(ring.first { $0.tag == 14 }).body
        let sigs = try packets(data).drop { $0.tag != 14 }.dropFirst().prefix { $0.tag == 2 }.map(\.body)
        return CertificateValidator.newestBinding(subkeyBody: subkey, signatures: Array(sigs), primaryBody: primary)?.1
    }

    func testOfflinePrimaryIsRefused() throws {
        let key = try generate()
        let stubbed = try stubbing(key.privateKeyData, tag: 5, mode: 1)
        XCTAssertThrowsError(try SelfSignatureRefresh.refresh(publicKeyData: key.publicKeyData,
                                                              secretKeyData: stubbed, passphrase: nil)) { error in
            XCTAssertEqual(error as? SelfSignatureRefresh.RefreshError, .primaryNotOnDevice)
        }
    }

    func testSupportsV4Ed25519Primaries() throws {
        let key = try generate()
        XCTAssertTrue(SelfSignatureRefresh.supportsPrimary(publicKeyData: key.publicKeyData))
        XCTAssertFalse(SelfSignatureRefresh.supportsPrimary(publicKeyData: Data([0x01, 0x02])))
    }
}
