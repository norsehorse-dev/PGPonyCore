// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// HardeningTests
//
// 8.3.0 hardening: certificate binding checks, the AEAD chunk octet bounds,
// one PIN try per card operation, the remembered-PIN card identity, WKD
// lowercasing, MIME nesting, the S2K stream and the network response cap.

import XCTest
import CryptoKit
@testable import PGPonyCore

final class HardeningTests: XCTestCase {

    private func packets(_ data: Data) throws -> [ParsedPacket] {
        try OpenPGPPacketParser.parsePackets(data: Array(data))
    }

    /// A generated key with another generated key's encryption subkey (bound
    /// by that other key's primary) appended.
    private func ringWithForeignSubkey() throws -> (own: Data, combined: Data, foreignSubkey: [UInt8]) {
        let own = try Ed25519KeyGenerator.generate(name: "Own", email: "own@example.org",
                                                   passphrase: nil, expirationInterval: nil)
        let other = try Ed25519KeyGenerator.generate(name: "Other", email: "other@example.org",
                                                     passphrase: nil, expirationInterval: nil)
        let otherPackets = try packets(other.publicKeyData)
        let subIndex = try XCTUnwrap(otherPackets.firstIndex { $0.tag == 14 })
        var combined = Array(own.publicKeyData)
        for p in otherPackets[subIndex...] {
            combined += OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: p.tag, body: p.body)
        }
        return (own.publicKeyData, Data(combined), otherPackets[subIndex].body)
    }

    // MARK: - Certificate bindings

    func testASubkeyBoundByAnotherPrimaryIsNotPartOfTheCertificate() throws {
        let (own, combined, foreign) = try ringWithForeignSubkey()
        let kept = try CertificateValidator.boundComponents(combined, purpose: .encrypt)
        let subkeys = try packets(kept).filter { $0.tag == 14 }.map(\.body)
        XCTAssertEqual(subkeys.count, 1)
        XCTAssertFalse(subkeys.contains(foreign))
        XCTAssertEqual(kept, own)
    }

    func testGeneratedKeysKeepEveryComponent() throws {
        let v4 = try Ed25519KeyGenerator.generate(name: "Keep", email: "keep@example.org", passphrase: nil, expirationInterval: nil)
        XCTAssertEqual(try CertificateValidator.boundComponents(v4.publicKeyData), v4.publicKeyData)
        XCTAssertEqual(try CertificateValidator.boundComponents(v4.publicKeyData, purpose: .encrypt), v4.publicKeyData)
        let v6 = try V6KeyGenerator.generate(name: "Keep Six", email: "keep6@example.org", passphrase: nil, expirationInterval: nil)
        XCTAssertEqual(try CertificateValidator.boundComponents(v6.publicKeyData), v6.publicKeyData)
    }

    func testABindingWithAnUnsupportedHashIsInvalidNotUncheckable() throws {
        let key = try Ed25519KeyGenerator.generate(name: "Hash", email: "hash@example.org", passphrase: nil, expirationInterval: nil)
        let all = try packets(key.publicKeyData)
        let primary = try XCTUnwrap(all.first { $0.tag == 6 })
        let subIndex = try XCTUnwrap(all.firstIndex { $0.tag == 14 })
        let bindingPacket = try XCTUnwrap(all[(subIndex + 1)...].first { $0.tag == 2 })
        let document = CertificateValidator.frameKey(primary.body, signatureVersion: 4)
            + CertificateValidator.frameKey(all[subIndex].body, signatureVersion: 4)
        let genuine = try OpenPGPPacketParser.parseSignaturePacket(body: bindingPacket.body)
        XCTAssertEqual(CertificateValidator.verify(genuine, signerBody: primary.body, document: document), .valid)
        var body = bindingPacket.body
        body[3] = 3
        let altered = try OpenPGPPacketParser.parseSignaturePacket(body: body)
        XCTAssertEqual(CertificateValidator.verify(altered, signerBody: primary.body, document: document), .invalid)
    }

    func testKeyFramingFollowsTheRequestedVersion() {
        let v4Body: [UInt8] = [4, 0, 0, 0, 1, 1] + [UInt8](repeating: 7, count: 10)
        let v5Body: [UInt8] = [5, 0, 0, 0, 1, 8] + [UInt8](repeating: 7, count: 10)
        XCTAssertEqual(Array(CertificateValidator.frameKey(v4Body, signatureVersion: 6).prefix(5)), [0x9B, 0, 0, 0, 16])
        XCTAssertEqual(Array(CertificateValidator.frameKey(v4Body, signatureVersion: 4).prefix(3)), [0x99, 0, 16])
        XCTAssertEqual(Array(CertificateValidator.frameKey(v4Body, signatureVersion: 5).prefix(5)), [0x9A, 0, 0, 0, 16])
        let both = CertificateValidator.bindingDocuments(primaryBody: v4Body, subkeyBody: v5Body, signatureVersion: 4)
        XCTAssertEqual(both.count, 2, "RFC 9580 framing and GnuPG's key-version framing of a v5 subkey")
        XCTAssertEqual(both[1][19], 0x9A)
        XCTAssertEqual(CertificateValidator.bindingDocuments(primaryBody: v4Body, subkeyBody: v4Body, signatureVersion: 4).count, 1)
    }

    // MARK: - AEAD chunk octet

    private func seipdV2Body(chunkByte: UInt8) -> [UInt8] {
        [2, 7, 2, chunkByte] + [UInt8](repeating: 0, count: 32) + [UInt8](repeating: 0, count: 16)
    }

    func testSEIPDv2ChunkOctetAbove16IsRejected() {
        for b: UInt8 in [17, 56, 57, 58, 255] {
            XCTAssertThrowsError(try OpenPGPPacketParser.parseSEIPD(body: seipdV2Body(chunkByte: b)), "octet \(b)")
        }
        for b: UInt8 in [0, 6, 16] {
            XCTAssertEqual(try OpenPGPPacketParser.parseSEIPD(body: seipdV2Body(chunkByte: b)).chunkSizeByte, b)
        }
    }

    func testTag20ChunkOctetAbove56Throws() {
        let body: [UInt8] = [1, 7, 2, 57] + [UInt8](repeating: 0, count: 15) + [UInt8](repeating: 0, count: 16)
        XCTAssertThrowsError(try OpenPGPPacketParser.decryptAEADEncryptedData(body: body, sessionKey: [UInt8](repeating: 0, count: 16)))
    }

    func testAChunkOctetOutOfBoundsHasNoChunkSize() {
        XCTAssertEqual(AEADChunkBounds.chunkSize(octet: 16, librePGP: false), 1 << 22)
        XCTAssertNil(AEADChunkBounds.chunkSize(octet: 17, librePGP: false))
        XCTAssertEqual(AEADChunkBounds.chunkSize(octet: 56, librePGP: true), 1 << 62)
        XCTAssertNil(AEADChunkBounds.chunkSize(octet: 57, librePGP: true))
    }

    // MARK: - Card PIN

    private func wildcardPKESK() -> [UInt8] {
        var body: [UInt8] = [3] + [UInt8](repeating: 0, count: 8) + [18]
        body += [0x01, 0x07, 0x40] + [UInt8](repeating: 0x09, count: 32)
        body += [48] + [UInt8](repeating: 0xAA, count: 48)
        return OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 1, body: body)
    }

    func testAWrongPINIsSentOncePerOperation() async throws {
        var message: [UInt8] = []
        for _ in 0..<3 { message += wildcardPKESK() }
        message += OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 18, body: [1] + [UInt8](repeating: 0x55, count: 64))
        var verifyCalls = 0
        do {
            _ = try await OpenPGPPacketParser.decryptMessageOnCard(
                messageData: Data(message),
                recipientSubkeyID: [1, 2, 3, 4, 5, 6, 7, 8],
                recipientFingerprint: [UInt8](repeating: 0x11, count: 20),
                kdfHashID: 8, kdfCipherID: 9,
                provideSharedSecret: { _ in
                    verifyCalls += 1
                    throw OpenPGPCardError.wrongPIN(retriesRemaining: 3 - verifyCalls)
                })
            XCTFail("decrypt must fail")
        } catch {}
        XCTAssertEqual(verifyCalls, 1)
    }

    func testTheRememberedPINIsBoundToTheCardKeysAndKDF() {
        let keys = [UInt8](repeating: 0xAB, count: 60)
        var others = keys
        others[59] ^= 1
        let base = OpenPGPCardService.pinIdentity(serial: "0006123456", fingerprints: keys, kdfEnabled: true)
        XCTAssertEqual(base, OpenPGPCardService.pinIdentity(serial: "0006123456", fingerprints: keys, kdfEnabled: true))
        XCTAssertNotEqual(base, OpenPGPCardService.pinIdentity(serial: "0006123456", fingerprints: others, kdfEnabled: true))
        XCTAssertNotEqual(base, OpenPGPCardService.pinIdentity(serial: "0006123456", fingerprints: keys, kdfEnabled: false))

        CardPINCache.mode = .fiveMinutes
        defer { CardPINCache.shared.clear(); CardPINCache.mode = .never }
        CardPINCache.shared.store("123456", forSerial: base)
        XCTAssertEqual(CardPINCache.shared.pin(forSerial: base), "123456")
        XCTAssertNil(CardPINCache.shared.pin(forSerial: "0006123456"))
    }

    // MARK: - WKD, MIME, S2K

    func testWKDLowercasesASCIIOnly() {
        XCTAssertEqual(WKDService.asciiLowercased("MiXeD.Ünïcode"), "mixed.Ünïcode")
    }

    func testDeeplyNestedMultipartStopsAtTheCap() {
        var body = "leaf"
        for level in 0..<(MIMEParser.maxNestingDepth + 10) {
            let b = "b\(level)"
            body = "Content-Type: multipart/mixed; boundary=\"\(b)\"\r\n\r\n--\(b)\r\n\(body)\r\n--\(b)--\r\n"
        }
        _ = MIMEParser.parse(Data(body.utf8))
    }

    func testS2KStreamHashesTheSameOctetsAsTheRepetitionLoop() {
        let unit = Array("saltsaltpassphrase".utf8)
        for count in [1, 17, 18, 65_536, 65_537, 200_003] {
            var expected = SHA256()
            var fed = 0
            while fed < count {
                let n = min(unit.count, count - fed)
                expected.update(data: Data(unit[0..<n])); fed += n
            }
            var streamed = SHA256()
            S2KStream.feed(unit, count: count) { bytes, n in
                streamed.update(bufferPointer: UnsafeRawBufferPointer(start: bytes, count: n))
            }
            XCTAssertEqual(Array(expected.finalize()), Array(streamed.finalize()), "count \(count)")
        }
    }

    // MARK: - Response cap

    func testAResponseLargerThanTheCapIsRefused() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [FixedBodyProtocol.self]
        let session = URLSession(configuration: config)
        let url = try XCTUnwrap(URL(string: "https://example.invalid/key"))

        FixedBodyProtocol.body = Data(repeating: 0x41, count: 4096)
        let (small, _) = try await HTTPSessionFactory.boundedData(session, from: url, limit: 8192)
        XCTAssertEqual(small.count, 4096)

        FixedBodyProtocol.body = Data(repeating: 0x41, count: 16_384)
        do {
            _ = try await HTTPSessionFactory.boundedData(session, from: url, limit: 8192)
            XCTFail("a body past the cap was returned")
        } catch let error as URLError {
            XCTAssertEqual(error.code, .dataLengthExceedsMaximum)
        }
    }
}

/// Answers every request with `body` and no Content-Length, so the cap is
/// enforced while reading, not from the header.
final class FixedBodyProtocol: URLProtocol {
    nonisolated(unsafe) static var body = Data()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Self.body)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
