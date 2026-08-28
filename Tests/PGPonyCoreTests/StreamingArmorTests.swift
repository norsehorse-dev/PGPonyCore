// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// StreamingArmorTests.swift
// PGPony
//
// v8.2.0 §3f: the streaming armor writes an OpenPGP message from disk as ASCII
// armor without holding it whole, and the streaming RFC 3156 envelope carries
// that armored message in part 2. These lock the contract that matters for
// interop: the armored output de-armors back to the exact original bytes and
// carries a correct CRC-24, across sizes that exercise the 57-byte base64 line
// unit and the 171000-byte read chunk, so a large bundle exported this way is
// a valid PGP MESSAGE / PGP/MIME entity that gpg and Thunderbird read.

import XCTest
@testable import PGPonyCore

final class StreamingArmorTests: XCTestCase {

    private func tempURL() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("armor-\(UUID().uuidString)")
    }

    private func deterministic(_ n: Int, seed: Int) -> Data {
        Data((0..<n).map { UInt8((($0 &* 37) &+ ($0 / 5) &+ seed) & 0xFF) })
    }

    /// Pull the base64 body and the trailing =CRC out of an armored PGP MESSAGE
    /// block, tolerant of LF or CRLF line endings.
    private func deArmor(_ text: String) -> (body: Data, crc: String)? {
        guard let begin = text.range(of: "-----BEGIN PGP MESSAGE-----"),
              let end = text.range(of: "-----END PGP MESSAGE-----"),
              begin.upperBound <= end.lowerBound else { return nil }
        let inner = String(text[begin.upperBound..<end.lowerBound])
        // Normalize line endings BEFORE splitting: Swift treats "\r\n" as one
        // Character (an extended grapheme cluster), so a whereSeparator closure
        // testing $0 == "\r" || $0 == "\n" never matches a CRLF break. Collapse
        // to LF first, then split, so both the .asc (LF) and envelope (CRLF)
        // forms parse the same.
        let lines = inner
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .split(separator: "\n", omittingEmptySubsequences: true)
            .map(String.init)
        guard let crcLine = lines.last, crcLine.hasPrefix("=") else { return nil }
        let b64 = lines.dropLast().joined()
        guard let data = Data(base64Encoded: b64) else { return nil }
        return (data, String(crcLine.dropFirst()))
    }

    private func expectedCRC(_ data: Data) -> String {
        var crc = OpenPGPPacketBuilder.StreamingCRC24()
        crc.update(data)
        return Data(crc.finalize()).base64EncodedString()
    }

    func testArmoredFileRoundTripsAcrossSizes() throws {
        let sizes = [0, 1, 3, 4, 56, 57, 58, 114, 200, 171000, 171001, 171057]
        for (i, n) in sizes.enumerated() {
            let original = deterministic(n, seed: i * 11)
            let bin = tempURL(); try original.write(to: bin)
            let asc = tempURL()
            try OpenPGPPacketBuilder.streamArmoredFile(binaryAt: bin, to: asc)
            let text = try String(contentsOf: asc, encoding: .utf8)
            guard let (body, crc) = deArmor(text) else {
                return XCTFail("armor did not parse for n=\(n)")
            }
            XCTAssertEqual(body, original, "de-armored body must equal the original (n=\(n))")
            XCTAssertEqual(crc, expectedCRC(original), "armor CRC-24 must be correct (n=\(n))")
        }
    }

    func testEnvelopeCarriesTheArmoredMessage() throws {
        let original = deterministic(171057, seed: 99)
        let bin = tempURL(); try original.write(to: bin)
        let eml = tempURL()
        try MIMEBuilder.streamEncryptedEnvelope(binaryMessageAt: bin, to: eml, boundary: "----=_env_test")

        let text = try String(contentsOf: eml, encoding: .utf8)
        XCTAssertTrue(text.contains("multipart/encrypted; protocol=\"application/pgp-encrypted\""),
                      "RFC 3156 envelope header present")
        XCTAssertTrue(text.contains("Version: 1"), "PGP/MIME version identification part present")
        XCTAssertTrue(text.contains("------=_env_test--"), "envelope closes with the final boundary")

        guard let (body, crc) = deArmor(text) else {
            return XCTFail("no armored message found in the envelope")
        }
        XCTAssertEqual(body, original, "part 2 must de-armor to the original message")
        XCTAssertEqual(crc, expectedCRC(original), "part 2 armor CRC-24 must be correct")
    }

    func testStreamingCRC24MatchesWholeBufferForm() throws {
        // The incremental CRC fed in two pieces equals feeding the whole buffer.
        let a = deterministic(100, seed: 1)
        let b = deterministic(171057, seed: 2)
        var whole = OpenPGPPacketBuilder.StreamingCRC24(); whole.update(a + b)
        var split = OpenPGPPacketBuilder.StreamingCRC24(); split.update(a); split.update(b)
        XCTAssertEqual(whole.finalize(), split.finalize())
    }

    func testStreamingDearmorRoundTrip() throws {
        // The streaming de-armor must recover the exact original bytes from both
        // a standalone .asc and an RFC 3156 .eml (envelope skip), so the large
        // decrypt path feeds the streaming binary decryptor the right message.
        for (i, n) in [0, 1, 2, 3, 57, 58, 200, 171056, 171057].enumerated() {
            let original = deterministic(n, seed: i * 23 + 5)
            let bin = tempURL(); try original.write(to: bin)

            let asc = tempURL()
            try OpenPGPPacketBuilder.streamArmoredFile(binaryAt: bin, to: asc)
            let fromAsc = tempURL()
            try OpenPGPPacketParser.streamingDearmor(fileAt: asc, to: fromAsc)
            XCTAssertEqual(try Data(contentsOf: fromAsc), original, ".asc de-armor must round-trip (n=\(n))")

            let eml = tempURL()
            try MIMEBuilder.streamEncryptedEnvelope(binaryMessageAt: bin, to: eml)
            let fromEml = tempURL()
            try OpenPGPPacketParser.streamingDearmor(fileAt: eml, to: fromEml)
            XCTAssertEqual(try Data(contentsOf: fromEml), original, ".eml de-armor must round-trip (n=\(n))")
        }
    }

    func testStreamedCRCMatchesArmorMessage() throws {
        // The table-driven streaming CRC must equal the bit-loop CRC that
        // armorMessage produces (the in-memory armor gpg already accepts), or
        // the streamed export would carry a wrong checksum and be rejected.
        for (i, n) in [1, 2, 3, 57, 58, 1000, 171056, 171057].enumerated() {
            let data = deterministic(n, seed: i * 17 + 3)
            let bin = tempURL(); try data.write(to: bin)
            let asc = tempURL()
            try OpenPGPPacketBuilder.streamArmoredFile(binaryAt: bin, to: asc)
            let streamedCRC = deArmor(try String(contentsOf: asc, encoding: .utf8))?.crc

            let inMemoryCRC = OpenPGPPacketBuilder.armorMessage(data)
                .replacingOccurrences(of: "\r\n", with: "\n")
                .split(separator: "\n", omittingEmptySubsequences: true)
                .first(where: { $0.hasPrefix("=") })
                .map { String($0.dropFirst()) }

            XCTAssertNotNil(streamedCRC, "streamed armor did not parse (n=\(n))")
            XCTAssertEqual(streamedCRC, inMemoryCRC, "table CRC must equal armorMessage's bit-loop CRC (n=\(n))")
        }
    }
}
