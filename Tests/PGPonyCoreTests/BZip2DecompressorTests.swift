// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// BZip2DecompressorTests.swift
// PGPonyTests
//
// v8.1.1 — fixtures below are real `bzip2 -9` output (via Python's `bz2`,
// which wraps libbz2, the reference implementation), generated once and
// hardcoded here so the test doesn't depend on any compression capability —
// PGPony only ever needs to decompress BZip2, never produce it.

import XCTest
@testable import PGPonyCore

final class BZip2DecompressorTests: XCTestCase {

    func testDecompressesEmptyStream() throws {
        let compressed: [UInt8] = [0x42, 0x5a, 0x68, 0x39, 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0x00, 0x00, 0x00, 0x00]
        let result = try BZip2Decompressor.decompress(compressed)
        XCTAssertTrue(result.isEmpty)
    }

    func testDecompressesShortText() throws {
        let compressed: [UInt8] = [0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x44, 0xf7, 0x13, 0x78,
                                    0x00, 0x00, 0x01, 0x91, 0x80, 0x40, 0x00, 0x06, 0x44, 0x90, 0x80, 0x20, 0x00, 0x22,
                                    0x03, 0x34, 0x84, 0x30, 0x21, 0xb6, 0x81, 0x54, 0x27, 0x8b, 0xb9, 0x22, 0x9c, 0x28,
                                    0x48, 0x22, 0x7b, 0x89, 0xbc, 0x00]
        let result = try BZip2Decompressor.decompress(compressed)
        XCTAssertEqual(String(decoding: result, as: UTF8.self), "hello world")
    }

    func testDecompressesLongRuns() throws {
        // Exercises the RUNA/RUNB bijective run-length path (RLE2) with runs
        // long enough to need multiple run bits, across two distinct bytes.
        let compressed: [UInt8] = [0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x6a, 0x34, 0x0c, 0x6d,
                                    0x00, 0x00, 0x04, 0xb3, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x10, 0x20, 0x00, 0x20,
                                    0x00, 0x30, 0xcd, 0x34, 0x18, 0xc8, 0x3a, 0xa5, 0x78, 0xbb, 0x92, 0x29, 0xc2, 0x84,
                                    0x83, 0x51, 0xa0, 0x63, 0x68]
        let result = try BZip2Decompressor.decompress(compressed)
        let expected = String(repeating: "a", count: 40) + String(repeating: "Z", count: 25)
        XCTAssertEqual(String(decoding: result, as: UTF8.self), expected)
    }

    func testDecompressesRepeatedMixedContent() throws {
        // A wider alphabet (letters, digits, punctuation) repeated 3x, so the
        // Huffman table selection (multiple 50-symbol groups) and the
        // move-to-front state both get real exercise.
        let compressed: [UInt8] = [0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xc2, 0x92, 0x1c, 0x55,
                                    0x00, 0x00, 0x2c, 0x9f, 0x80, 0x6f, 0x70, 0x7f, 0xe0, 0x40, 0x00, 0x04, 0x01, 0x3f,
                                    0xff, 0xff, 0xf0, 0x20, 0x00, 0x60, 0xcf, 0xfd, 0x55, 0x26, 0x80, 0x1a, 0x0d, 0x00,
                                    0xc4, 0x68, 0x00, 0xd3, 0x35, 0x06, 0x06, 0x41, 0x90, 0x00, 0x62, 0x34, 0x19, 0x0c,
                                    0x80, 0xc9, 0x94, 0xb9, 0xa0, 0xee, 0x82, 0xa5, 0x68, 0xd5, 0xb1, 0x28, 0x65, 0x4a,
                                    0xe2, 0xd4, 0x99, 0x33, 0x03, 0x5b, 0x63, 0x6b, 0x73, 0x7b, 0x82, 0x75, 0x0a, 0x53,
                                    0xa9, 0x52, 0xf2, 0x95, 0xe1, 0x1b, 0xc4, 0x4b, 0x57, 0x1f, 0x16, 0x3b, 0x2d, 0x5d,
                                    0x7a, 0x46, 0xb8, 0x83, 0xe2, 0x45, 0x4a, 0xd6, 0x24, 0x75, 0x7d, 0x5a, 0x91, 0x04,
                                    0x19, 0xd1, 0x45, 0xf9, 0xf9, 0xfc, 0x5d, 0xc9, 0x14, 0xe1, 0x42, 0x43, 0x0a, 0x48,
                                    0x71, 0x54]
        let result = try BZip2Decompressor.decompress(compressed)
        let one = "The quick brown fox jumps over the lazy dog 0123456789 !@#$%^&*()"
        XCTAssertEqual(String(decoding: result, as: UTF8.self), one + one + one)
    }

    func testRejectsNonBZip2Data() {
        let notBZip2: [UInt8] = [0x00, 0x01, 0x02, 0x03]
        XCTAssertThrowsError(try BZip2Decompressor.decompress(notBZip2)) { error in
            XCTAssertTrue(error is BZip2Error)
        }
    }

    func testRejectsTruncatedStream() {
        // A valid header with everything cut off after it.
        let truncated: [UInt8] = [0x42, 0x5a, 0x68, 0x39]
        XCTAssertThrowsError(try BZip2Decompressor.decompress(truncated)) { error in
            XCTAssertTrue(error is BZip2Error)
        }
    }

    // MARK: - Wired into the packet parser (extractLiteralData, case 3)

    /// bzip2 -9 of a complete, FRAMED literal-data packet (new-format CTB
    /// 0xCB, one-byte length, then the body: mode 'b', no filename, zero
    /// timestamp, "hello world"). A Compressed Data packet's payload is a
    /// packet STREAM (RFC 4880 §5.6), packets with headers, not a bare
    /// packet body; that is what GnuPG emits and what
    /// `flattenCompressedPackets` hands to `parsePackets` after inflating.
    ///
    /// v8.2.0 fixture fix: the original v8.1.1 fixture compressed the bare
    /// BODY without the 0xCB framing, so the inner parse failed, the tag-8
    /// wrapper survived flattening, and both parser-wiring tests below have
    /// failed since the day they were added. The decompressor itself was
    /// always fine (its direct tests passed); only this fixture was wrong.
    /// Regenerated with Python's bz2 (libbz2, the reference implementation)
    /// and round-trip verified before baking in.
    private static let literalPacketCompressed: [UInt8] = [
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xd0, 0x21, 0x40, 0xd1, 0x00, 0x00,
        0x09, 0x71, 0x84, 0x60, 0x00, 0x20, 0x00, 0x40, 0x00, 0x16, 0x44, 0x90, 0x80, 0x00, 0x08, 0x20,
        0x00, 0x21, 0xa9, 0xa3, 0x26, 0x9b, 0x14, 0x20, 0x1a, 0x00, 0x98, 0x01, 0x9a, 0x26, 0xd2, 0x90,
        0xed, 0x3f, 0x8b, 0xb9, 0x22, 0x9c, 0x28, 0x48, 0x68, 0x10, 0xa0, 0x68, 0x80
    ]

    func testExtractLiteralDataDecompressesBZip2CompressedPacket() throws {
        // Compressed Data packet (tag 8, new-format CTB 0xC8), one-byte
        // algorithm ID (3 = BZip2) followed by the raw bzip2 stream.
        let compressedPacketBody: [UInt8] = [3] + Self.literalPacketCompressed
        let framed: [UInt8] = [0xC8, UInt8(compressedPacketBody.count)] + compressedPacketBody

        let packets = try OpenPGPPacketParser.parsePackets(data: framed)
        let literal = try OpenPGPPacketParser.extractLiteralData(from: packets)

        XCTAssertNotNil(literal)
        XCTAssertEqual(String(decoding: literal ?? Data(), as: UTF8.self), "hello world")
    }

    func testFlattenCompressedPacketsDecompressesBZip2() throws {
        let compressedPacketBody: [UInt8] = [3] + Self.literalPacketCompressed
        let framed: [UInt8] = [0xC8, UInt8(compressedPacketBody.count)] + compressedPacketBody

        let packets = try OpenPGPPacketParser.parsePackets(data: framed)
        let flattened = OpenPGPPacketParser.flattenCompressedPackets(packets)

        // The compressed wrapper should be gone, replaced by its one inner
        // literal-data packet (tag 11) — this is what lets a compressed AND
        // signed message's tag-2 signature be found by a top-level scan.
        XCTAssertEqual(flattened.count, 1)
        XCTAssertEqual(flattened.first?.tag, 11)
    }

    /// This is the tester's exact "message decrypted, but says unsigned and
    /// the text is empty" bug, isolated to the packet layer with no crypto
    /// involved: a compressed (algo 0, uncompressed — the compression itself
    /// isn't the point here) wrapper around OnePassSig + Literal + Signature.
    /// Before the fix, a top-level `first(where: { $0.tag == 2 })` scan over
    /// the un-flattened packets never found the signature, because it was
    /// nested inside the compressed packet rather than a sibling of it.
    func testFlattenCompressedPacketsSurfacesNestedSignature() throws {
        let onePassSig: [UInt8] = [0x84, 0x0d] + Array(repeating: 0, count: 13)   // old-format tag 4, dummy body
        let literalBody: [UInt8] = [0x62, 0x00, 0x00, 0x00, 0x00, 0x00] + Array("hi".utf8)
        let literal: [UInt8] = [0xCB, UInt8(literalBody.count)] + literalBody     // new-format tag 11
        let signature: [UInt8] = [0x88, 0x05] + Array(repeating: 0, count: 5)     // old-format tag 2, dummy body
        let innerStream = onePassSig + literal + signature

        let compressedBody: [UInt8] = [0] + innerStream   // algo 0 = uncompressed
        let framed: [UInt8] = [0xC8, UInt8(compressedBody.count)] + compressedBody

        let topLevelPackets = try OpenPGPPacketParser.parsePackets(data: framed)
        XCTAssertNil(topLevelPackets.first(where: { $0.tag == 2 }),
                      "sanity check: the signature really is nested, not a top-level sibling")

        let flattened = OpenPGPPacketParser.flattenCompressedPackets(topLevelPackets)
        XCTAssertNotNil(flattened.first(where: { $0.tag == 2 }),
                         "flattening must surface the nested signature so it isn't misreported as unsigned")
    }
}
