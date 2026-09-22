// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// SecurityLimitsTests.swift
// PGPonyTests
//
// 8.3.0 hardening, planning section 5 findings 1 and 2: the pre-authentication
// resource ceilings. Argon2 parameters off the wire are bounded before any
// block is allocated; Compressed Data packets are bounded in nesting depth and
// in inflated bytes; a truncated deflate stream is an error, not a spin.
// Every legitimate shape PGPony emits or reads today must still pass.

import XCTest
import Compression
import zlib
@testable import PGPonyCore

final class SecurityLimitsTests: XCTestCase {

    // MARK: - Argon2 policy (finding 1)

    func testOwnAndCommonArgon2ParametersPass() throws {
        // PGPony's own v6 protection (V6KeyGenerator), and gpg / Sequoia defaults.
        XCTAssertNoThrow(try SecurityLimits.enforceArgon2Policy(passes: 3, parallelism: 4, memoryExponent: 14))
        XCTAssertNoThrow(try SecurityLimits.enforceArgon2Policy(passes: 1, parallelism: 4, memoryExponent: 16))
        XCTAssertNoThrow(try SecurityLimits.enforceArgon2Policy(passes: 3, parallelism: 1, memoryExponent: 10))
    }

    func testArgon2MemoryAboveTheHardCeilingIsRefused() {
        XCTAssertThrowsError(try SecurityLimits.enforceArgon2Policy(passes: 1, parallelism: 1, memoryExponent: 23)) {
            XCTAssertTrue($0 is SecurityLimitError, "got \($0)")
        }
        XCTAssertThrowsError(try SecurityLimits.enforceArgon2Policy(passes: 1, parallelism: 1, memoryExponent: 31)) {
            XCTAssertTrue($0 is SecurityLimitError, "got \($0)")
        }
    }

    func testArgon2PassAndParallelismCeilings() {
        XCTAssertThrowsError(try SecurityLimits.enforceArgon2Policy(passes: 65, parallelism: 1, memoryExponent: 14))
        XCTAssertThrowsError(try SecurityLimits.enforceArgon2Policy(passes: 1, parallelism: 65, memoryExponent: 14))
        XCTAssertThrowsError(try SecurityLimits.enforceArgon2Policy(passes: 0, parallelism: 1, memoryExponent: 14))
    }

    func testArgon2AboveTheFloorIsDeviceRelative() {
        // Whatever this host can spare, 2^22 KiB (4 GiB) is over the hard
        // ceiling and 2^17 KiB (128 MiB) is decided by the budget, never by
        // a crash. Both outcomes are typed.
        do {
            try SecurityLimits.enforceArgon2Policy(passes: 1, parallelism: 1, memoryExponent: 17)
        } catch {
            XCTAssertTrue(error is SecurityLimitError, "got \(error)")
        }
        XCTAssertGreaterThan(SecurityLimits.availableMemoryBytes(), 0)
    }

    /// The seam every caller goes through: a crafted exponent is refused by
    /// deriveKey itself, before allocation, with the typed error rather than
    /// Argon2Error.memoryAllocationFailed or a jetsam kill.
    func testDeriveKeyRefusesACraftedMemoryExponent() {
        let salt = [UInt8](repeating: 0x5A, count: 16)
        XCTAssertThrowsError(try Argon2Service.deriveKey(
            passphrase: "pw", salt: salt, iterations: 1, parallelism: 1, memoryExponent: 31, hashLength: 32)) {
            XCTAssertTrue($0 is SecurityLimitError, "got \($0)")
        }
    }

    func testDeriveKeyStillWorksAtOwnParameters() throws {
        let salt = [UInt8](repeating: 0x5A, count: 16)
        let key = try Argon2Service.deriveKey(
            passphrase: "pw", salt: salt, iterations: 1, parallelism: 1, memoryExponent: 10, hashLength: 32)
        XCTAssertEqual(key.count, 32)
    }

    // MARK: - Decompression (finding 2)

    /// Raw DEFLATE (OpenPGP compression algorithm 1) of `count` zero bytes.
    private func rawDeflateZeros(_ count: Int) -> [UInt8] {
        let source = [UInt8](repeating: 0, count: count)
        var dest = [UInt8](repeating: 0, count: max(1024, count / 100 + 1024))
        let written = source.withUnsafeBufferPointer { src in
            dest.withUnsafeMutableBufferPointer { dst in
                compression_encode_buffer(dst.baseAddress!, dst.count, src.baseAddress!, src.count, nil, COMPRESSION_ZLIB)
            }
        }
        precondition(written > 0, "compression_encode_buffer failed")
        return Array(dest[0..<written])
    }

    private func literalPacket(_ payload: [UInt8]) -> [UInt8] {
        // format 'b', empty filename, zero date, data
        OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 11, body: [0x62, 0x00, 0, 0, 0, 0] + payload)
    }

    private func compressedPacket(algo: UInt8, _ inner: [UInt8]) -> [UInt8] {
        OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 8, body: [algo] + inner)
    }

    func testInflationPastTheLimitIsRefused() throws {
        let compressed = rawDeflateZeros(1 << 20)                       // 1 MiB of zeros, a few KB deflated
        let body: [UInt8] = [1] + compressed
        XCTAssertEqual(try OpenPGPPacketParser.decompressCompressedBody(body).count, 1 << 20)
        XCTAssertThrowsError(try OpenPGPPacketParser.decompressCompressedBody(body, limit: 512 * 1024)) {
            XCTAssertTrue($0 is SecurityLimitError, "got \($0)")
        }
    }

    func testTruncatedDeflateStreamIsAnErrorNotAHang() {
        let compressed = rawDeflateZeros(64 * 1024)
        let cut = Array(compressed.dropLast(max(8, compressed.count / 4)))
        XCTAssertThrowsError(try OpenPGPPacketParser.decompressCompressedBody([1] + cut)) { error in
            XCTAssertFalse(error is SecurityLimitError, "a truncated stream is a parse failure, not a limit")
        }
    }

    func testNestingWithinTheDepthCeilingStillYieldsTheLiteral() throws {
        let payload = Array("nested but legal".utf8)
        var packet = literalPacket(payload)
        for _ in 0..<SecurityLimits.maxDecompressionDepth {
            packet = compressedPacket(algo: 0, packet)                  // algorithm 0: stored, no inflate
        }
        let packets = try OpenPGPPacketParser.parsePackets(data: packet)
        XCTAssertEqual(try OpenPGPPacketParser.extractLiteralData(from: packets), Data(payload))
        XCTAssertEqual(try OpenPGPPacketParser.flattenMessagePackets(packet).first?.tag, 11)
    }

    func testNestingPastTheDepthCeilingIsRefused() throws {
        var packet = literalPacket(Array("too deep".utf8))
        for _ in 0...SecurityLimits.maxDecompressionDepth {
            packet = compressedPacket(algo: 0, packet)
        }
        let packets = try OpenPGPPacketParser.parsePackets(data: packet)
        XCTAssertThrowsError(try OpenPGPPacketParser.extractLiteralData(from: packets)) {
            XCTAssertTrue($0 is SecurityLimitError, "got \($0)")
        }
        XCTAssertThrowsError(try OpenPGPPacketParser.flattenMessagePackets(packet))
        // The non-throwing flattener stops at the ceiling and keeps the
        // innermost compressed packet opaque instead of inflating it.
        let flat = OpenPGPPacketParser.flattenCompressedPackets(packets)
        XCTAssertEqual(flat.count, 1)
        XCTAssertEqual(flat.first?.tag, 8)
    }

    private func rawDeflate(_ bytes: [UInt8]) -> [UInt8] {
        var dest = [UInt8](repeating: 0, count: bytes.count + 1024)
        let n = bytes.withUnsafeBufferPointer { src in
            dest.withUnsafeMutableBufferPointer { dst in
                compression_encode_buffer(dst.baseAddress!, dst.count, src.baseAddress!, src.count, nil, COMPRESSION_ZLIB)
            }
        }
        precondition(n > 0, "compression_encode_buffer failed")
        return Array(dest[0..<n])
    }

    /// The everyday shape (gpg compresses the literal packet, algorithm 1)
    /// is untouched by the caps.
    func testOrdinaryCompressedLiteralStillRoundTrips() throws {
        let payload = Array("Hello world".utf8)
        let packet = compressedPacket(algo: 1, rawDeflate(literalPacket(payload)))
        let packets = try OpenPGPPacketParser.parsePackets(data: packet)
        XCTAssertEqual(try OpenPGPPacketParser.extractLiteralData(from: packets), Data(payload))
        XCTAssertEqual(OpenPGPPacketParser.flattenCompressedPackets(packets).first?.tag, 11)
    }
}
