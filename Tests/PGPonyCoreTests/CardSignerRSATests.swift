// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CardSignerRSATests.swift
// PGPonyTests
//
// HW-R2: hardware-free tests for the RSA-on-card signing additions to CardSigner.
//
// Two pure pieces are exercised without any NFC:
//   1. sha256DigestInfo — the PKCS#1 v1.5 DigestInfo handed to the card's PSO:CDS
//      for an RSA signing key (fixed 19-byte SHA-256 DER prefix + the 32-byte
//      digest).
//   2. assembleSignatureBody — the v4 signature packet body framing, which must
//      emit pubkey-algo 1 with a single MPI for RSA and pubkey-algo 22 with two
//      MPIs for EdDSA.
//
// The on-card APDU exchange itself (signRSA / transmitChained) needs hardware and
// is verified on-device against `gpg --verify`.

import XCTest
import CryptoKit
@testable import PGPonyCore

final class CardSignerRSATests: XCTestCase {

    // MARK: - Algorithm mapping

    func testCardAlgoIDMapping() {
        XCTAssertEqual(CardSignatureAlgorithm(cardAlgoID: 0x01), .rsa)
        XCTAssertEqual(CardSignatureAlgorithm(cardAlgoID: 0x16), .eddsa)
        XCTAssertNil(CardSignatureAlgorithm(cardAlgoID: 0x13)) // ECDSA — not built
        XCTAssertNil(CardSignatureAlgorithm(cardAlgoID: 0x00))
    }

    func testPacketAlgorithmIDs() {
        XCTAssertEqual(CardSignatureAlgorithm.rsa.packetAlgorithmID, 1)
        XCTAssertEqual(CardSignatureAlgorithm.eddsa.packetAlgorithmID, 22)
    }

    // MARK: - DigestInfo

    func testSHA256DigestInfoPrefixAndLength() {
        let digest = [UInt8](repeating: 0xAB, count: 32)
        let di = CardSigner.sha256DigestInfo(digest)

        // 19-byte DER prefix + 32-byte digest.
        XCTAssertEqual(di.count, 51)

        let expectedPrefix: [UInt8] = [
            0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
        ]
        XCTAssertEqual(Array(di.prefix(19)), expectedPrefix)
        XCTAssertEqual(Array(di.suffix(32)), digest)
    }

    func testSHA256DigestInfoMatchesRealHash() {
        // The DigestInfo must wrap exactly the SHA-256 of the input, so the card
        // signs over the same bytes a verifier recomputes.
        let msg = Array("hardware key".utf8)
        let digest = Array(SHA256.hash(data: Data(msg)))
        let di = CardSigner.sha256DigestInfo(digest)
        XCTAssertEqual(Array(di.suffix(32)), digest)
        // Final OCTET STRING length byte must announce 32.
        XCTAssertEqual(di[18], 0x20)
    }

    // MARK: - Packet body framing

    /// Minimal MPI reader: returns (bitLength, valueBytes, bytesConsumed).
    private func readMPI(_ bytes: ArraySlice<UInt8>) -> (bits: Int, value: [UInt8], consumed: Int)? {
        let arr = Array(bytes)
        guard arr.count >= 2 else { return nil }
        let bits = (Int(arr[0]) << 8) | Int(arr[1])
        let byteLen = (bits + 7) / 8
        guard arr.count >= 2 + byteLen else { return nil }
        return (bits, Array(arr[2..<(2 + byteLen)]), 2 + byteLen)
    }

    func testRSABodyHasAlgo1AndExactlyOneMPI() {
        let hashed: [UInt8] = [0xAA, 0xBB, 0xCC]
        let unhashed: [UInt8] = [0xDD, 0xEE]
        let prefix2: [UInt8] = [0x12, 0x34]
        // A 512-byte RSA-4096 signature with a non-zero top byte (canonical).
        var sig = [UInt8](repeating: 0x7F, count: 512)
        sig[0] = 0x01

        let body = CardSigner.assembleSignatureBody(
            pubkeyAlgo: 1, sigType: 0x00,
            hashed: hashed, unhashed: unhashed,
            hashPrefix2: prefix2, signatureMPIs: [sig]
        )

        // Header: version 4, sig type 0x00, pubkey algo 1 (RSA), hash algo 8.
        XCTAssertEqual(Array(body.prefix(4)), [4, 0x00, 1, 8])

        // Walk to the MPI region: 4 header + 2 (hashed len) + hashed + 2 (unhashed len)
        // + unhashed + 2 (hash prefix).
        var i = 4
        XCTAssertEqual((Int(body[i]) << 8) | Int(body[i + 1]), hashed.count)
        i += 2 + hashed.count
        XCTAssertEqual((Int(body[i]) << 8) | Int(body[i + 1]), unhashed.count)
        i += 2 + unhashed.count
        XCTAssertEqual(Array(body[i..<(i + 2)]), prefix2)
        i += 2

        // Exactly one MPI, and it consumes the rest of the body.
        guard let mpi = readMPI(body[i...]) else { return XCTFail("no MPI") }
        // Top byte 0x01 → 7 leading zero bits → bit length 512*8 - 7 = 4089.
        XCTAssertEqual(mpi.bits, 4089)
        XCTAssertEqual(mpi.value.count, 512)
        XCTAssertEqual(i + mpi.consumed, body.count, "RSA body must hold exactly one MPI")
    }

    func testEdDSABodyHasAlgo22AndTwoMPIs() {
        let hashed: [UInt8] = [0x01, 0x02]
        let unhashed: [UInt8] = [0x03]
        let prefix2: [UInt8] = [0xAB, 0xCD]
        var r = [UInt8](repeating: 0x55, count: 32); r[0] = 0x80
        var s = [UInt8](repeating: 0x66, count: 32); s[0] = 0x80

        let body = CardSigner.assembleSignatureBody(
            pubkeyAlgo: 22, sigType: 0x00,
            hashed: hashed, unhashed: unhashed,
            hashPrefix2: prefix2, signatureMPIs: [r, s]
        )

        XCTAssertEqual(Array(body.prefix(4)), [4, 0x00, 22, 8])

        var i = 4 + 2 + hashed.count + 2 + unhashed.count + 2
        guard let m1 = readMPI(body[i...]) else { return XCTFail("no first MPI") }
        XCTAssertEqual(m1.value.count, 32)
        i += m1.consumed
        guard let m2 = readMPI(body[i...]) else { return XCTFail("no second MPI") }
        XCTAssertEqual(m2.value.count, 32)
        i += m2.consumed
        XCTAssertEqual(i, body.count, "EdDSA body must hold exactly two MPIs")
    }

    func testCanonicalMPIBitLengthForNonZeroTopByte() {
        // Sanity on the MPI bit-length math the RSA path relies on after leading
        // zero bytes are stripped: top byte 0xFF → no leading zeros.
        let value: [UInt8] = [0xFF, 0x00, 0x01]
        let body = CardSigner.assembleSignatureBody(
            pubkeyAlgo: 1, sigType: 0x00,
            hashed: [], unhashed: [], hashPrefix2: [0, 0], signatureMPIs: [value]
        )
        var i = 4 + 2 + 0 + 2 + 0 + 2
        guard let mpi = readMPI(body[i...]) else { return XCTFail("no MPI") }
        XCTAssertEqual(mpi.bits, 24)          // 3 bytes, top byte 0xFF, no leading zeros
        XCTAssertEqual(mpi.value, value)
        i += mpi.consumed
        XCTAssertEqual(i, body.count)
    }
}
