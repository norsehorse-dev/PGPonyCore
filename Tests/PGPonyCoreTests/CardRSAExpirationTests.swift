// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CardRSAExpirationTests.swift
// PGPonyTests
//
// HW-R5: on-card expiration editing for RSA card keys. The key-targeted signature
// builder (`signKeyTargeted`) must frame the binding/cert signature for the card's
// algorithm: RSA = pubkey algo 1 + a single canonical MPI (leading zero bytes
// stripped); EdDSA = pubkey algo 22 + two MPIs (R, S). The card transform itself is
// validated on device by a gpg --import + verify of the re-signed key.

import XCTest
@testable import PGPonyCore

final class CardRSAExpirationTests: XCTestCase {

    // Empty hashed/unhashed subpackets so the MPI region starts at a known offset:
    // [version, sigType, pubAlgo, hashAlgo, hashedLen(2)=0, unhashedLen(2)=0,
    //  hashPrefix(2), MPIs...] → MPIs begin at body offset 10.
    private func tag2Body(_ packetBytes: [UInt8]) throws -> [UInt8] {
        let parsed = try OpenPGPPacketParser.parsePackets(data: packetBytes)
        guard let sig = parsed.first(where: { $0.tag == 2 }) else {
            throw NSError(domain: "test", code: 0)
        }
        return sig.body
    }

    func testRSABindingHasAlgo1AndSingleCanonicalMPI() async throws {
        // Card returns a 512-byte RSA-4096 signature with a leading zero byte.
        let cardSig: [UInt8] = [0x00, 0x80] + [UInt8](repeating: 0x5A, count: 510)
        let packet = try await KeyExpirationEditor.signKeyTargeted(
            primaryBody: [UInt8](repeating: 0x11, count: 40),
            document2: [0x99, 0x00, 0x05, 1, 2, 3, 4, 5],
            sigType: 0x18,
            algorithm: .rsa,
            hashedSubpackets: [],
            unhashedSubpackets: [],
            sign: { _ in cardSig }
        )
        let body = try tag2Body(packet)

        XCTAssertEqual(body[0], 4)       // v4 signature
        XCTAssertEqual(body[2], 1)       // pubkey algorithm: RSA
        XCTAssertEqual(body[3], 8)       // hash: SHA-256

        // Single MPI at offset 10; leading zero stripped → 511 bytes, top bit set.
        let mpiBits = Int(body[10]) << 8 | Int(body[11])
        let mpiBytes = (mpiBits + 7) / 8
        XCTAssertEqual(mpiBytes, 511)
        XCTAssertEqual(body.count, 10 + 2 + 511)   // exactly one MPI, nothing trailing
        XCTAssertEqual(body[12], 0x80)             // first kept byte (zero was stripped)
    }

    func testEdDSABindingHasAlgo22AndTwoMPIs() async throws {
        // Card returns 64 bytes R||S.
        let r = [UInt8](repeating: 0x22, count: 32)
        let s = [UInt8](repeating: 0x33, count: 32)
        let packet = try await KeyExpirationEditor.signKeyTargeted(
            primaryBody: [UInt8](repeating: 0x11, count: 40),
            document2: [0xB4, 0, 0, 0, 3, 65, 66, 67],
            sigType: 0x13,
            algorithm: .eddsa,
            hashedSubpackets: [],
            unhashedSubpackets: [],
            sign: { _ in r + s }
        )
        let body = try tag2Body(packet)

        XCTAssertEqual(body[2], 22)      // pubkey algorithm: EdDSA

        // First MPI (R) at offset 10.
        let mpi1Bits = Int(body[10]) << 8 | Int(body[11])
        let mpi1Bytes = (mpi1Bits + 7) / 8
        let secondMPIStart = 12 + mpi1Bytes
        let mpi2Bits = Int(body[secondMPIStart]) << 8 | Int(body[secondMPIStart + 1])
        let mpi2Bytes = (mpi2Bits + 7) / 8
        // Two MPIs, R||S = 32 bytes each (0x22.. and 0x33.. have the high bit clear,
        // so each encodes as 30 significant bits → still 32 bytes... actually 0x22 =
        // 0010_0010, top bit clear, so bit length is 8*31 + 6 = 254 → 32 bytes).
        XCTAssertEqual(body.count, secondMPIStart + 2 + mpi2Bytes)
        XCTAssertEqual(mpi1Bytes, 32)
        XCTAssertEqual(mpi2Bytes, 32)
    }

    func testRSAEmptySignatureThrows() async {
        do {
            _ = try await KeyExpirationEditor.signKeyTargeted(
                primaryBody: [1, 2, 3],
                document2: [4, 5, 6],
                sigType: 0x18,
                algorithm: .rsa,
                hashedSubpackets: [],
                unhashedSubpackets: [],
                sign: { _ in [] }
            )
            XCTFail("Expected empty-signature error")
        } catch {
            // expected
        }
    }
}
