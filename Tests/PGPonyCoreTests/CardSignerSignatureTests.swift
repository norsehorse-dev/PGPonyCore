// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CardSignerSignatureTests.swift
// PGPony
//
// v8.2.0: guards the hardware-key signature framing against the MPI leading-zero
// bug. CardSigner.assembleSignatureBody builds the v4 signature packet body from
// the MPIs a card returns; its mpiEncode used to emit the full value bytes while
// declaring a bit length that excluded leading zeros, so a reader taking
// ceil(bits/8) bytes misaligned the following MPI. For an EdDSA card signature
// that is R then S (S, a reduced scalar, frequently has a high zero octet), so
// the signature verified only some of the time.
//
// These drive the real assembly path (the seam CardSigner already exposes for
// card-free testing) with a signature whose S has a leading zero octet, then
// parse the body back with the production parser and confirm both MPIs recover
// their original 32-byte values with nothing bleeding across the boundary.
// Deterministic: fails on the old encoder, passes on the fixed one.

import XCTest
@testable import PGPonyCore

final class CardSignerSignatureTests: XCTestCase {

    private func parseMPI(_ bytes: [UInt8], _ offset: inout Int) -> [UInt8]? {
        guard offset + 2 <= bytes.count else { return nil }
        let bits = Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
        offset += 2
        let nbytes = (bits + 7) / 8
        guard offset + nbytes <= bytes.count else { return nil }
        let value = Array(bytes[offset..<(offset + nbytes)])
        offset += nbytes
        return value
    }

    private func repad32(_ v: [UInt8]) -> [UInt8] {
        var out = v
        while out.count < 32 { out.insert(0, at: 0) }
        return out
    }

    func testEdDSACardSignatureWithLeadingZeroScalarRoundTrips() throws {
        // R: full-width, no leading zero. S: a reduced scalar with a high zero
        // octet, the shape that used to corrupt the framing.
        var r = [UInt8](repeating: 0, count: 32); r[0] = 0x80
        for i in 1..<32 { r[i] = UInt8((i * 11 + 5) & 0xFF) }
        var s = [UInt8](repeating: 0, count: 32); s[0] = 0x00; s[1] = 0x7F
        for i in 2..<32 { s[i] = UInt8((i * 7 + 3) & 0xFF) }

        let body = CardSigner.assembleSignatureBody(
            pubkeyAlgo: 22,          // EdDSA
            sigType: 0x00,           // binary document
            hashed: [],
            unhashed: [],
            hashPrefix2: [0x12, 0x34],
            signatureMPIs: [r, s]
        )

        // Parse the whole body with the production parser: proves the body is a
        // well-formed v4 signature, not just that mpiEncode did something.
        let sig = try OpenPGPPacketParser.parseSignaturePacket(body: body)
        XCTAssertEqual(sig.version, 4)
        XCTAssertEqual(sig.signatureType, 0x00)

        // signatureData for a v4 EdDSA sig is MPI(R) followed by MPI(S).
        var off = 0
        guard let parsedR = parseMPI(sig.signatureData, &off) else { return XCTFail("R unparseable") }
        guard let parsedS = parseMPI(sig.signatureData, &off) else { return XCTFail("S unparseable") }
        XCTAssertEqual(off, sig.signatureData.count, "S must consume exactly the remaining bytes")
        XCTAssertEqual(repad32(parsedR), r, "R recovers its 32 bytes")
        XCTAssertEqual(repad32(parsedS), s, "S recovers its 32 bytes")
    }

    func testRSACardSignatureWithLeadingZeroValueRoundTrips() throws {
        // An RSA card signature is a single value m^d mod n. A value with a high
        // zero octet must still frame as one clean MPI.
        var value = [UInt8](repeating: 0, count: 256)
        value[0] = 0x00
        value[1] = 0x00
        value[2] = 0x91
        for i in 3..<256 { value[i] = UInt8((i * 13 + 7) & 0xFF) }

        let body = CardSigner.assembleSignatureBody(
            pubkeyAlgo: 1,           // RSA
            sigType: 0x00,
            hashed: [],
            unhashed: [],
            hashPrefix2: [0xAB, 0xCD],
            signatureMPIs: [value]
        )

        let sig = try OpenPGPPacketParser.parseSignaturePacket(body: body)
        var off = 0
        guard let parsed = parseMPI(sig.signatureData, &off) else { return XCTFail("RSA value unparseable") }
        XCTAssertEqual(off, sig.signatureData.count, "the single RSA MPI must consume all signature bytes")
        XCTAssertNotEqual(parsed.first, 0, "no leading zero octet survives")
        // Strip the two leading zero octets from the original and compare.
        var expected = value
        while expected.first == 0 { expected.removeFirst() }
        XCTAssertEqual(parsed, expected, "RSA value recovers, minus its leading zeros")
    }
}
