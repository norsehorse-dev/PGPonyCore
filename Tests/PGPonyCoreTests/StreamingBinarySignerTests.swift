// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// StreamingBinarySignerTests.swift
// PGPonyTests
//
// v8.1.0 — §3a. Inline signatures over a stream.
//
// The claim that matters: feeding the message in pieces does not change WHAT
// gets signed.
//
// An earlier version of this file asserted that the whole signature packet was
// byte-identical regardless of chunking, on the grounds that Ed25519 is
// deterministic per RFC 8032. That is true of the specification and false of
// Apple's implementation: CryptoKit randomises, so signing the same bytes twice
// produces different R and S values. The assertion could never have held, and
// it failed the first time this file was run.
//
// So the equality is asserted where it actually exists. Everything up to the
// signature values is deterministic — the hashed subpackets, the creation time,
// and the two-octet hash prefix, which is derived from the digest. If the digest
// differed, that prefix would differ. Comparing it proves the hash agreed
// without pretending the signature bytes must.
//
// Each signature is also verified, which byte-comparison alone would not do.
//
// This also protects the refactor underneath: the shipping
// `buildBinarySignaturePacket` now delegates here, so every existing signing
// test in the suite exercises this class.

import XCTest
import CryptoKit
@testable import PGPonyCore

final class StreamingBinarySignerTests: XCTestCase {

    private let creationTime = Date(timeIntervalSince1970: 1_750_000_000)

    private func payload(_ n: Int) -> [UInt8] {
        (0..<n).map { UInt8(($0 &* 97 &+ 13) & 0xFF) }
    }

    private func signer(_ key: Curve25519.Signing.PrivateKey) -> StreamingBinarySigner {
        StreamingBinarySigner(
            signingKey: key,
            keyID: (0..<8).map { UInt8($0 &+ 1) },
            fingerprint: (0..<20).map { UInt8(($0 &* 7 &+ 3) & 0xFF) },
            creationTime: creationTime
        )
    }

    private func sign(_ data: [UInt8], key: Curve25519.Signing.PrivateKey, chunk: Int?) throws -> [UInt8] {
        let s = signer(key)
        if let chunk {
            var offset = 0
            while offset < data.count {
                let end = Swift.min(offset + chunk, data.count)
                s.update(Array(data[offset..<end]))
                offset = end
            }
        } else {
            s.update(data)
        }
        return try s.finish()
    }

    /// Everything a signature packet contains before its R and S values, which
    /// is all of the deterministic part. Ends with the two-octet hash prefix,
    /// so two packets agreeing here agreed on the digest.
    private func deterministicPrefix(of packet: [UInt8]) throws -> [UInt8] {
        let parsed = try XCTUnwrap(try OpenPGPPacketParser.parsePackets(data: packet).first)
        let body = parsed.body
        let hashedLength = (Int(body[4]) << 8) | Int(body[5])
        var offset = 6 + hashedLength
        let unhashedLength = (Int(body[offset]) << 8) | Int(body[offset + 1])
        offset += 2 + unhashedLength + 2          // unhashed area, then the hash prefix
        return Array(body[0..<offset])
    }

    /// Verify a detached signature over `data`, the way the decrypt path does.
    private func verifies(_ packet: [UInt8], over data: [UInt8], key: Curve25519.Signing.PrivateKey) throws -> Bool {
        let parsed = try XCTUnwrap(try OpenPGPPacketParser.parsePackets(data: packet).first)
        let verifier = try XCTUnwrap(StreamingBinaryVerifier(
            onePassBody: signer(key).onePassPacket.suffix(from: 2).map { $0 }
        ))
        verifier.update(data)
        return verifier.verify(signatureBody: parsed.body, publicKey: .ed25519(key.publicKey)) == true
    }

    func testChunkingDoesNotChangeWhatIsSigned() throws {
        let key = Curve25519.Signing.PrivateKey()
        let data = payload(200_000)
        let whole = try deterministicPrefix(of: try sign(data, key: key, chunk: nil))
        for chunk in [1, 7, 4_096, 65_536, 199_999] {
            XCTAssertEqual(try deterministicPrefix(of: try sign(data, key: key, chunk: chunk)), whole,
                           "the signed digest changed when fed in \(chunk)-byte pieces")
        }
    }

    func testChunkedSignatureVerifies() throws {
        let key = Curve25519.Signing.PrivateKey()
        let data = payload(120_000)
        for chunk in [1, 4_096, 120_000] {
            let packet = try sign(data, key: key, chunk: chunk)
            XCTAssertTrue(try verifies(packet, over: data, key: key),
                          "signature made in \(chunk)-byte pieces did not verify")
        }
    }

    func testEmptyMessageSigns() throws {
        let key = Curve25519.Signing.PrivateKey()
        XCTAssertEqual(try deterministicPrefix(of: try sign([], key: key, chunk: nil)),
                       try deterministicPrefix(of: try sign([], key: key, chunk: 1_024)))
    }

    /// The shipping builder now delegates here, so both must sign the same
    /// digest. Their signature VALUES differ, because CryptoKit randomises.
    func testShippingBuilderSignsTheSameDigest() throws {
        let key = Curve25519.Signing.PrivateKey()
        let data = payload(50_000)
        let viaBuilder = try OpenPGPPacketBuilder.buildBinarySignaturePacket(
            signingKey: key,
            keyID: (0..<8).map { UInt8($0 &+ 1) },
            fingerprint: (0..<20).map { UInt8(($0 &* 7 &+ 3) & 0xFF) },
            literalBody: data,
            creationTime: creationTime
        )
        XCTAssertEqual(try deterministicPrefix(of: viaBuilder),
                       try deterministicPrefix(of: try sign(data, key: key, chunk: 8_192)))
    }

    /// Split from the test above so a failure says WHICH half broke: the two
    /// paths disagreeing on the digest, or the signature not verifying at all.
    func testShippingBuilderSignatureVerifies() throws {
        let key = Curve25519.Signing.PrivateKey()
        let data = payload(50_000)
        let viaBuilder = try OpenPGPPacketBuilder.buildBinarySignaturePacket(
            signingKey: key,
            keyID: (0..<8).map { UInt8($0 &+ 1) },
            fingerprint: (0..<20).map { UInt8(($0 &* 7 &+ 3) & 0xFF) },
            literalBody: data,
            creationTime: creationTime
        )
        XCTAssertTrue(try verifies(viaBuilder, over: data, key: key))
    }

    func testProducesASignaturePacket() throws {
        let key = Curve25519.Signing.PrivateKey()
        let packet = try sign(payload(1_000), key: key, chunk: nil)
        let parsed = try XCTUnwrap(try OpenPGPPacketParser.parsePackets(data: packet).first)
        XCTAssertEqual(parsed.tag, 2, "expected a signature packet")
        XCTAssertEqual(parsed.body.first, 4, "expected a v4 signature")
        XCTAssertEqual(parsed.body[1], 0x00, "expected a binary-document signature")
    }

    func testOnePassPacketPrecedesAndNamesTheKey() throws {
        let key = Curve25519.Signing.PrivateKey()
        let ops = signer(key).onePassPacket
        let parsed = try XCTUnwrap(try OpenPGPPacketParser.parsePackets(data: ops).first)
        XCTAssertEqual(parsed.tag, 4, "expected a one-pass signature packet")
    }

    // MARK: - v6 detached sign + streaming verify (8.2.1)

    /// A detached v6 signature (StreamingV6Signer's packet is exactly that) must
    /// verify against the original file read from disk in chunks — the path a
    /// large signed file's .sig takes now that the verify UI streams the original
    /// instead of buffering it.
    func testV6DetachedSignVerifiesStreamingFromDisk() throws {
        let key = Curve25519.Signing.PrivateKey()
        let fp = (0..<32).map { UInt8(($0 &* 11 &+ 5) & 0xFF) }
        let data = payload(300_000)

        let signer = try StreamingV6Signer(signingKey: key, fingerprint: fp, creationTime: creationTime)
        var offset = 0
        while offset < data.count {
            let end = Swift.min(offset + 4_096, data.count)
            signer.update(Array(data[offset..<end]))
            offset = end
        }
        let sigPacket = try signer.finish()
        let parsed = try XCTUnwrap(try OpenPGPPacketParser.parsePackets(data: sigPacket).first)
        let sigInfo = try OpenPGPPacketParser.parseSignaturePacket(body: parsed.body)

        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("original.bin")
        try Data(data).write(to: file)

        let ok = try OpenPGPPacketParser.verifyEd25519SignatureStreaming(
            signature: sigInfo, fileAt: file, publicKey: Array(key.publicKey.rawRepresentation))
        XCTAssertTrue(ok, "detached v6 signature must verify when the original is streamed from disk")

        // A modified original must fail.
        var bad = data
        bad[0] = bad[0] &+ 1
        let badFile = dir.appendingPathComponent("tampered.bin")
        try Data(bad).write(to: badFile)
        let bogus = try OpenPGPPacketParser.verifyEd25519SignatureStreaming(
            signature: sigInfo, fileAt: badFile, publicKey: Array(key.publicKey.rawRepresentation))
        XCTAssertFalse(bogus, "a modified original must fail streamed verification")
    }

    // MARK: - v6 streaming sign + verify (8.2.1)

    /// The v6 counterpart of the round-trip above: StreamingV6Signer signs a
    /// streamed document and StreamingBinaryVerifier (v6 path) verifies it. This
    /// is the path a post-quantum key uses to sign a large file, and the reason a
    /// signed FILE now shows its signer the way signed text always has.
    func testV6StreamingSignAndVerify() throws {
        let key = Curve25519.Signing.PrivateKey()
        let data = payload(200_000)
        let fp = (0..<32).map { UInt8(($0 &* 7 &+ 3) & 0xFF) }

        // One signer instance: its OPS and its signature share the same salt.
        let s = try StreamingV6Signer(signingKey: key, fingerprint: fp, creationTime: creationTime)
        let ops = s.onePassPacket
        var offset = 0
        while offset < data.count {
            let end = Swift.min(offset + 4_096, data.count)
            s.update(Array(data[offset..<end]))
            offset = end
        }
        let packet = try s.finish()

        let parsed = try XCTUnwrap(try OpenPGPPacketParser.parsePackets(data: packet).first)
        XCTAssertEqual(parsed.tag, 2, "expected a signature packet")
        XCTAssertEqual(parsed.body.first, 6, "expected a v6 signature")

        let verifier = try XCTUnwrap(StreamingBinaryVerifier(onePassBody: Array(ops.suffix(from: 2))))
        verifier.update(data)
        XCTAssertEqual(verifier.verify(signatureBody: parsed.body, publicKey: .ed25519(key.publicKey)), true,
                       "v6 streamed signature must verify through the streaming verifier")

        // Signer key ID is the leading 8 octets of the fingerprint.
        XCTAssertEqual(verifier.signerKeyID, Array(fp.prefix(8)))

        // A tampered document must NOT verify.
        let v2 = try XCTUnwrap(StreamingBinaryVerifier(onePassBody: Array(ops.suffix(from: 2))))
        var bad = data
        bad[0] = bad[0] &+ 1
        v2.update(bad)
        XCTAssertNotEqual(v2.verify(signatureBody: parsed.body, publicKey: .ed25519(key.publicKey)), true,
                          "a modified document must fail v6 verification")
    }
}
