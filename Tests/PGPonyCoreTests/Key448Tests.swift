// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// Key448Tests.swift
// PGPonyCoreTests
//
// 8.4.0 build 9 (plan 5l): Ed448 + X448 keys in both wire forms, end to end.
//
//   LibrePGP v5 (fixtures made by gpg 2.4.4, Resources/librepgp-v5-448):
//     import (fingerprints and key IDs equal to gpg's), unprotected and
//     protected secret unlock, decrypt (OCB tag 20, SEIPD v1, two recipients,
//     signed, a protected key), verify (cleartext, inline, detached), the
//     wrong-key error, encrypt and sign round trips, and v5 fingerprinting,
//     the X448 KDF and key wrap and v5 signature hashing as known answers.
//   RFC 9580 v6 Ed448 (28) + X448 (26) (fixtures made by Sequoia through
//     pysequoia 0.1.35, Resources/rfc9580-448): the same set.
//
// "mirror-*" fixtures and the signature known answers were made by a Python
// mirror of this build's Swift code and checked with gpg --decrypt /
// gpg --verify (v5) and Sequoia (v6) before they were committed; a Swift
// signature equal to a known answer byte for byte is one those tools accept
// (Ed448 is deterministic).
//
// Ported from the app's Build9Key448Tests.swift. The tests there that need the app's
// storage, models or secret-key unlock stay in the app.

import XCTest
import CryptoKit
@testable import PGPonyCore

@MainActor
final class Key448Tests: XCTestCase {

    /// Armored fixture as binary packets.
    private func binary(_ data: Data) throws -> [UInt8] {
        let text = try XCTUnwrap(String(data: data, encoding: .utf8))
        return Array(try OpenPGPPacketParser.dearmor(text))
    }

    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02X", $0) }.joined() }

    private func bytes(_ hex: String) -> [UInt8] {
        var out: [UInt8] = []
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            out.append(UInt8(hex[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    /// The fixtures' keys expire in October 2027; bindings are judged at a
    /// fixed date inside their lifetime so these tests do not age out.
    private let judged = Date(timeIntervalSince1970: 1_793_400_000)

    // gpg 2.4.4 --with-subkey-fingerprints, as listed when the fixtures were made.
    private let v5Primary = "A837E056E0DBB5B075A56588CB5147524708C5982863B6748AAF9371135605A6"
    private let v5X448 = "C4D93FB01EC7DDC01438F21CDBB22CA8742586F05FD141A6BE8FF1A0456401F7"
    private let v5Auth = "CAFC27C5C6A112F73D2FEFB0EF6A69ECF6D848F2"
    private let v5pPrimary = "748D4D6CD0E4C3F4A2A70952A21DF48E5DEDF8FDA5180D9C52DE79B471C3AA93"
    private let v5pX448 = "91CD73962007FC3ACFAC02EEC00675644D1FE7293BBBD120C6F9CC235E60B04C"
    private let v5Passphrase = "v5 test passphrase"
    // Sequoia (pysequoia Cert.fingerprint and its packet dump).
    private let v6Primary = "54C3CE9AA1A6D968A24D08D90D506B7D0F6DABFB6CEED17810FFFEF59DFC1AA7"
    private let v6X448 = "DC112980CF88D87EB68DF58FE363145C309A75F7C109F90D49D8A8A457A585F9"
    private let v6Ed448Sign = "3A0FEE3D503BCF5A1B1DDD6EBC886A31D92C4233AA80395085812416E6D2ECC8"

    private let message = "v5 interop test message.\nSecond line.\n"

    /// RFC 6637 KDF with the leftmost 20 octets of the v5 fingerprint, SHA-512
    /// and an AES-256 KEK (the fixture's 03 01 0a 09), then AES key unwrap.
    /// Values from the Python reference (cryptography 50, X448 + AES-KW).
    func testX448ECDHKDFAndUnwrapKnownAnswer() throws {
        let recipientScalar = Array(UInt8(1)...UInt8(56))
        let ephemeral = bytes("2B5FDBBEAEF3D235310B5A7F550D4744532C01FB3BD09397104F85DFDB330E3A00B8C60B5EF3BCA001854A5A09F74ED492A887E794D3067B")
        let shared = bytes("498BB97E2B43011265E3734F40411B58CC5DC5A7F56286319050144CAF4D55109D95E68E923F02CA0A68B2DF59793756EB5280F62C54962F")
        let wrapped = bytes("72882DA0B14BFA108DD7FB11B53622781C9719A1E65892C6A5B47D24314BF5D5200CA376F508D641B0340090552A2C8B")
        let fp20 = bytes(String(v5X448.prefix(40)))
        let sessionKey = Array(UInt8(1)...UInt8(32))

        XCTAssertEqual(Array(try X448.sharedSecret(privateKey: Data(recipientScalar), publicKey: Data(ephemeral))), shared)
        let fromShared = try Cv25519ECDHService.sessionKeyFromSharedSecret(
            sharedSecret: shared, wrappedSessionKey: wrapped, recipientFingerprint: fp20,
            kdfHashID: 10, kdfCipherID: 9, includesAlgorithmID: true, curveOID: OpenPGP448.x448OID)
        XCTAssertEqual(fromShared.algorithmID, 9)
        XCTAssertEqual(fromShared.sessionKey, sessionKey)
        // Bare and 0x40-prefixed ephemerals both open it.
        for eph in [ephemeral, [0x40] + ephemeral] {
            let r = try Cv25519ECDHService.decryptSessionKey(
                ephemeralPublicKey: eph, wrappedSessionKey: wrapped, recipientPrivateKey: recipientScalar,
                recipientFingerprint: fp20, kdfHashID: 10, kdfCipherID: 9, curve: .x448)
            XCTAssertEqual(r.sessionKey, sessionKey)
        }
        // A different key fails the unwrap: the normal wrong-key result.
        XCTAssertThrowsError(try Cv25519ECDHService.decryptSessionKey(
            ephemeralPublicKey: ephemeral, wrappedSessionKey: wrapped, recipientPrivateKey: Array(UInt8(2)...UInt8(57)),
            recipientFingerprint: fp20, kdfHashID: 10, kdfCipherID: 9, curve: .x448))
    }

    /// RFC 9580 5.1.7: HKDF-SHA512 over ephemeral | recipient | shared with
    /// "OpenPGP X448", AES-256 key wrap of the bare session key.
    func testNativeX448KDFAndWrapKnownAnswer() throws {
        let recipientScalar = Array(UInt8(1)...UInt8(56))
        let recipientPublic = bytes("BDA7365BA1BD9A66F2EF38DB6EC5AC5FAD5452E990D8B2F88F721FD53363237E775F65205D1D4667D473F0E1F4C57694D2D802E8DFF06026")
        let ephemeral = bytes("2B5FDBBEAEF3D235310B5A7F550D4744532C01FB3BD09397104F85DFDB330E3A00B8C60B5EF3BCA001854A5A09F74ED492A887E794D3067B")
        let shared = bytes("498BB97E2B43011265E3734F40411B58CC5DC5A7F56286319050144CAF4D55109D95E68E923F02CA0A68B2DF59793756EB5280F62C54962F")
        XCTAssertEqual(Array(try X448.publicKey(for: Data(recipientScalar))), recipientPublic)
        XCTAssertEqual(hex(OpenPGP448.nativeKEK(ephemeral: ephemeral, recipientPublic: recipientPublic, shared: shared)),
                       "DE154CD54DCDBCCB32559F4750F1C996D71BAE6FA91C8B644CB995B6645653CB")
        let wrapped = bytes("0A8EA273B201F33F179467B6BD0C581974D0D1D36DEDF8D8752EC725DCF7451813D69C3C2A045F37")
        XCTAssertEqual(try OpenPGP448.nativeUnwrap(ephemeral: ephemeral, wrapped: wrapped, scalar: recipientScalar),
                       Array(UInt8(1)...UInt8(32)))
        // And a fresh wrap opens with the recipient's scalar.
        let fresh = try OpenPGP448.nativeWrap(sessionKey: Array(UInt8(1)...UInt8(32)), recipientPublic: recipientPublic)
        XCTAssertEqual(try OpenPGP448.nativeUnwrap(ephemeral: fresh.ephemeral, wrapped: fresh.wrapped, scalar: recipientScalar),
                       Array(UInt8(1)...UInt8(32)))
    }

    /// v5 hashing: the literal metadata goes after the hashed area (zeros for
    /// a detached signature), then 0x05 0xFF and an 8-octet length.
    func testV5SignatureTrailer() {
        XCTAssertEqual(OpenPGP448.v5Trailer(signatureType: 0x00, hashedPortionLength: 0x3D, literalMetadata: nil),
                       [0, 0, 0, 0, 0, 0, 5, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0x3D])
        XCTAssertEqual(OpenPGP448.v5Trailer(signatureType: 0x01, hashedPortionLength: 1,
                                            literalMetadata: OpenPGP448.cleartextLiteralMetadata),
                       [0x74, 0, 0, 0, 0, 0, 5, 0xFF, 0, 0, 0, 0, 0, 0, 0, 1])
        // A key binding hashes no literal metadata.
        XCTAssertEqual(OpenPGP448.v5Trailer(signatureType: 0x18, hashedPortionLength: 2, literalMetadata: [1, 2]),
                       [5, 0xFF, 0, 0, 0, 0, 0, 0, 0, 2])
        XCTAssertEqual(OpenPGP448.literalMetadata(ofLiteralBody: [0x62, 3, 0x61, 0x62, 0x63, 1, 2, 3, 4, 9, 9]),
                       [0x62, 3, 0x61, 0x62, 0x63, 1, 2, 3, 4])
    }

    private func decrypt(_ message: [UInt8], _ keys: [Cv25519DecryptionKey]) throws -> OpenPGPPacketParser.DecryptedMessageContents {
        try OpenPGPPacketParser.decryptMessageReturningInnerPackets(messageData: Data(message), decryptionKeys: keys)
    }

    private func verify(_ sigBody: [UInt8], document: [UInt8], ring: [UInt8], meta: [UInt8]?) throws -> Bool {
        let sig = try OpenPGPPacketParser.parseSignaturePacket(body: sigBody)
        let key = try XCTUnwrap(OpenPGP448.signerPublicKey(publicRing: ring, issuerFingerprint: sig.issuerFingerprint,
                                                           issuerKeyID: sig.issuerKeyID ?? []))
        return try OpenPGPPacketParser.verifyEd25519Signature(signature: sig, document: document, publicKey: key,
                                                              literalMetadata: meta)
    }

    private func signingInfo(_ key: Ed448SigningKey) -> Ed25519SigningInfo {
        var info = Ed25519SigningInfo(privateKey: Curve25519.Signing.PrivateKey(), keyID: key.keyID, fingerprint: key.fingerprint)
        info.ed448 = key
        return info
    }
}
