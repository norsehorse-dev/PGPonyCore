// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// BrainpoolKeygenTests.swift
// PGPonyCoreTests
//
// 8.4.0 build 7 wave 2 (plan K3, Android 4.6.0 item 13): brainpool ECDH and
// the LibrePGP ML-KEM + brainpool composite.
//
// ECDH: the RFC 7027 appendix A vectors on all three curves (public keys and
// the shared point from both sides), checked through the constant-time
// ladder (BrainpoolECDH, BrainpoolCurve.multiplySecret), which must also agree
// with the variable-time verifier arithmetic for other scalars and refuse an
// off-curve peer. KDF: the ECC key share for ky768_bp256 (SHA3-256) and
// ky1024_bp384 (SHA3-512) over the RFC 7027 points, against Python's hashlib.
// Keys: ky768_bp256 (the new picker entry) and ky1024_bp384 generate with the
// v5 algorithm 8 subkey shape gpg and Android write (brainpool OID, a 515-bit
// minimal MPI for the 65-octet point), round-trip encrypt and decrypt,
// protected and not, and label themselves. No gpg 2.5 was available to make a
// GnuPG-side fixture; the Android 4.7.0 item 8 Kleopatra check stands for
// wire compatibility, as it does on Android.
//
// Ported from the app's Build7BrainpoolKeygenTests.swift. The tests there that need the app's
// storage, models or secret-key unlock stay in the app.

import XCTest
import CryptoKit
@testable import PGPonyCore

@MainActor
final class BrainpoolKeygenTests: XCTestCase {

    private func bytes(_ hex: String) -> [UInt8] {
        var out: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            out.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    private func hexString(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - RFC 7027 ECDH vectors

    private struct ECDHVector {
        let curve: BrainpoolCurve
        let dA: String
        let qA: String
        let dB: String
        let qB: String
        let z: String
    }

    private let rfc7027: [ECDHVector] = [
        ECDHVector(curve: .p256r1,
                   dA: "81db1ee100150ff2ea338d708271be38300cb54241d79950f77b063039804f1d",
                   qA: "0444106e913f92bc02a1705d9953a8414db95e1aaa49e81d9e85f929a8e3100be58ab4846f11caccb73ce49cbdd120f5a900a69fd32c272223f789ef10eb089bdc",
                   dB: "55e40bc41e37e3e2ad25c3c6654511ffa8474a91a0032087593852d3e7d76bd3",
                   qB: "048d2d688c6cf93e1160ad04cc4429117dc2c41825e1e9fca0addd34e6f1b39f7b990c57520812be512641e47034832106bc7d3e8dd0e4c7f1136d7006547cec6a",
                   z: "0489afc39d41d3b327814b80940b042590f96556ec91e6ae7939bce31f3a18bf2b49c27868f4eca2179bfd7d59b1e3bf34c1dbde61ae12931648f43e59632504de"),
        ECDHVector(curve: .p384r1,
                   dA: "1e20f5e048a5886f1f157c74e91bde2b98c8b52d58e5003d57053fc4b0bd65d6f15eb5d1ee1610df870795143627d042",
                   qA: "0468b665dd91c195800650cdd363c625f4e742e8134667b767b1b476793588f885ab698c852d4a6e77a252d6380fcaf06855bc91a39c9ec01dee36017b7d673a931236d2f1f5c83942d049e3fa20607493e0d038ff2fd30c2ab67d15c85f7faa59",
                   dB: "032640bc6003c59260f7250c3db58ce647f98e1260acce4acda3dd869f74e01f8ba5e0324309db6a9831497abac96670",
                   qB: "044d44326f269a597a5b58bba565da5556ed7fd9a8a9eb76c25f46db69d19dc8ce6ad18e404b15738b2086df37e71d1eb462d692136de56cbe93bf5fa3188ef58bc8a3a0ec6c1e151a21038a42e9185329b5b275903d192f8d4e1f32fe9cc78c48",
                   z: "040bd9d3a7ea0b3d519d09d8e48d0785fb744a6b355e6304bc51c229fbbce239bbadf6403715c35d4fb2a5444f575d4f420df213417ebe4d8e40a5f76f66c56470c489a3478d146decf6df0d94bae9e598157290f8756066975f1db34b2324b7bd"),
        ECDHVector(curve: .p512r1,
                   dA: "16302ff0dbbb5a8d733dab7141c1b45acbc8715939677f6a56850a38bd87bd59b09e80279609ff333eb9d4c061231fb26f92eeb04982a5f1d1764cad57665422",
                   qA: "040a420517e406aac0acdce90fcd71487718d3b953efd7fbec5f7f27e28c6149999397e91e029e06457db2d3e640668b392c2a7e737a7f0bf04436d11640fd09fd72e6882e8db28aad36237cd25d580db23783961c8dc52dfa2ec138ad472a0fcef3887cf62b623b2a87de5c588301ea3e5fc269b373b60724f5e82a6ad147fde7",
                   dB: "230e18e1bcc88a362fa54e4ea3902009292f7f8033624fd471b5d8ace49d12cfabbc19963dab8e2f1eba00bffb29e4d72d13f2224562f405cb80503666b25429",
                   qB: "049d45f66de5d67e2e6db6e93a59ce0bb48106097ff78a081de781cdb31fce8ccbaaea8dd4320c4119f1e9cd437a2eab3731fa9668ab268d871deda55a5473199f2fdc313095bcdd5fb3a91636f07a959c8e86b5636a1e930e8396049cb481961d365cc11453a06c719835475b12cb52fc3c383bce35e27ef194512b71876285fa",
                   z: "04a7927098655f1f9976fa50a9d566865dc530331846381c87256baf3226244b76d36403c024d7bbf0aa0803eaff405d3d24f11a9b5c0bef679fe1454b21c4cd1f7db71c3def63212841c463e881bdcf055523bd368240e6c3143bd8def8b3b3223b95e0f53082ff5e412f4222537a43df1c6d25729ddb51620a832be6a26680a2"),
    ]

    func testRFC7027PublicKeysAndSharedPoints() throws {
        for v in rfc7027 {
            let name = v.curve.name.rawValue
            XCTAssertEqual(hexString(try BrainpoolECDH.publicPoint(curve: v.curve, scalar: bytes(v.dA))), v.qA, name)
            XCTAssertEqual(hexString(try BrainpoolECDH.publicPoint(curve: v.curve, scalar: bytes(v.dB))), v.qB, name)
            XCTAssertEqual(hexString(try BrainpoolECDH.sharedPoint(curve: v.curve, scalar: bytes(v.dA), peerPoint: bytes(v.qB))),
                           v.z, name)
            XCTAssertEqual(hexString(try BrainpoolECDH.sharedPoint(curve: v.curve, scalar: bytes(v.dB), peerPoint: bytes(v.qA))),
                           v.z, name)
        }
    }

    func testAnOffCurvePeerIsRefused() {
        for v in rfc7027 {
            var peer = bytes(v.qB)
            peer[peer.count - 1] ^= 0x01
            XCTAssertThrowsError(try BrainpoolECDH.sharedPoint(curve: v.curve, scalar: bytes(v.dA), peerPoint: peer))
            XCTAssertThrowsError(try BrainpoolECDH.sharedPoint(curve: v.curve, scalar: bytes(v.dA),
                                                                peerPoint: Array(bytes(v.qB).dropFirst())))
        }
    }

    func testTheLadderAgreesWithTheVerifierArithmetic() throws {
        for curve in BrainpoolCurve.all {
            let g = curve.generator
            for k in [BigUInt(1), BigUInt(2), BigUInt(3), curve.order - BigUInt(1),
                      BigUInt(bytes: Array(SHA512.hash(data: Data(curve.name.rawValue.utf8))).prefix(curve.fieldSize).map { $0 & 0x7F })] {
                let secret = try XCTUnwrap(k.bytes(length: curve.fieldSize))
                XCTAssertEqual(curve.multiplySecret(g, by: secret), curve.multiply(g, by: k), curve.name.rawValue)
            }
            XCTAssertNil(curve.multiplySecret(g, by: curve.order.minimalBytes), "n G is infinity")
            XCTAssertNil(curve.multiplySecret(g, by: [UInt8](repeating: 0, count: curve.fieldSize)), "0 G is infinity")
            XCTAssertEqual(curve.multiplySecret(g, by: [0, 0, 5]), curve.multiply(g, by: BigUInt(5)), "leading zero octets")
        }
    }

    func testGeneratedKeyPairsAreConsistent() throws {
        for curve in [BrainpoolCurve.p256r1, .p384r1] {
            let pair = try BrainpoolECDH.generateKeyPair(curve: curve)
            XCTAssertEqual(pair.scalar.count, curve.fieldSize)
            let scalar = BigUInt(bytes: pair.scalar)
            XCTAssertFalse(scalar.isZero)
            XCTAssertTrue(scalar < curve.order)
            XCTAssertNotNil(curve.decodePoint(pair.point))
            XCTAssertEqual(try BrainpoolECDH.publicPoint(curve: curve, scalar: pair.scalar), pair.point)
            let other = try BrainpoolECDH.generateKeyPair(curve: curve)
            XCTAssertEqual(try BrainpoolECDH.sharedPoint(curve: curve, scalar: pair.scalar, peerPoint: other.point),
                           try BrainpoolECDH.sharedPoint(curve: curve, scalar: other.scalar, peerPoint: pair.point))
        }
    }

    // MARK: - LibrePGP suites

    func testSuiteTable() {
        XCTAssertEqual(LibrePGPSuite.fromOidTail(BrainpoolCurve.p256r1.oid), .ky768_bp256)
        XCTAssertEqual(LibrePGPSuite.fromOidTail(BrainpoolCurve.p384r1.oid), .ky1024_bp384)
        XCTAssertNil(LibrePGPSuite.fromOidTail(BrainpoolCurve.p512r1.oid), "gpg pairs no ML-KEM with P512r1")
        XCTAssertEqual(LibrePGPSuite.ky768_bp256.secretBytes, 96)
        XCTAssertEqual(LibrePGPSuite.ky1024_bp384.secretBytes, 112)
        XCTAssertEqual(LibrePGPSuite.ky768_bp256.eccPointBytes, 65)
        XCTAssertEqual(LibrePGPSuite.ky1024_bp384.eccPointBytes, 97)
        XCTAssertEqual(LibrePGPSuite.ky768_bp256.mlkemLevel, .mlkem768)
        XCTAssertEqual(LibrePGPSuite.ky1024_bp384.mlkemLevel, .mlkem1024)
        let point = [UInt8](repeating: 4, count: 65)
        XCTAssertEqual(LibrePGPSuite.ky768_bp256.normalizePoint(point), point, "a brainpool point is used as written")
        XCTAssertEqual(LibrePGPSuite.ky768_cv25519.eccPointBytes, 32)
        XCTAssertEqual(LibrePGPSuite.ky1024_cv448.eccPointBytes, 56)
    }

    func testECCKeyShareKDFMatchesGnuPGsHashChoice() {
        // ecc_ss = SHA3(shared point || ephemeral || recipient public), with the
        // RFC 7027 points standing in (B the sender's ephemeral, A the recipient).
        let p256 = rfc7027[0]
        XCTAssertEqual(hexString(LibrePGPSuite.ky768_bp256.eccKemKdf(
            rawECDH: bytes(p256.z), eccCipherText: bytes(p256.qB), eccPublic: bytes(p256.qA))),
            "af00f28c0dcb769389f6050f0ae2cc08329fd086e46167e00685c70d446bedde")
        let p384 = rfc7027[1]
        XCTAssertEqual(hexString(LibrePGPSuite.ky1024_bp384.eccKemKdf(
            rawECDH: bytes(p384.z), eccCipherText: bytes(p384.qB), eccPublic: bytes(p384.qA))),
            "cef432652cb28df8e1a792b7782c9690a79162ccb6a12454432317cb72cc544ceedc58bde75cb886b98277ea081c27fc479d9cb75d2f4e209b9454433b11ae88")
    }

    // MARK: - Key generation and round trips

    private func librePGPKey(_ suite: LibrePGPSuite, passphrase: String?) throws -> Ed25519KeyGeneratorResult {
        try Ed25519KeyGenerator.generate(
            name: "LibrePGP Brainpool", email: "bp@pgpony.test",
            passphrase: passphrase, expirationInterval: nil,
            pqcEncryption: true, pqcSuite: suite)
    }

    func testGeneratedKeysHaveGnuPGsShape() throws {
        for (suite, curve) in [(LibrePGPSuite.ky768_bp256, BrainpoolCurve.p256r1), (.ky1024_bp384, .p384r1)] {
            let result = try librePGPKey(suite, passphrase: nil)
            let packets = try OpenPGPPacketParser.parsePackets(data: [UInt8](result.publicKeyData))
            XCTAssertEqual(packets.first { $0.tag == 6 }?.body[5], 22, "a v4 Ed25519 primary")
            let sub = try XCTUnwrap(packets.first { $0.tag == 14 && $0.body.count > 11 && $0.body[0] == 5 && $0.body[5] == 8 })
            XCTAssertEqual(Int(sub.body[10]), curve.oid.count)
            XCTAssertEqual(Array(sub.body[11..<(11 + curve.oid.count)]), curve.oid)
            // The point MPI: minimal bit length of 0x04 || X || Y.
            let mpi = 11 + curve.oid.count
            let bits = Int(sub.body[mpi]) << 8 | Int(sub.body[mpi + 1])
            XCTAssertEqual(bits, (curve.pointLength - 1) * 8 + 3)
            XCTAssertEqual(sub.body[mpi + 2], 0x04)
            let point = Array(sub.body[(mpi + 2)..<(mpi + 2 + curve.pointLength)])
            XCTAssertNotNil(curve.decodePoint(point))

            let decryptionKey = try XCTUnwrap(LibrePGPDecryptService.extractDecryptionKey(
                privateKeyData: [UInt8](result.privateKeyData)))
            XCTAssertEqual(decryptionKey.suite, suite)
            XCTAssertEqual(decryptionKey.eccSecret.count, curve.fieldSize)
            XCTAssertEqual(decryptionKey.eccPublic, point)
            XCTAssertEqual(try BrainpoolECDH.publicPoint(curve: curve, scalar: decryptionKey.eccSecret), point,
                           "the stored scalar derives the packet's point")

            let recipient = try LibrePGPEncryptService.findRecipient(publicKeyData: [UInt8](result.publicKeyData))
            XCTAssertEqual(recipient.suite, suite)
            XCTAssertEqual(recipient.eccPublic, point)
        }
    }

    func testRoundTrips() throws {
        for suite in [LibrePGPSuite.ky768_bp256, .ky1024_bp384] {
            for passphrase in [nil, "brainpool-pass"] as [String?] {
                let result = try librePGPKey(suite, passphrase: passphrase)
                let plaintext = "ML-KEM and brainpool, there and back"
                let message = try LibrePGPEncryptService.encrypt(
                    plaintext: Array(plaintext.utf8), publicKeyData: [UInt8](result.publicKeyData))

                // The PKESK carries the ephemeral as a minimal MPI of the
                // uncompressed point, as gpg writes it.
                let pkesk = try XCTUnwrap(try OpenPGPPacketParser.parsePackets(data: message).first { $0.tag == 1 })
                let curve = try XCTUnwrap(suite.brainpoolCurve)
                let bits = Int(pkesk.body[10]) << 8 | Int(pkesk.body[11])
                XCTAssertEqual(bits, (curve.pointLength - 1) * 8 + 3)
                XCTAssertEqual(pkesk.body[12], 0x04)

                let decrypted = try LibrePGPDecryptService.decrypt(
                    messageData: message, secretKeyData: [UInt8](result.privateKeyData), passphrase: passphrase)
                XCTAssertEqual(String(decoding: decrypted, as: UTF8.self), plaintext)
                if passphrase != nil {
                    XCTAssertThrowsError(try LibrePGPDecryptService.decrypt(
                        messageData: message, secretKeyData: [UInt8](result.privateKeyData), passphrase: "wrong"))
                }
            }
        }
    }

    func testATamperedEphemeralIsRefused() throws {
        let result = try librePGPKey(.ky768_bp256, passphrase: nil)
        var message = try LibrePGPEncryptService.encrypt(
            plaintext: Array("tamper".utf8), publicKeyData: [UInt8](result.publicKeyData))
        // PKESK body: ver(1) keyID(8) algo(1) bits(2), then the 65-octet
        // point; change its last Y octet so it leaves the curve.
        let pkesk = try XCTUnwrap(try OpenPGPPacketParser.parsePackets(data: message).first { $0.tag == 1 })
        let bodyStart = try XCTUnwrap(findSubsequence(pkesk.body, in: message))
        message[bodyStart + 12 + 64] ^= 0x01
        XCTAssertThrowsError(try LibrePGPDecryptService.decrypt(
            messageData: message, secretKeyData: [UInt8](result.privateKeyData)))
    }

    private func findSubsequence(_ needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard needle.count <= haystack.count else { return nil }
        for start in 0...(haystack.count - needle.count) where haystack[start] == needle[0] {
            if Array(haystack[start..<(start + needle.count)]) == needle { return start }
        }
        return nil
    }
}
