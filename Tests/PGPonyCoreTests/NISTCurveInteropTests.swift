// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// NISTCurveInteropTests.swift
// PGPony — test vectors for NIST P-256/384/521 operational support (issue #3).
//
// Provenance: three throwaway keypairs generated with GnuPG 2.2.41 (libgcrypt
// 1.8.10) on 2026-09-10, each an ECDSA primary [SC] plus an ECDH subkey [E] on
// the same curve — the shape `gpg --expert --full-gen-key` produces for ECC,
// and the shape a NIST-curve hardware signer exports. For each curve the
// vectors are: the primary and subkey public-key packet bodies, the secret
// subkey packet body, a detached signature over `signedDocument`, and a
// complete encrypted message whose plaintext is `expectedPlaintext`.
//
// Both operations were confirmed against GnuPG before being committed here:
// `gpg --verify` reports a good signature for all three, and `gpg --decrypt`
// returns the expected plaintext for all three.
//
// On secrets: the secret subkey packets are real key material and are included
// deliberately. These three keys were generated for this file, have never been
// used for anything, are unprotected (no passphrase, so no prompt or PIN is
// needed at test time) and their user IDs are all @example.invalid. Nothing
// here is, or ever was, a live secret.
//
// 8.3.0: the operational work landed, so the two tests that were XCTSkips
// now assert what they named (ECDSA verify and ECDH decrypt on all three
// curves), and the recognition tests pin the new labels: a NIST key is
// .nistP256 / .nistP384 / .nistP521 rather than .otherEC, and the three
// curves are no longer recognition-only (brainpool still is).
//
// The recognition tests also pin the two facts that made the operational
// work more than a type swap:
//   * the curve check is load-bearing for algo 18, because a NIST ECDH subkey
//     and a Cv25519 subkey share that algorithm ID; and
//   * the RFC 6637 KDF parameters are curve-specific (SHA-256/384/512 and
//     AES-128/192/256), so a deriveKEK that only branches SHA-256 cannot
//     serve P-384 or P-521.
//
// Until 8.3.0 the two operational tests were skipped: decryption was typed
// `[Cv25519DecryptionKey]` with a 32-byte X25519 scalar, and a P-521 scalar is
// 66 bytes. The key now carries its curve and a scalar of the curve's size.

import XCTest
@testable import PGPonyCore

final class NISTCurveInteropTests: XCTestCase {

    private let signedDocument = Array("PGPonyCore NIST curve interop test vector\n".utf8)
    private let expectedPlaintext = "NIST ECDH decrypt works"

    // MARK: - NIST P-256
    private let p256PrimaryBody = hex("""
046aa358c413082a8648ce3d03010702030437f55aad689bd4554b49e818e49600e5f59b93e33f
9594851131ecff8c078ba00522b0b8ec8eb15db9e7fcbd17cd2df4eefe954f6cf005a1cbb75632
8a4043a8
""")
    private let p256SubkeyBody = hex("""
046aa358c412082a8648ce3d030107020304af221eaef0e8b1f7d9f21f83a64e07c4bf2da07e51
b5d9a49a854ea913adc65c11cf411ea3a82ab05e5193e0297ae36510ceba30a1c1525189b4c0ac
819fb35803010807
""")
    private let p256SecretSubkeyBody = hex("""
046aa358c412082a8648ce3d030107020304af221eaef0e8b1f7d9f21f83a64e07c4bf2da07e51
b5d9a49a854ea913adc65c11cf411ea3a82ab05e5193e0297ae36510ceba30a1c1525189b4c0ac
819fb358030108070000fe3d2c754d8f71eaa4de54de32a764b6e801319afba9d6384fa5b5e5c3
e721123211bd
""")
    private let p256DetachedSig = hex("""
04001308003716210473dcd95cc9babbec974ea6d3f51a7d1775a0c9e205026aa35944191c6e69
737470323536406578616d706c652e696e76616c6964000a0910f51a7d1775a0c9e2b9a000fb04
a591aafc71f247dcb55073767454fc91f3d21014167f20a63ae8c462079dd200ff4420bbba4662
edf32399b0e736163259475fb6a728f6da8ab2a909e78307db34
""")
    private let p256EncryptedMessage = hex("""
847e03b33f999b657f31c612020304bf69d349bab7d3d226898eddee0ad307825a71d463bc91bd
ff49393f3c1cddcb6595f26635d85252d8d24f50d970b00439a1bc5cae0ff0e57cf39be4c0512f
2e308ac3ae9d55b721df267eb89ecb59e6ad64370118913ab3803ee760d614096b265bf3823865
ff5c57b2421376eed53e80d25201b80aa318f9b2055ce8ff6a286ef1859510a576900d8b3581a2
b4e3e9ff29d20303c707b7412429fcc37eee9ffc16739387ef4c085e26ae130f7570511334ad18
c1757f3fb700d346d1e70d4e3a76f96d3a
""")

    // MARK: - NIST P-384
    private let p384PrimaryBody = hex("""
046aa358c413052b81040022030304ea3f41087e082ebc569b8a2a2b31d321b838476596348111
02754b794ce6ce570c64204f72533ea71153e0a7985e95e62537e50378eef0807f833e61be8705
b09d5e335020cae174a18566596bf01c63418045acadb87540961e6165e25983bf
""")
    private let p384SubkeyBody = hex("""
046aa358c412052b81040022030304a3a9451a69ac05fd3f38de60ba37ea1cde6882d0b1d1e16f
2f8031a3a08469171c22bcb0b97eb4eb50134a3a8a35d47f02943417443a0bc83f54f4eda86239
c6dce07edb34a4bc2150d5c3d9c2882cda93c066e62f4444cfeeab201faf01d93e03010908
""")
    private let p384SecretSubkeyBody = hex("""
046aa358c412052b81040022030304a3a9451a69ac05fd3f38de60ba37ea1cde6882d0b1d1e16f
2f8031a3a08469171c22bcb0b97eb4eb50134a3a8a35d47f02943417443a0bc83f54f4eda86239
c6dce07edb34a4bc2150d5c3d9c2882cda93c066e62f4444cfeeab201faf01d93e030109080001
7d1dafaa3f884f391f852dfde093e439357afa74945550148359c2de89412fbd487712d8be5ef1
c27a45949a1231df39691766
""")
    private let p384DetachedSig = hex("""
040013090037162104335d33c6360778fe6b78050399a60b1cb9dcd47005026aa35944191c6e69
737470333834406578616d706c652e696e76616c6964000a091099a60b1cb9dcd4705acf017e26
4ca03a0f24bf6df5a349a5e90e250930b3cb5030e449e3c6feda6468804e7bd9721bbc1a06e65c
48d5dc16a656a07f017f5c32e7ed6072721574ccea61dd6865d1947920e2dc370e2fa33570e643
71c3d10730c5a602fcb0ad995c06eee31222e3
""")
    private let p384EncryptedMessage = hex("""
849e037ef0b4726928256c12030304046e0b40ad70082697a9adb9ef26a6d1d0f6eb09d23674af
0127fa4f0c48c3af5d265b12f64908ee86881b39c93fe519752dcf2dd6f764ac4876e8800c145f
b841a38dd76a8c759062d35cc579db6c08b1334d1bf3241bacbac7d4d2d35079a530f10d326c02
ef7d0d02a3c074bc4658196b0a35209ea4cbc22f75d73781f365da222156877881e5e3e317be8b
991b48ecd25201f24db3d6f1ac5ec17a84176b406107a644384eefaa15044941b7d31f96d0449d
2cce2d47f0a42898453f0c015067f322d4a4d7262eb7c01182456cf5e77ca052bdcccdadd52824
759ddad9c3898507bf9d
""")

    // MARK: - NIST P-521
    private let p521PrimaryBody = hex("""
046aa358ab13052b8104002304230400074d63476b2ffa6dbd0245ef2d51bc3149c93d75ab0d03
7bfbde1609619ae9aca9c29e15f3af8df09c80d6b8d30a0af75dc99e64ebe557a277becadfa27c
76e99a00222a397e0af569c2110a4db78c9af280309f402dc59eb7d09b75660bc8c974c3678bb2
473aad65790fd492acb09649a08e67152f4fbccfb14fed16132f16f2af21
""")
    private let p521SubkeyBody = hex("""
046aa358ab12052b8104002304230400c86a7687dd04c38f6d5160655089d1272d82fa6d5a7825
9c504b5a7c07e5bc1ec702369faa2296100b0a3aaf2d9700af40bcf0c32d43a70cf45abc52f954
2f4185004847d620fad650d7eedbe20f39be95a10787d26dc5657772c205249b4906112baed44f
9ff0906ba575a6c6f0483d88990fa50722efe55608a7e31d86a499efc27903010a09
""")
    private let p521SecretSubkeyBody = hex("""
046aa358ab12052b8104002304230400c86a7687dd04c38f6d5160655089d1272d82fa6d5a7825
9c504b5a7c07e5bc1ec702369faa2296100b0a3aaf2d9700af40bcf0c32d43a70cf45abc52f954
2f4185004847d620fad650d7eedbe20f39be95a10787d26dc5657772c205249b4906112baed44f
9ff0906ba575a6c6f0483d88990fa50722efe55608a7e31d86a499efc27903010a0900020901e2
57368eca76eb2e2e9c15fd42d1dc9295a0f041208e62ffb49fed0cb180e6584b5ffcc74d6b1477
d38105f5719a113c4ba93746db64f55f0c8d40613de00e8fac20e9
""")
    private let p521DetachedSig = hex("""
0400130a003a1621049e4420f28449e5ca35acb1bdea8f26ed36bcb2f105026aa359451c1c7465
73742d766563746f72406578616d706c652e696e76616c6964000a0910ea8f26ed36bcb2f103af
0208de6cb445d149a74e68e2724348e7488478ab58fc106672367d0f36c63e1b7fcd29dfb71344
57ec7dde7347ccc704791f9fc5909901f1ce10e06a7a4b94eb9c0f4c020744c7eb70939376794b
bce35cedd6b4da00e1c0071ecd5a484baf99e3cc4ae662a1ca5653fc25cdbd5351cea996171853
57f22766dd2790a2b2203e2c405e8e40db
""")
    private let p521EncryptedMessage = hex("""
84c203992ff37b4663ff9512042304013a7e54820daea8632bea965a192258a98d54db340d7b61
bdbac6360313fa4f5d46f63dbb642e4a8fcac9b16e3017d23d89f272420bd822c0e931d81650f8
a53e4d001f4673eba39a40cdb4c202d6e207a8fc1589b8f9dd789ac05ff42f1d71e815c1bc190f
5d5822e6e344bc601aa4b8dbba9db07bda3c77f4d939514f4079ea4b218d30ca363d997c3a1e31
35070247dd6902e4e04686d98f4f08f97e7513ff9b8b29bfddd46a632e15c7268f0107e06bae59
c5d252015145b2dde266d6c6d7a1d9043970a979cd15356f4ff613c9c09c46cc4b5f99164a2806
65a72cbfbd8d0b5dd72a86230806edd8421f6bce349e95bfd1b827b0e63e15860d5a4fbdbfc44d
a832bf582946b5
""")


    // MARK: - Recognition (passes today)

    /// Every primary key packet is ECDSA (algo 19) and names its curve.
    func testPrimaryKeysRecogniseTheirCurve() {
        let cases: [(String, Data, ECCurve)] = [
            ("P-256", p256PrimaryBody, .nistP256),
            ("P-384", p384PrimaryBody, .nistP384),
            ("P-521", p521PrimaryBody, .nistP521),
        ]
        for (name, body, expected) in cases {
            let b = [UInt8](body)
            XCTAssertEqual(b[5], 19, "\(name) primary should be ECDSA (algo 19)")
            XCTAssertEqual(ECCurve.fromKeyPacketBody(b), expected,
                           "\(name) primary should be recognised as \(expected.displayName)")
        }
    }

    /// Every encryption subkey is ECDH (algo 18) and names its curve.
    func testSubkeysRecogniseTheirCurve() {
        let cases: [(String, Data, ECCurve)] = [
            ("P-256", p256SubkeyBody, .nistP256),
            ("P-384", p384SubkeyBody, .nistP384),
            ("P-521", p521SubkeyBody, .nistP521),
        ]
        for (name, body, expected) in cases {
            let b = [UInt8](body)
            XCTAssertEqual(b[5], 18, "\(name) subkey should be ECDH (algo 18)")
            XCTAssertEqual(ECCurve.fromKeyPacketBody(b), expected,
                           "\(name) subkey should be recognised as \(expected.displayName)")
        }
    }

    /// All six packets classify by their curve (8.3.0) rather than falling
    /// back to RSA (algo 19 -> nil) or being mislabeled Cv25519 (algo 18).
    func testNISTKeysClassifyByCurve() {
        let cases: [(Data, KeyAlgorithm)] = [
            (p256PrimaryBody, .nistP256), (p256SubkeyBody, .nistP256),
            (p384PrimaryBody, .nistP384), (p384SubkeyBody, .nistP384),
            (p521PrimaryBody, .nistP521), (p521SubkeyBody, .nistP521),
        ]
        for (body, expected) in cases {
            XCTAssertEqual(KeyAlgorithm.from(keyPacketBody: [UInt8](body)), expected)
        }
    }

    /// The three NIST curves are operational as of 8.3.0; brainpool stays
    /// recognition-only (CryptoKit has no brainpool).
    func testNISTCurvesAreOperational() {
        for curve in [ECCurve.nistP256, .nistP384, .nistP521] {
            XCTAssertFalse(curve.isRecognitionOnly, "\(curve.displayName) is operational")
        }
        for curve in [ECCurve.cv25519, .ed25519Legacy, .x25519, .ed25519] {
            XCTAssertFalse(curve.isRecognitionOnly)
        }
        for curve in [ECCurve.brainpoolP256r1, .brainpoolP384r1, .brainpoolP512r1] {
            XCTAssertTrue(curve.isRecognitionOnly, "\(curve.displayName) stays recognition-only")
        }
    }

    /// Algorithm ID 18 alone cannot distinguish a NIST ECDH subkey from a
    /// Cv25519 one: by ID the NIST subkey classifies as Cv25519, and only the
    /// curve OID separates them. Any routing that branches on the algorithm
    /// byte alone sends a NIST subkey into the 25519 path.
    func testCurveCheckIsLoadBearingForAlgo18() {
        XCTAssertEqual(KeyAlgorithm.from(algorithmID: 18, keyVersion: 4), .ed25519,
                       "algo 18 by itself still means Cv25519")
        XCTAssertEqual(KeyAlgorithm.from(keyPacketBody: [UInt8](p521SubkeyBody)), .nistP521,
                       "the curve OID is what tells the two apart")
    }

    /// RFC 6637 §12.5 fixes the KDF hash and KEK cipher per curve. Parsed off
    /// the real GnuPG subkeys: the last four bytes of an ECDH public-key packet
    /// are the KDF field — length (3), reserved (1), hash algorithm, symmetric
    /// algorithm. A `deriveKEK` that only branches SHA-256 cannot serve P-384
    /// or P-521.
    func testECDHKDFParametersAreCurveSpecific() {
        //                         (hash, symmetric)  8=SHA256 9=SHA384 10=SHA512
        //                                            7=AES128 8=AES192  9=AES256
        let cases: [(String, Data, UInt8, UInt8)] = [
            ("P-256", p256SubkeyBody,  8, 7),
            ("P-384", p384SubkeyBody,  9, 8),
            ("P-521", p521SubkeyBody, 10, 9),
        ]
        for (name, body, hash, sym) in cases {
            let b = [UInt8](body)
            let kdf = Array(b.suffix(4))
            XCTAssertEqual(kdf[0], 3, "\(name) KDF field length")
            XCTAssertEqual(kdf[1], 1, "\(name) KDF reserved byte")
            XCTAssertEqual(kdf[2], hash, "\(name) KDF hash algorithm")
            XCTAssertEqual(kdf[3], sym, "\(name) KEK symmetric algorithm")
        }
    }

    /// The detached signatures parse, and are ECDSA with the digest GnuPG pairs
    /// with each curve. `signatureData` is the (r, s) MPI pair the future
    /// ECDSA verify has to read — the same shape the v4 EdDSA path already
    /// handles, with field-width rather than 32-byte padding.
    func testDetachedSignaturesAreECDSAWithCurveMatchedDigest() throws {
        let cases: [(String, Data, UInt8)] = [
            ("P-256", p256DetachedSig,  8),
            ("P-384", p384DetachedSig,  9),
            ("P-521", p521DetachedSig, 10),
        ]
        for (name, sig, digest) in cases {
            let parsed = try OpenPGPPacketParser.parseSignaturePacket(body: [UInt8](sig))
            XCTAssertEqual(parsed.version, 4, "\(name) signature version")
            XCTAssertEqual(parsed.publicKeyAlgorithm, 19, "\(name) should be ECDSA")
            XCTAssertEqual(parsed.hashAlgorithm, digest, "\(name) digest algorithm")
            XCTAssertEqual(parsed.signatureType, 0x00, "\(name) binary document signature")
            XCTAssertFalse(parsed.signatureData.isEmpty, "\(name) carries (r, s)")
        }
    }

    /// Each encrypted message is a PKESK (tag 1) naming the ECDH subkey by key
    /// ID, followed by a SEIPD (tag 18). v3 PKESK layout is version (1), key ID
    /// (8), algorithm (1), so the key ID and algorithm are read directly rather
    /// than through parsePKESK, which is not NIST-aware yet.
    func testEncryptedMessagesTargetTheECDHSubkey() throws {
        let cases: [(String, Data, String)] = [
            ("P-256", p256EncryptedMessage, "b33f999b657f31c6"),
            ("P-384", p384EncryptedMessage, "7ef0b4726928256c"),
            ("P-521", p521EncryptedMessage, "992ff37b4663ff95"),
        ]
        for (name, message, subkeyID) in cases {
            let packets = try OpenPGPPacketParser.parsePackets(data: [UInt8](message))
            XCTAssertEqual(packets.map(\.tag), [1, 18], "\(name): PKESK then SEIPD")
            let pkesk = packets[0].body
            XCTAssertEqual(pkesk[0], 3, "\(name) PKESK version")
            let id = pkesk[1..<9].map { String(format: "%02x", $0) }.joined()
            XCTAssertEqual(id, subkeyID, "\(name) PKESK names the ECDH subkey")
            XCTAssertEqual(pkesk[9], 18, "\(name) PKESK algorithm is ECDH")
        }
    }

    // MARK: - Operational (8.3.0)

    /// The public point of a v4 EC key packet: version, time, algorithm, OID,
    /// then the point as an MPI (0x04 || x || y).
    private func point(ofKeyPacket body: Data) throws -> [UInt8] {
        let b = [UInt8](body)
        let oidLength = Int(b[6])
        var off = 7 + oidLength
        let bits = Int(b[off]) << 8 | Int(b[off + 1]); off += 2
        let length = (bits + 7) / 8
        return Array(b[off..<(off + length)])
    }

    /// GnuPG's detached signatures verify with each primary's ECDSA key, and
    /// a changed document does not.
    func testECDSAVerify() throws {
        let cases: [(String, Data, Data)] = [
            ("P-256", p256PrimaryBody, p256DetachedSig),
            ("P-384", p384PrimaryBody, p384DetachedSig),
            ("P-521", p521PrimaryBody, p521DetachedSig),
        ]
        for (name, primary, sig) in cases {
            let parsed = try OpenPGPPacketParser.parseSignaturePacket(body: [UInt8](sig))
            let publicPoint = try point(ofKeyPacket: primary)
            XCTAssertTrue(try OpenPGPPacketParser.verifyEd25519Signature(
                signature: parsed, document: signedDocument, publicKey: publicPoint), "\(name) verifies")
            XCTAssertFalse(try OpenPGPPacketParser.verifyEd25519Signature(
                signature: parsed, document: signedDocument + [0x0A], publicKey: publicPoint), "\(name) altered document")
        }
    }

    /// GnuPG's encrypted messages decrypt with each unprotected secret subkey
    /// (S2K usage 0: the scalar MPI, then a two-octet checksum).
    func testECDHDecrypt() throws {
        let cases: [(String, Data, Data, ECCurve)] = [
            ("P-256", p256SecretSubkeyBody, p256EncryptedMessage, .nistP256),
            ("P-384", p384SecretSubkeyBody, p384EncryptedMessage, .nistP384),
            ("P-521", p521SecretSubkeyBody, p521EncryptedMessage, .nistP521),
        ]
        for (name, secret, message, curve) in cases {
            let b = [UInt8](secret)
            let oidLength = Int(b[6])
            var off = 7 + oidLength
            let pointBits = Int(b[off]) << 8 | Int(b[off + 1]); off += 2 + (pointBits + 7) / 8
            let kdfLength = Int(b[off])
            let kdfHash = b[off + 2], kdfCipher = b[off + 3]
            off += 1 + kdfLength
            let publicBody = Array(b[0..<off])
            XCTAssertEqual(b[off], 0, "\(name): unprotected"); off += 1
            let scalarBits = Int(b[off]) << 8 | Int(b[off + 1]); off += 2
            let scalar = Array(b[off..<(off + (scalarBits + 7) / 8)])
            let fingerprint = OpenPGPPacketParser.computeV4Fingerprint(packetBody: publicBody)
            let key = Cv25519DecryptionKey(
                subkeyID: Array(fingerprint.suffix(8)), subkeyFingerprint: fingerprint,
                privateKey: scalar, kdfHashID: kdfHash, kdfCipherID: kdfCipher, curve: curve)
            let contents = try OpenPGPPacketParser.decryptMessageReturningInnerPackets(
                messageData: message, decryptionKeys: [key])
            // GnuPG was fed the plaintext by echo, so the literal ends in "\n".
            XCTAssertEqual(String(decoding: contents.literalData, as: UTF8.self), expectedPlaintext + "\n", name)
        }
    }

    private static func hex(_ s: String) -> Data {
        let c = s.filter { $0.isHexDigit }; var o = Data(capacity: c.count/2); var i = c.startIndex
        while i < c.endIndex { let n = c.index(i, offsetBy: 2); o.append(UInt8(c[i..<n], radix: 16)!); i = n }
        return o
    }
    private func hex(_ s: String) -> Data { Self.hex(s) }
}
