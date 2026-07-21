// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CompositeKEMKATTests.swift
// PGPony — Phase F (PQC) F2.
//
// RFC 9980 §4 composite KEM (ML-KEM-768 + X25519, alg 35) known-answer tests.
// The vectors are taken from RFC 9980's OWN sample message (the "Testing\n"
// message encrypted to the v6 ML-KEM-768+X25519 sample certificate) and were
// each re-derived and cross-checked in the sandbox before being baked in:
//   * the combiner output (KEK) was reproduced with SHA3-256 over the exact
//     151-octet input and equals the RFC's stated KEK,
//   * X25519(r, V) equals the RFC's stated ecdhKeyShare,
//   * ML-KEM decaps(mlkemCT) with the seed-expanded key equals mlkemKeyShare
//     (verified against an independent FIPS-203 implementation),
//   * AES-256 unwrapping the PKESK's wrapped key with the KEK equals the RFC's
//     stated session key.
//
// A passing suite means our composite KEM agrees byte-for-byte with RFC 9980.

import XCTest
import CryptoKit
@testable import PGPonyCore

final class CompositeKEMKATTests: XCTestCase {

    // MARK: - RFC 9980 sample-message vectors

    private let mlkemKeyShare = hex("b0e45408d8c713f3941cd27276f879e557df013e05bcf43e37d4c60266a4b797")
    private let ecdhKeyShare  = hex("9d994741e0db5eacee44cb028c2ec48b1346feae2576aaac383bbcd64138c932")
    private let V             = hex("85e2fe4ce047b23147c1583272389a01b4bc2b99607d0c38ac18d2ab1d7a4a6b")   // ecdhCipherText (ephemeral X25519 public)
    private let R             = hex("22150b430cf724ec19b8be55df9bcaade327085711369404a575c8023443b05f")   // ecdhPublicKey (recipient X25519 public)
    private let r             = hex("c04dbeb8360fc5ba3ce71959dbfc869de7225d2f0cbdfa81cfc64e23fcb40b7c")   // recipient X25519 secret
    private let expectedKEK   = hex("5bf078bf7977109db6dead92d3578b62d0ab0487ef84e8e0af08f4b4b229e590")
    private let mlkemSeed     = hex("51b27ed9159da710068ff5151ba1049291cfe07ab8b17b8ec70bb5fe30fea1ed4032e3dfa776"
        + "f44ee801f1db36733e20e56743605f7a7a01e9b8e738df313efe")   // 64-octet d‖z
    private let mlkemCT       = hex("bdd2ea61b0fe3948775c6318025d386e43b4cdfa24a2f9e0a0e8dc080f870645be23557760d1"
        + "2f6eaf77a15a60b5e362b906e9246d658140324cd2141af435be2f3fb93c06fa24e7c53867db"
        + "5f34539ae34133c9de3eb8a0c4eaed0ded342baa99943bc18d73b1e66bee09e8ffdf75a77c91"
        + "583e1c6965fbf4fbad39766fd2cbe234414a5a2ab5625d9a11e19d35826df934a8180949983d"
        + "5f4cb29b05f1ac999623969139cb6dab945ae0c24e5f0a35b310e163f940e6b1b3ae4257cd80"
        + "60c929441a029ac8237c5072f1fc527aa20a875aa0855decfbbc437294b151cfb6d8efff34c3"
        + "53aba9f00de3308d0f243a5e44845583d164f640d5c13cc4d7ad05748e8c79be223ea20a263b"
        + "e4a413723ae81efb38ab4ec0d3f8090f1d143da126993f1b5fb298637284ca9808de214dae1a"
        + "225ecb001d4aa6f8dcd5948ae318a3a369b8b9af3d57d7a27602a2a3c46b8a4cc47ba9303b27"
        + "40db5967c878c20cf7d9dc262d0e9d01617801ae5d0c9d958218c8ffb4c5383daeaabcaeff9b"
        + "4b330a91183b2fa76049df822a21b2e7f8954d867b26d4ac560ebf9d56105e17ea745ab4acff"
        + "073db94f3af55d88183db3323a6de050f4744c7de594dbabdc4a102eae27e1bafd7a3517fd57"
        + "ca64f1245a4ba0fc89bca67cfcda5bf46aa255aa7c847836345622036c29e3547848f4255c93"
        + "caecb440a32dc25293d4f3a92fbc4e98b4ee27ba17dd5701189a07077c1e8a45e11d4b9a729c"
        + "121105effedc25529369ad26651e454732069f5a0a7b400d00dd0b14fe70d8766a5dba66b91c"
        + "0aae9c9f908b0762315118ef710cc7fbb8f22a3f3135a8bdb25487e97831a9ac7bc96c6cdc4c"
        + "9f3aaf9a8703fff6e7b980adf7c70f6e105b2b418af3e414325158821087736eded3705a27f9"
        + "9136ab4e0afae823dfc016bf84b79058f19c16ad32961deb846f0262fc58e5cca3e0e482a774"
        + "3b337771a1d4b65ec58808aa14183a3413dba278973b7fcd37f7b0c6a781370603fbb3f5e4da"
        + "77164fb365ae972d62016230a0a311d4966ced3c0bc446f0e62006731c637a79c6a936bbadb5"
        + "25c09ebacdee7f72a0eb05013e89236b95dd94b6d540877ef34333103ca386fdf1e9cfc5d1ac"
        + "ff2ebceadffd9da67defcb4ad4f56679f775919d567bd29708590a9a2580a23b267b9a44e4ab"
        + "2860f0fdfc61466e16d4861a4ebd9fb403ddb7590636f33119ef7af42ec577baf96797693f6e"
        + "bc463f18a2deb2d829a08d5a0d2f7b39f9b174e25a7d524d8c3ce5d83272284a4276a08eb136"
        + "9b55f2da1aee82dcd41336370724d5c985317c06df5ce9dd562120c449f987b439f3b4c5be63"
        + "fcbe8ee53f845c0af70977768d6138742fa9d52bb2487e6bbad9bf89d4b7d05a7657baa19b52"
        + "cd798333ee4f56a5362d0e9122b39e6764a820c06fe0f9ecca47ab0285304541f8cf8824422d"
        + "2b537af8c15b5aea40dfa3d1e5b4d779b25e807f2e12604d3af95b09f5fa6bd50e232841db36"
        + "16a790f829becd0241433252503c1c19f4e5eaa690844602")
    private let wrappedC      = hex("7374a273524b623e0600b60e6c0be4f5a30c662eece2adb13315095472044b0f3346d5415e8b"
        + "3772")    // AES-wrapped session key from PKESK
    private let sessionKey    = hex("94a3b8c9784463bb96b682cddf549adb23579b75bcb646f989d7cfe3e6e14435")

    // MARK: - Combiner (RFC 9980 §4.2.1)

    /// The SHA3-256 key combiner must reproduce the RFC's KEK exactly.
    func testCompositeCombinerKAT() {
        let kek = CompositeKEMService.deriveKEK(
            mlkemKeyShare: mlkemKeyShare,
            ecdhKeyShare: ecdhKeyShare,
            ecdhCipherText: V,
            ecdhPublicKey: R,
            algId: 35)
        XCTAssertEqual(kek, expectedKEK, "combiner KEK mismatch vs RFC 9980")
    }

    /// Domain separator + algorithm ID constants.
    func testCompositeConstants() {
        XCTAssertEqual(CompositeKEMService.algIdMLKEM768X25519, 35)
        XCTAssertEqual(Data(CompositeKEMService.domainSeparator),
                       Data("OpenPGPCompositeKDFv1".utf8))
        XCTAssertEqual(CompositeKEMService.domainSeparator.count, 21)
    }

    // MARK: - X25519 half

    /// CryptoKit X25519 must match the RFC: X25519(r, V) == ecdhKeyShare.
    func testX25519SharedSecretKAT() throws {
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: r)
        let pub  = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: V)
        let ss   = try priv.sharedSecretFromKeyAgreement(with: pub)
        let x    = ss.withUnsafeBytes { Data($0) }
        XCTAssertEqual(x, ecdhKeyShare, "CryptoKit X25519 disagrees with RFC 9980")
    }

    // MARK: - Full end-to-end decapsulation from the RFC message

    /// Expand the stored 64-octet ML-KEM seed, run the full composite
    /// decapsulation on the RFC's actual ciphertexts, and confirm both the KEK
    /// and (via AES key unwrap) the RFC's session key.
    func testCompositeDecapsulateEndToEndKAT() throws {
        // Seed -> expanded 2400-octet ML-KEM secret key.
        let (_, mlkemSK) = try MLKEMService.generateKeyPair(seed: mlkemSeed)

        let kek = try CompositeKEMService.decapsulate(
            mlkemCipherText: mlkemCT,
            ecdhCipherText: V,
            mlkemSecretKey: mlkemSK,
            ecdhSecretKey: r,
            ecdhPublicKey: R,
            algId: 35)
        XCTAssertEqual(kek, expectedKEK, "composite decapsulation KEK mismatch vs RFC 9980")

        // Unwrap the PKESK's wrapped key with the KEK -> RFC session key.
        let unwrapped = try AESKeyWrap.unwrap(ciphertext: [UInt8](wrappedC), kek: [UInt8](kek))
        XCTAssertEqual(Data(unwrapped), sessionKey, "AES-unwrapped session key mismatch vs RFC 9980")
    }

    // MARK: - Round trip (self-consistency)

    /// Fresh keypairs: encapsulate then decapsulate must agree on the KEK.
    func testCompositeRoundTrip() throws {
        // ML-KEM keypair.
        let (mlkemPK, mlkemSK) = try MLKEMService.generateKeyPair()
        // X25519 keypair.
        let ecdhPriv = Curve25519.KeyAgreement.PrivateKey()
        let ecdhPub  = ecdhPriv.publicKey.rawRepresentation

        let enc = try CompositeKEMService.encapsulate(mlkemPublicKey: mlkemPK,
                                                      ecdhPublicKey: ecdhPub)
        XCTAssertEqual(enc.mlkemCipherText.count, 1088)
        XCTAssertEqual(enc.ecdhCipherText.count, 32)
        XCTAssertEqual(enc.kek.count, 32)

        let kek2 = try CompositeKEMService.decapsulate(
            mlkemCipherText: enc.mlkemCipherText,
            ecdhCipherText: enc.ecdhCipherText,
            mlkemSecretKey: mlkemSK,
            ecdhSecretKey: ecdhPriv.rawRepresentation,
            ecdhPublicKey: ecdhPub)
        XCTAssertEqual(enc.kek, kek2, "encaps/decaps KEK disagree")
    }

    // MARK: - hex helper

    private static func hex(_ s: String) -> Data {
        var out = Data(capacity: s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let n = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<n], radix: 16)!)
            i = n
        }
        return out
    }
    private func hex(_ s: String) -> Data { Self.hex(s) }
}
