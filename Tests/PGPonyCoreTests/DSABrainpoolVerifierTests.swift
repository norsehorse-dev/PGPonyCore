// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// DSABrainpoolVerifierTests.swift
// PGPonyCoreTests
//
// 8.4.0 build 7 (plan K3, K4): DSA and brainpool ECDSA verification.
//
// Arithmetic: BigUInt and MontgomeryModulus against values computed with
// Python's integers; the brainpool curves (RFC 5639) with the generator on
// the curve, 2G and 3G computed three ways and checked against an affine
// reference, n G at infinity, malformed points refused.
// ECDSA: signatures made by an independent implementation (pyca
// cryptography 50) on all three curves, one of them over SHA-512 truncated
// to 256 bits and one over a SHA-256 digest shorter than the 512-bit order,
// plus a signature made here by formula with a known private key and nonce.
// DSA: 1024/160 (SHA-256 truncated to 160 bits) and 3072/256 signatures by
// pyca cryptography, with negatives.
// GnuPG: the Android repo's gpg 2.4.4 certificates (DSA 2048, brainpoolP256r1,
// P384r1, P512r1: User ID certification, two subkey bindings, a signing
// subkey's back-signature) through CertificateValidator, and gpg 2.2.27 data
// signatures (DSA 3072, DSA 1024 over SHA-256, brainpool on all three curves,
// brainpoolP256r1 over SHA-512) detached, clear-signed, inline and streamed
// from a file through SigningService. A secp256k1 key still reads as
// uncheckable.
//
// Ported from the app's Build7CurvesTests.swift. The tests there that need the app's
// storage, models or secret-key unlock stay in the app.

import XCTest
import CryptoKit
@testable import PGPonyCore

@MainActor
final class DSABrainpoolVerifierTests: XCTestCase {

    // MARK: - Helpers

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

    private func big(_ hex: String) -> BigUInt { BigUInt(hex: hex)! }

    private func hexString(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func packets(_ data: Data) throws -> [ParsedPacket] {
        try OpenPGPPacketParser.parsePackets(data: Array(data))
    }

    private func subkeyCount(_ data: Data) throws -> Int {
        try packets(data).filter { $0.tag == 14 }.count
    }

    private func digest(_ algorithm: String, _ data: [UInt8]) -> [UInt8] {
        switch algorithm {
        case "sha384": return Array(SHA384.hash(data: Data(data)))
        case "sha512": return Array(SHA512.hash(data: Data(data)))
        default: return Array(SHA256.hash(data: Data(data)))
        }
    }

    // MARK: - BigUInt

    func testBigUIntBasics() {
        let x = big("0123456789ABCDEF00112233445566778899")
        XCTAssertEqual(x.minimalBytes, bytes("0123456789abcdef00112233445566778899"))
        XCTAssertEqual(x.bytes(length: 20), [0, 0] + bytes("0123456789abcdef00112233445566778899"))
        XCTAssertNil(x.bytes(length: 17))
        XCTAssertEqual(x.bitWidth, 137)
        XCTAssertEqual(x.shiftedLeft(by: 37).shiftedRight(by: 37), x)
        XCTAssertEqual(x.shiftedRight(by: 8 * 17), BigUInt(1))
        XCTAssertEqual(x.shiftedRight(by: 200), BigUInt())
        XCTAssertEqual(BigUInt(bytes: [0, 0, 1]), BigUInt(1))
        XCTAssertTrue(BigUInt(bytes: []).isZero)
        let y = big("FFFFFFFFFFFFFFFFFFFF")
        XCTAssertEqual((x + y) - y, x)
        XCTAssertTrue(y < x)
        XCTAssertEqual(big("0100000000000000000000000000000000000000000000003039").remainder(dividingBy: BigUInt(1_000_003)), big("0F0BB5"))
        XCTAssertEqual(BigUInt.leftmostBits(of: [0xAB, 0xCD, 0xEF], count: 12), big("ABC"))
        XCTAssertEqual(BigUInt.leftmostBits(of: [0xAB, 0xCD], count: 256), big("ABCD"))
        XCTAssertNil(BigUInt(hex: "12G4"))
    }

    func testMontgomeryArithmetic() throws {
        let curve = BrainpoolCurve.p256r1
        let field = curve.field
        XCTAssertEqual(field.powerMod(BigUInt(3), BigUInt(65537)), big("9FF4D0FECFC4D03D62D26693E7192ABE2BFCA82CB12E0A6969830242781ED4CE"))
        XCTAssertEqual(field.powerMod(BigUInt(12345), curve.prime - BigUInt(1)), BigUInt(1), "Fermat")
        let inverse = try XCTUnwrap(curve.scalars.inverse(BigUInt(7)))
        XCTAssertEqual(inverse, big("3090F487E51F9E35C8AF70BB9AB7DF45037E230A33D2C1FD96E404254FCB8679"))
        XCTAssertEqual(curve.scalars.multiplyMod(BigUInt(7), inverse), BigUInt(1))
        let wide = curve.prime.shiftedLeft(by: 300) + BigUInt(5)
        XCTAssertEqual(field.multiplyMod(wide, BigUInt(1)), BigUInt(5), "a value wider than the modulus")
        XCTAssertNil(MontgomeryModulus(BigUInt(16)), "even modulus")
        XCTAssertNil(MontgomeryModulus(BigUInt(1)))
        XCTAssertNil(try XCTUnwrap(MontgomeryModulus(BigUInt(15))).inverse(BigUInt(5)), "no inverse modulo a composite")
        XCTAssertNil(curve.scalars.inverse(curve.order), "zero has no inverse")
        let top = field.toMontgomery(curve.prime - BigUInt(1))
        XCTAssertEqual(field.fromMontgomery(field.add(top, field.one)), BigUInt())
        XCTAssertEqual(field.fromMontgomery(field.subtract(field.zero, field.one)), curve.prime - BigUInt(1))
    }

    // MARK: - Curves

    private let doubledX: [BrainpoolCurve.Name: String] = [
        .p256r1: "743CF1B8B5CD4F2EB55F8AA369593AC436EF044166699E37D51A14C2CE13EA0E",
        .p384r1: "2282BC382A2F4DFCB95C3495D7B4FD590AD520B3EB6BE4D6EC2F80C4E0F70DF87C4BA74A09B553EBB427B58DF9D59FCA",
        .p512r1: "9F4945F680EDF9800A63285758F399B3D18D8141B8A18064A30D3035F4CB6581957877F3A8F0F72597116E702915A4F4F698F404089A4CC5080447DEF02F4850",
    ]

    private let tripledX: [BrainpoolCurve.Name: String] = [
        .p256r1: "A8F217B77338F1D4D6624C3AB4F6CC16D2AA843D0C0FCA016B91E2AD25CAE39D",
        .p384r1: "7B63205BF00DDAE73B17452B6A27EBF53DF581348C6949F83EE1B6FCC7463BBE3C11EF6596A3B8897D7CC85B3035F11F",
        .p512r1: "08DD87E12B0A4CC436CDD42543F20AFE907C80EF3BC2459309C09CEFD830151BC1F6FB975CEECADE4780AE53E1853D62F56E34ABFA9AC7205D4ABF882CCB8D94",
    ]

    func testGeneratorsLieOnTheirCurves() {
        for curve in BrainpoolCurve.all {
            XCTAssertTrue(curve.isOnCurve(curve.generator), curve.name.rawValue)
            XCTAssertEqual(curve.decodePoint(curve.encodePoint(curve.generator)), curve.generator)
            XCTAssertEqual(curve.order.bitWidth, curve.fieldSize * 8)
            XCTAssertEqual(BrainpoolCurve.forOID(curve.oid)?.name, curve.name)
        }
        XCTAssertNil(BrainpoolCurve.forOID(NISTCurve.p256.oid))
        XCTAssertEqual(ECCurve.brainpoolP384r1.brainpoolCurve?.name, .p384r1)
        XCTAssertNil(ECCurve.nistP256.brainpoolCurve)
    }

    func testDoublingAgreesWithAdditionAndMultiplication() throws {
        for curve in BrainpoolCurve.all {
            let g = curve.generator
            let doubled = try XCTUnwrap(curve.doubled(g))
            XCTAssertEqual(curve.sum(g, g), doubled, curve.name.rawValue)
            XCTAssertEqual(curve.multiply(g, by: BigUInt(2)), doubled, curve.name.rawValue)
            XCTAssertEqual(doubled.x, big(try XCTUnwrap(doubledX[curve.name])), curve.name.rawValue)
            XCTAssertTrue(curve.isOnCurve(doubled))
            let tripled = try XCTUnwrap(curve.sum(doubled, g))
            XCTAssertEqual(curve.multiply(g, by: BigUInt(3)), tripled, curve.name.rawValue)
            XCTAssertEqual(tripled.x, big(try XCTUnwrap(tripledX[curve.name])), curve.name.rawValue)
            XCTAssertEqual(curve.linearCombination(BigUInt(1), g, BigUInt(1), doubled), tripled)
        }
    }

    func testTheOrderTimesTheGeneratorIsInfinity() {
        for curve in BrainpoolCurve.all {
            let g = curve.generator
            XCTAssertNil(curve.multiply(g, by: curve.order), curve.name.rawValue)
            let minusG = curve.multiply(g, by: curve.order - BigUInt(1))
            XCTAssertEqual(minusG, BrainpoolCurve.Point(x: g.x, y: curve.prime - g.y), curve.name.rawValue)
            XCTAssertNil(curve.sum(g, minusG))
        }
    }

    func testMalformedPointsAreRefused() {
        for curve in BrainpoolCurve.all {
            let encoded = curve.encodePoint(curve.generator)
            XCTAssertEqual(encoded.count, curve.pointLength)
            var offCurve = encoded
            offCurve[offCurve.count - 1] ^= 0x01
            XCTAssertNil(curve.decodePoint(offCurve), "off the curve")
            XCTAssertNil(curve.decodePoint([0x02] + Array(encoded.dropFirst())), "not uncompressed")
            XCTAssertNil(curve.decodePoint(Array(encoded.dropLast())), "short")
        }
    }

    // MARK: - ECDSA

    private struct ECVector {
        let curve: BrainpoolCurve
        let hash: String
        let point: String
        let r: String
        let s: String
    }

    private let ecMessage = Array("PGPony build 7 brainpool vector".utf8)

    private let ecVectors: [ECVector] = [
        ECVector(curve: .p256r1, hash: "sha512",
                 point: "0494f54a9020b5e0b09af041b5a27e3f6706e33acd25214c095e180a609284c9420d61207d513f9a9969c1ee64305a9978e0d64299b33239ea770c4b0f8950ca54",
                 r: "32dc36d812a3b4446028ded3544b982840e76e33d2982bb4100325dfe99d82ed",
                 s: "8d843cf972bdcece9c9580c18ccae04a58aa897ba55f9a8854d8ae6f06562526"),
        ECVector(curve: .p384r1, hash: "sha384",
                 point: "04621c420948fe41e4f62b69c84bde42aa274e0ccff6d583d387bf2d2aaa896f159148d203e3a6919b92b08b4c173a200d7ffeee7ae51e44ea69c0d23e51c0ee223451957b698b6d7fe65071a7b0b2efe19a31d076fe0c59237877ed5013b233b8",
                 r: "77e565a326d09d2bce9a8c3bd591956381478f6e2d62d1ca2e5a4d8f37e03b6187180804e2c04ebea132164f287a4219",
                 s: "18a76b9ce9db0c0abedfe4846227e366177fbd6b294c9c86a5a471ada7835b5a98fbe5933106b7496ea44422e56afb12"),
        ECVector(curve: .p512r1, hash: "sha256",
                 point: "046c6d72a718d050d1d5dfe3345c6a5b0cbea6df03b49f0c6e8cedf778b0fd801e47d6c0a079e904d820ee18b47a9af48768269a1da9a7c99af15487623e851b9d9465927b8857f0c8b9dfbebe91507e369ba86bf21ea0eaf7006ec07a75211c16e6a07606b4c140f78848ca800aff06e95334aa207620b49d870a5952e178ff23",
                 r: "7bcc715e8b10a148c5bf13cd1bdef0862bf22e80f96b2441380cb1cdcd2748089592885a61caf9b945a7643f6b9f93811bccca575f4e8a35cc6424d4b56ade3f",
                 s: "3836ceceaf300e145d6edf1e3d87e21d7bdd7883d4667262487ae7edcdaf92c7f921006abfb0fa4ccfe0980ebce7bed4441a534112b5538d09ed0fbc11b04819"),
    ]

    func testIndependentBrainpoolSignaturesVerify() {
        for v in ecVectors {
            let name = v.curve.name.rawValue
            let d = digest(v.hash, ecMessage)
            let point = bytes(v.point)
            XCTAssertTrue(BrainpoolECDSA.verify(r: bytes(v.r), s: bytes(v.s), digest: d, curve: v.curve, publicPoint: point), name)
            XCTAssertFalse(BrainpoolECDSA.verify(r: bytes(v.r), s: bytes(v.s), digest: digest(v.hash, ecMessage + [0x21]),
                                                 curve: v.curve, publicPoint: point), name)
            XCTAssertFalse(BrainpoolECDSA.verify(r: (big(v.r) + BigUInt(1)).minimalBytes, s: bytes(v.s), digest: d,
                                                 curve: v.curve, publicPoint: point), name)
            XCTAssertFalse(BrainpoolECDSA.verify(r: bytes(v.r), s: [], digest: d, curve: v.curve, publicPoint: point), name)
            XCTAssertFalse(BrainpoolECDSA.verify(r: (big(v.r) + v.curve.order).minimalBytes, s: bytes(v.s), digest: d,
                                                 curve: v.curve, publicPoint: point), "r at or above n: \(name)")
            var offCurve = point
            offCurve[offCurve.count - 1] ^= 0x01
            XCTAssertFalse(BrainpoolECDSA.verify(r: bytes(v.r), s: bytes(v.s), digest: d, curve: v.curve, publicPoint: offCurve), name)
        }
    }

    func testASignatureMadeHereWithAKnownKeyAndNonceVerifies() throws {
        let d = big("1F2E3D4C5B6A79881726354453627180A9B8C7D6E5F4")
        let k = big("0C0FFEE0DECAF0BADC0DE5EEDBEEF12345678")
        let digest = Array(SHA512.hash(data: Data("made by formula".utf8)))
        for curve in BrainpoolCurve.all {
            let n = curve.order
            let q = try XCTUnwrap(curve.multiply(curve.generator, by: d))
            let e = BigUInt.leftmostBits(of: digest, count: n.bitWidth)
            let r = try XCTUnwrap(curve.multiply(curve.generator, by: k)).x.remainder(dividingBy: n)
            let kInverse = try XCTUnwrap(curve.scalars.inverse(k))
            let s = curve.scalars.multiplyMod(kInverse, curve.scalars.addMod(e, curve.scalars.multiplyMod(r, d)))
            let point = curve.encodePoint(q)
            XCTAssertTrue(BrainpoolECDSA.verify(r: r.minimalBytes, s: s.minimalBytes, digest: digest, curve: curve, publicPoint: point),
                          curve.name.rawValue)
            var wrong = digest
            wrong[0] ^= 0x80
            XCTAssertFalse(BrainpoolECDSA.verify(r: r.minimalBytes, s: s.minimalBytes, digest: wrong, curve: curve, publicPoint: point))
            let otherKey = curve.encodePoint(try XCTUnwrap(curve.multiply(curve.generator, by: d + BigUInt(1))))
            XCTAssertFalse(BrainpoolECDSA.verify(r: r.minimalBytes, s: s.minimalBytes, digest: digest, curve: curve, publicPoint: otherKey))
        }
    }

    // MARK: - DSA

    private struct DSAVector {
        let bits: Int
        let p: String
        let q: String
        let g: String
        let y: String
        let r: String
        let s: String
    }

    private let dsaMessage = Array("PGPony build 7 DSA vector".utf8)

    private let dsaVectors: [DSAVector] = [
        DSAVector(bits: 1024,
                  p: "8b67fd7d29ed0acd66e8a75962e330fbe2830ed9add7efbb416a3298dc69306f206a4a54d709e11b64548b34eee8da63c042f361f8928304a77cfd3f5797b00996c505bc5aba5146e6f42b9c4a340a9bc0aca5b3c2743b2c2597e1ee4df815fb1e40bce0fba57451e19da69b41639eae77b9d2ee26a7e6bdfeee960dba541687",
                  q: "861f231b0655a91e0d43c0f3299e972229efa3c5",
                  g: "677e82ce8867268bb1aec2ff523e8f295e83d8f46f7203c898ca93d03a8b47b3c4941d9712bf32641047a5334d5de84ec05d671cfde4afa62f73a4d51a6880c247395cbf23831474bc3adcc59a698f5fc171594d90e4566b820b41e14de7bae0d979e074405b8cfdfd0d793f8c7791aa678c3afd59a5b4d228d4ce2cc2cb1cc8",
                  y: "74518befbb934944c73ac900edf3e43cba35f67f7a3d27b1265c5a34894c83df165436ecf600f74370463aebe07c46d2ea1cb716711a251c3f8930a057b65fad264a3d0885ddc86e62a26301984416f76703d6a721f0c0280324ee1245a6969781c042a638a7f31beffc0dd3db94200fe6f5664231088c78c02ad5aebf156e72",
                  r: "31eb0d788776a22ea819ced01ca19958d4f6d0f2",
                  s: "6ee35d90f84a50a60b2d2b1e73ca97f89a8ee7af"),
        DSAVector(bits: 3072,
                  p: "a42424f851be9fa013f272453dbefb80ee1777278ca03178ac267fcab27a2a09ddd31d7fc2034ba2fbec249200fa5b4d89365d6f14f924a56028c521ba26f20b68c1c28366b5e2c724d405df18ea9836c0c34e869341eef960360b784c8a9dea625414cb53951ae003ead7f387866f13cb1476906ecde8c6895cd4ea2018b95d69bb531d78116dded1a4a0dbe71ea0f924fe81c0ba46a73aa3195bfd477519c9a9f5ec33e39834f5e5002bcb91b22e047b9d232052589c8d479e49b2edd86d703ee35d677e79ab150f246159eb1347d9cc2a32ead998414120aaeec0f92907c6acfa1f09384c925bdab94c1665096bcd8e98a88b8e4ed58de1d65afe7d431d68a7cead6692b3b25c3c465eb8d5b9b62071977c680ba329d845a4e8efa1acf118f7e686bfd89e9d0311e468d244ac36a5c0dae0b27985ad29de6815979f62adb7bf0371ede165b83fab68e23cb387603f940b0ec3521b01649805e14e86192ec0773584f0dc142eb8283f5b9ffdc5104cb16b1e39d139d2e305f5865c0c2919ef",
                  q: "93b9f27f0f627deafadf078da24789a06fc4bcdd17a40d5bf252d4d618f68683",
                  g: "9469f7ebb24cad9ed86a86cb8253facd2c733fcc54a0af7f1cd917193c887b6f562c09c960b3bd1beb974c1824dcf119c139d3ddb92dc7fb52bf948fe7a351f41a69879f0dda16b16bb11491bfe1d118d7556bd648ec6d6a25d86278452d1969ca1a9ea37b775ed7fe62fa88a18a18695821713eaebe47676b68023bca38f1ce038539c8ca4c70e081866176ad3de2235f723f11f49ee94bb5adc722699ffa276522414027ba5352c4610cf11e566da8343e3850f8feb8a2ad19b9dd461fc716d10ac5747e41b2284869f2c8b222585a9927df40dcc60dd0a6406532307bcebb01b2933c0fc53f97e2f57d9539ae2f20409c1a17ad0c92092b5da163367253ec9615898bc8961ed5d376cda0ef4f58d74e127a8070aba1a6f04d424376932ff98aa7712c6010ae352dd9211020e4e279e68694e650beea178b40a5f516b587c560197f5745370a614a9c064e4a02940d3caaced2c75e3a95ee1513bcb8abb34dc0c25e86b3686f2bb06836601e8928a568767de0ac5f387e2b9210422f9f7c3b",
                  y: "1c2c4b2c23f54d0ff8690e08ac8c783cadae07144093d9d2d7fcaeb14d4f6695033134f653b2353b6dc83f1dc413cae95fbbbf4d49cdb8ac38d53a627bfcc2bfe2600f0df93e5ce5d0e6fde380e70bbb56afebc9ca6d05b908e67baffa6a5593f5cdd5af3a1e2a1fadedc93c5185ac93720911ec4d794f5ba7c86803e39b1ad2b561f2d778ab3878edff18e20e14e7e06cb41e60840dcbf25dfa6bf1c7e3f9d0e7d2583f94408198b3034361c39310f06a05514980c77838fdf2c1d292160141b9bab2370a98ef4f57425d1b8c2431550a1251321e89eeb5ff32d9610d15b2118be9594e491902e4b8a35098b83103650fe660630cb741c4b652d7f0ca3a16f6dca18e1fb87565e674972afd1e9674e6e83c67c0289a067cc4c1cbef34f91e37b7c4d8a8a505da86e21cf8caef1b46d27a8a966e1c10faee5809a1a3d49141068b4cefb24b74011fe8ff35433c3e1c984384291ee1f272f7044fcd45a014ef75385b32ef34bdd893b806cf066c1da49574fbe0cecc6910655671d347b4d23666",
                  r: "87c252d334eefd531af89dee7aeca751ff7e12655c30bf3eb20a0d276869a17b",
                  s: "7e8af9ae5f2a76827512d21ef7f2dc2c8c141d432d04a87147dfb65792be750c"),
    ]

    func testDSASignaturesVerify() {
        let d = digest("sha256", dsaMessage)
        for v in dsaVectors {
            let start = Date()
            XCTAssertTrue(DSAVerifier.verify(r: bytes(v.r), s: bytes(v.s), digest: d,
                                             p: bytes(v.p), q: bytes(v.q), g: bytes(v.g), y: bytes(v.y)), "DSA \(v.bits)")
            let elapsed = Date().timeIntervalSince(start)
            print("Build7CurvesTests: DSA \(v.bits) verify took \(String(format: "%.3f", elapsed)) s")
            XCTAssertLessThan(elapsed, 5, "DSA \(v.bits)")
            XCTAssertFalse(DSAVerifier.verify(r: bytes(v.r), s: bytes(v.s), digest: digest("sha256", dsaMessage + [0x21]),
                                              p: bytes(v.p), q: bytes(v.q), g: bytes(v.g), y: bytes(v.y)))
            XCTAssertFalse(DSAVerifier.verify(r: (big(v.r) + BigUInt(1)).minimalBytes, s: bytes(v.s), digest: d,
                                              p: bytes(v.p), q: bytes(v.q), g: bytes(v.g), y: bytes(v.y)))
            XCTAssertFalse(DSAVerifier.verify(r: bytes(v.r), s: bytes(v.q), digest: d,
                                              p: bytes(v.p), q: bytes(v.q), g: bytes(v.g), y: bytes(v.y)), "s = q")
            XCTAssertFalse(DSAVerifier.verify(r: bytes(v.r), s: bytes(v.s), digest: d,
                                              p: bytes(v.p), q: bytes(v.q), g: bytes(v.g), y: [1]), "y = 1")
        }
    }

    // MARK: - GnuPG certificates (gpg 2.4.4, from the Android repo's test resources)

    private let gnupgRings: [(String, Data)] = [
        ("gpg-dsa2048", Data(base64Encoded: "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")!),
        ("gpg-brainpoolP256r1", Data(base64Encoded: "mFMEarM5NRMJKyQDAwIIAQEHAgMENNlrxmgaXbPcFxx9RLzr1JuHN+4cJHXve2ujjo6CjSMA5st2TJbWgRV9C0OCs4ZMq+boFmEP2ArfBNEyRNmMVrQ1Rml4dHVyZSBicmFpbnBvb2xQMjU2cjEgPGJyYWlucG9vbFAyNTZyMUBleGFtcGxlLm9yZz6IkwQTEwgAOxYhBEjLovBFnxhP8CMfH0q5EDyUk5E/BQJqszk1AhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEEq5EDyUk5E/2JoA/0+WUShOfyldHJnVAFkF3ARk3fPWq4fs93D8t4zsWMSTAP959duuhn2tU9gCGFSK4UTcW7s5p+qahI8/SU57ZSdx9bhXBGqzOTUSCSskAwMCCAEBBwIDBIE8x1nRejh/xL8/Az7wjmmwxk0cDnJiwrP7z/Duw00JDxSiPg0TlD2uEHLURguB/znyOZ5taOifkoFg2c/t83UDAQgHiHgEGBMIACAWIQRIy6LwRZ8YT/AjHx9KuRA8lJORPwUCarM5NQIbDAAKCRBKuRA8lJORP1O8AP454bC/zSEdn19o4ohWGcjV0bwfDnYBVtVEoHFVJyK8oAEAnMVYv2DEgc7EwldlhT2ekS+C2pZHd31oQ556/a4YPwm4UwRqszk/EwkrJAMDAggBAQcCAwSkm7Ujtjb2BJWKMySRNPlrWbQF5K9HHF8mUtFQiR3hDhjBezKhz5j/evx1BT+vNS8NPjwSwPIHmuSSl/PGfxeuiO8EGBMIACAWIQRIy6LwRZ8YT/AjHx9KuRA8lJORPwUCarM5PwIbAgCBCRBKuRA8lJORP3YgBBkTCAAdFiEEUvp9Ty2hntzemOsibE+LZEl92R0FAmqzOT8ACgkQbE+LZEl92R3OZwD9Hc8vn3xq9mnJhcshgTyx7grPLqxWWsjW53PlWvylou0BAJ9XzArra++BnEUn6lkvvrRqsgq63wEveQoPHq8MFsQS15EA/R7/vqhHOHHZa5EnJZ0clQl1pGSNeAkKMdwsWbD+zZ7nAP9if4mKKo73O+E01E6LQr92zUx+krLs4yHsh/6Z8iKyPQ==")!),
        ("gpg-brainpoolP384r1", Data(base64Encoded: "mHMEarM5NRMJKyQDAwIIAQELAwMEiid9G6AsJybsXwHXkJOXpYb4QgLKjSLvw7un6Me49UutJnYFmxE3QK6llXT+2OFHPy0NRi2MmfQR24KiteC75VO67KYmydD+dPUQDlFr2WgYCyB+4Lymv7WUN5a9sVfEtDVGaXh0dXJlIGJyYWlucG9vbFAzODRyMSA8YnJhaW5wb29sUDM4NHIxQGV4YW1wbGUub3JnPoizBBMTCQA7FiEE7WgHD+rXYFCOr/WzuywWXfd1Cf4FAmqzOTUCGwMFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQuywWXfd1Cf5BeAF+LBclNDaEV8N6tU/X0s8ETcaljXCYoIkMwl59GtRTZBs6zYYYq5BwYWX3RRfbwpf1AX43e7N0WYzyNNi4/+iM7p9fvOQ48/fyMVO3YoJjxzamX25eDmkVkPX0HYRyWXMg+fm4dwRqszk1EgkrJAMDAggBAQsDAwR4L4KPRwC+aDnjedE87UTlMMHMcQkJV6rcu/WlOHrBqK7IAKateaQMDcjKK0B7OrdA9ibvZH8eTyRqD1T8AFU9cbqhrXH/oW8A1wtvBC5DIcI7N7C+xysjYdPC0R9XY8cDAQkJiJgEGBMJACAWIQTtaAcP6tdgUI6v9bO7LBZd93UJ/gUCarM5NQIbDAAKCRC7LBZd93UJ/tsKAXwMuzUOiry6pyRcl7QskGlNJmn/RLte92XDohD4YLMfM4ZgSsgU2p5ngbvAT7M374YBf0hW5qan05WxXF9/Jv/hhSOSZzlPtwN3+nZMY6BZwZGvs6INrU8SLEYkU81HGA+Rz7hzBGqzOT8TCSskAwMCCAEBCwMDBGO1TLqhTVk/atOXVq0L3/xSAHFebuN5D56kEEqWonH0vp/mpQ6MAUQ1bKzEpUaErQSuO1zUbYrrqojh9ETJP9fkTLfjYIHWXKxL3/Fi77euqKu/X/d1FPlcXerO2rF4A4kBLwQYEwkAIBYhBO1oBw/q12BQjq/1s7ssFl33dQn+BQJqszk/AhsCAKEJELssFl33dQn+liAEGRMJAB0WIQSi2P28RqZ85B218YIRQp7dK0pfBAUCarM5PwAKCRARQp7dK0pfBB+EAX9gZfsmXUCLPBWRe9B+VcLZhzCBZoqWmTAX4iJqhtkEusmJbVOAWFsBVoL+cvX/CAwBf0LbaEegPlOLw4B7wXj1BY61zQwRhgotH+yvMC7oO/jwoA4p9+OZXtvxhmPKanLL8UXCAX4lmDoYslDeS4iGrbIY9IWf3qGAlc7sp4UsUZc4hQraRA85z5hxSpooXPzfxmHDC+sBf2H6NdVGrHMmUeOeDF6bsX8LFrhSH8cX6rPtdBGLUgYcdp0FqR4l3Mm9aKFVvcgSOA==")!),
        ("gpg-brainpoolP512r1", Data(base64Encoded: "mJMEarM5NRMJKyQDAwIIAQENBAMERDR3QNHY29ILpMTkKf8RUXax3tfkkYZLkCq9BbmWdeCC5nC0KSAk6uTDXcZRC4OZYBq59o7WvDT6qB5e3vmjqjWgYsevYr8W8yQbRx0OGYClAQWsb+Bqy/g9x/NonKfvTCx+GyHYTuvI1KtCHuXkHQGU4A2FSiGJsZ7XvFXzWQe0NUZpeHR1cmUgYnJhaW5wb29sUDUxMnIxIDxicmFpbnBvb2xQNTEycjFAZXhhbXBsZS5vcmc+iNMEExMKADsWIQQC2OPNGdLcEjvFieFUDyMXp4a7UwUCarM5NQIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRBUDyMXp4a7U6HpAf9WH9fMgDpIp8pqqx/YYZ5sGr4AnhEHxFb8qIkkqtP9kLGFSUXnEKsGTJfIZV3biLDXnrGiOPAyVg4J67acNccGAgCBCvOseFr/E686TlphmCP1wocMDDdJm3w5V/lm9y0npH6QL7fInJMyXHpOacVTVrvzD/fIeOKP9jyb9yh9IFXKuJcEarM5NRIJKyQDAwIIAQENBAMEihB7JX+DJq0caEDW4I/md1jEs70yyFuBDXJc3YYA7R3tsj9J504nGTJoRx3WNXliNgw6JOlsw0ueVWgZ3p4eWUJZCz9YFOeYVqR8efl2JJxCC977aWy/fpkb/qO8m5QoPRNVFWmH431WKWob3qogT/SfJPfSoBmksCVOTZiqM8EDAQoJiLgEGBMKACAWIQQC2OPNGdLcEjvFieFUDyMXp4a7UwUCarM5NQIbDAAKCRBUDyMXp4a7U+BRAf9RuNC+H5ZgN9spKKWyifdWi66f5VNMpUFkT/uxM4cOacspGWcURUXyeKghb0PM+BZFdS5IcVknfiUGLqWz/P3rAf4x/nhqOSITyCDbpqqaqIoCjkl1iAacRx55AKnJQ6HogjbYDJfZSL8rl+Zm4n6twb4RivHg6Eu4Bm6ZOQEJgEQJuJMEarM5PxMJKyQDAwIIAQENBAMEUByi2pYJK0lsiDUi0leoM+hnr36g61+icjUQcsCoIJMhDTYq1EeOWrn+kne0AFeswxa6ZkPJvkHDOnIN5rjTIkylYZO67ofZ//yl5iPEFdq89C/V2SsilHEs8pvhpuyYZosZu6EZE7XmNKvnJoyRB3v2RPoZuHPNnTl6WL90nkyJAW8EGBMKACAWIQQC2OPNGdLcEjvFieFUDyMXp4a7UwUCarM5PwIbAgDBCRBUDyMXp4a7U7YgBBkTCgAdFiEEJK0Ya3k59pClyUcvMZmqrvKr9CEFAmqzOT8ACgkQMZmqrvKr9CFiOwH7B3lEg21pQa7Bdz4Iq9D0Ij/ZnZqjHG/rXAaIR+fFiUBsWMiVDkKkp373a9a7Cgoyl0FRIzbkLymiBnaoaztjMgH/UpJPVGumDnZ75OZSxZyXxqtYPNfpXCDIBG0pnwFEfPe5bBf/vNjOroW4MBxwUANnY9DDNS+sIi77KD2UJEIZOaXhAf9lmXJ1cEe9h+34tu2sjGzh1n9boULPSJM1DfeHG8ffvPfLuvwNF3+kAV9g9FL4ONSPKk2qF5TFLlGUzAk2438vAf9IvKZ5EmsJ7f4V2lr065QRyhl9YyePFxjymV5oEoyZLRjejaCyocofOoZ5HLxX1+FnZfpBhPNe/botzyOicpiO")!),
    ]

    private let secp256k1Ring = UncheckableFixtures.androidSecp256k1

    func testGnuPGSelfSignaturesVerify() throws {
        for (name, ring) in gnupgRings {
            let all = try packets(ring)
            let primary = try XCTUnwrap(all.first { $0.tag == 6 })
            let uidIndex = try XCTUnwrap(all.firstIndex { $0.tag == 13 })
            let certPacket = all[uidIndex + 1]
            let cert = try OpenPGPPacketParser.parseSignaturePacket(body: certPacket.body)
            XCTAssertEqual(cert.signatureType, 0x13, name)
            let framedPrimary = CertificateValidator.frameKey(primary.body, signatureVersion: 4)
            let document = framedPrimary + CertificateValidator.frameIdentity(0xB4, all[uidIndex].body)
            XCTAssertEqual(CertificateValidator.verify(cert, signerBody: primary.body, document: document), .valid, name)
            let otherIdentity = framedPrimary + CertificateValidator.frameIdentity(0xB4, Array("Someone Else <else@example.org>".utf8))
            XCTAssertEqual(CertificateValidator.verify(cert, signerBody: primary.body, document: otherIdentity), .invalid, name)
            var altered = certPacket.body
            altered[altered.count - 2] ^= 0x01
            let forged = try OpenPGPPacketParser.parseSignaturePacket(body: altered)
            XCTAssertEqual(CertificateValidator.verify(forged, signerBody: primary.body, document: document), .invalid, name)

            var index = 0
            var subkeys = 0
            var backSignatures = 0
            while index < all.count {
                guard all[index].tag == 14 else {
                    index += 1
                    continue
                }
                var end = index + 1
                while end < all.count, all[end].tag == 2 { end += 1 }
                let signatures = all[(index + 1)..<end].map(\.body)
                let found = try XCTUnwrap(CertificateValidator.newestBinding(
                    subkeyBody: all[index].body, signatures: signatures, primaryBody: primary.body), name)
                XCTAssertEqual(found.1, .valid, name)
                if let flags = found.0.hashedSubpackets.first(where: { $0.type == 27 })?.data.first, flags & 0x02 != 0 {
                    XCTAssertTrue(CertificateValidator.backSignatureVerifies(
                        in: found.0, subkeyBody: all[index].body, primaryBody: primary.body), name)
                    backSignatures += 1
                }
                subkeys += 1
                index = end
            }
            XCTAssertEqual(subkeys, 2, name)
            XCTAssertEqual(backSignatures, 1, name)
            XCTAssertTrue(CertificateValidator.uncheckableSubkeys(in: ring).subkeys.isEmpty, "no pins needed: \(name)")
            XCTAssertEqual(try subkeyCount(try CertificateValidator.boundComponents(ring, purpose: .sign)), 1, name)
            XCTAssertEqual(try subkeyCount(try CertificateValidator.boundComponents(ring, purpose: .encrypt)), 1, name)
        }
    }

    func testOtherCurvesStayUncheckable() throws {
        // secp256k1 (GnuPG makes it; no verifier here) keeps the 8.3.0 rule.
        let all = try packets(secp256k1Ring)
        let primary = try XCTUnwrap(all.first { $0.tag == 6 })
        let uidIndex = try XCTUnwrap(all.firstIndex { $0.tag == 13 })
        let cert = try OpenPGPPacketParser.parseSignaturePacket(body: all[uidIndex + 1].body)
        let document = CertificateValidator.frameKey(primary.body, signatureVersion: 4)
            + CertificateValidator.frameIdentity(0xB4, all[uidIndex].body)
        XCTAssertEqual(CertificateValidator.verify(cert, signerBody: primary.body, document: document), .uncheckable)
        XCTAssertNil(DSABrainpoolVerifier.publicKey(fromKeyPacketBody: primary.body))
        XCTAssertEqual(CertificateValidator.uncheckableSubkeys(in: secp256k1Ring).subkeys.count, 2)
    }

    // MARK: - GnuPG data signatures (gpg 2.2.27) through SigningService

    private struct SignedFixture {
        let name: String
        let userID: String
        let publicKey: String
        let detached: String
        let clearSigned: String
        let inline: String
    }

    private let signedMessage = Data("PGPony build 7 verify test\nSecond line.\n".utf8)

    private let signedFixtures: [SignedFixture] = [
        SignedFixture(
            name: "dsa3072",
            userID: "DSA Verify <dsa3072@example.org>",
            publicKey: "mQSuBGrhjaIRDADo8Ykyvcmu1Um+FqyZGa/r867+P8Gxysp4pMPnNhIzIt3jJh8ghCFQTiC9HiVatQPjTBY1Z4P0kYHTJzh1S7tiXZWxUb2fAdcw08GLYODKBq5DS9VXkVIrrKfh0W0ujq0/GGHN4c1fHYBVW+jWmWErTAtfznhsO/UQV0dgvrs6YMrQ5J34Gf7L30JOeD66A/B5E4v1enCx+DNXPLkttP4GPUwD+XPRctzf6ZKtGCqmPo6ESJAZWQxzyBXmim6tJF1aKXzHOiIm1HqUe6g5tDlU9f2Vti1OLwpBLVRD4pwZErgSjmusTh/0KK4EqcVAGLchfsA0l0L5iIqiROzVgewQhk9ndUVKMSP++NuRI6fBGMaTPQdPa/ZJKSFi/3sxNfQknf4vZZH+8ibCH4u9lk1c8miXIF0bqQWmnENgvO282HGDra73LJiEHpfoyilqWIC8C+tv7T4QxJgE9rtxembjzrMphR5gEc9+8nuhiikUA9aD9+UDSb9/gxTKQh7rMh8BAIw9VZwVP6T0qCKJpzNQ0C/Ira/qmBjM6DDBTxNVZF5LC/9wRVIAAWl/XmJtXLAMREkSbaHqlEEH+eZt8ZIeP7+1JcCuqDsLlzxDGjX+Qs1vvZuzzXMRHdlunz2RvUksCVgWhGAC6JOiXxQhP3IZmtJRZ1P5a4q1lxSskpWgZA3UtpK1g+fVQdruWo7VJRbQWdhMOA7sjnanygv4BFaM/K9dkB4Ecqc//xhthfgOGq5wlkfq0cvJ4H+W4ajErgl1x5HGbvAyEvBheTOqvY7ih0y2udo/1A/Hq4hRl6EjZZAnt//VdC51vgqM5Yxk2MXFZz3NsBfMhE61/6VxkaiO0DdGvVMCWUyX1QxUMN2wSJwMn5DLpRQOcaz5DuUpo3u3WmrwT9TX7Vgs/qXA2RA5ifKWfhs+HGCQ6Rv3KhpVwypSv/UN0kNDApevgR4XpNBRZ8bD1lo09ZKFcBIWVWrsYcHKkCv7CDCtYReMJj0x/nxLRkSrmrqwuhI1GjluIHeHR+hEKj0hLEZ3orzpYrLTbBr1uvETRMqo4++RxNDGduAJ0O0MAMSVXFfsBl4ixtTHo7t+2sYBX7L8bsYroHGI1/6aqP+r/BN1blVu/bYGagE2NWnJKnWLu1nrL+DxQQHQ9QjKXl4PMTZf1FWfim29jebcCcBVzbO1lPGHL98IB8tVwR0zAs8wve91GhAPgFe+VjpAkuTsjXIUHk5bF9sMnvSv0AyhFF0UwcJBQ6//GK2+2pjq1oxsGPtEn09pQ+ipp/nEx7bBTmRtxNLiZm4/ZCfzUkrCDZq1armB5MU13OwWkJQQzL3XbmFjylmq8XDpFQKQe5qcef48Mo/3+zm0P9mZLrjLo+K7jb9NCmEhA1hHaxiq+2NY0bZUpfDa2YAyaQA+et0fckKsRJR8GJxVmExNUYvpFGQ09pcEfvMtmNzEF6HX0nxblW0Z5dvzTAEs+knvBktBrjXcGPQlSrGthLWa9/Li/S60r+z37EqiewOZTn6V/JBgDFPuK9WpVJ015jCr30yjprG8rSG1Owi/t/J5cWtZot6cFdP/z94DZXD/eY46W7QgRFNBIFZlcmlmeSA8ZHNhMzA3MkBleGFtcGxlLm9yZz6IkAQTEQgAOBYhBAluX28INgqnJML2qVBK0lcA53oXBQJq4Y2iAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEFBK0lcA53oX3SkA/1vuoO9G9Z1flmX4C6bsiTLZ571wEl1vuQYssObYOWbuAP4oo1GlJXf3vS4TgIZTPOrsP0gNOoBTJSQti9vh9TY2fQ==",
            detached: #"""
-----BEGIN PGP SIGNATURE-----

iHUEABEIAB0WIQQJbl9vCDYKpyTC9qlQStJXAOd6FwUCauGN2gAKCRBQStJXAOd6
FxkFAP90HshZTxl/raHaN9c5q+Ftq+ehsHV00SdFEAZsHNRTrgD+MQq7poXXF+Dq
mhQjKfYXJNvUbpVXrbLzguY0byqIxiI=
=RAFX
-----END PGP SIGNATURE-----
"""#,
            clearSigned: #"""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

PGPony build 7 verify test
Second line.
-----BEGIN PGP SIGNATURE-----

iHUEAREIAB0WIQQJbl9vCDYKpyTC9qlQStJXAOd6FwUCauGNsgAKCRBQStJXAOd6
F0YgAP496i2sUWTYnplUiKPGtoikaM88QvDjQPmfhOE87xilfAD/Sel6jXipV3xB
PeL1spGuo4h7XU1VFc+0KdKeqrsjT/s=
=afHR
-----END PGP SIGNATURE-----
"""#,
            inline: #"""
-----BEGIN PGP MESSAGE-----

kA0DAAgRUErSVwDnehcBrDViB21zZy50eHRq4Y2yUEdQb255IGJ1aWxkIDcgdmVy
aWZ5IHRlc3QKU2Vjb25kIGxpbmUuCoh1BAARCAAdFiEECW5fbwg2CqckwvapUErS
VwDnehcFAmrhjbIACgkQUErSVwDneheBiQD9E0MQGtOy9ko/vgjzF+ADBvgd1f8n
uZBkHqRYxwyTockA/3Qyrdv2bJ8WhQOCQTQts2iFE0YzyRuyntoWJUEHibjb
=c348
-----END PGP MESSAGE-----
"""#),
        SignedFixture(
            name: "dsa1024",
            userID: "DSA Small <dsa1024@example.org>",
            publicKey: "mQGhBGrhjaQRBACAlxGzZ6QA+cfxTzQDeWmqDs9aE3t3rUEHFUrp5Urv5Kre4x9jk6XMts9HZqmHWTbYyA0jxHWB5Ktzcb2B+DrR+hArDuQynI1QFnns72VZYV7Eaz9d18LioWXwW7ulUMa3hhxlBAfBKNtN8Hanlmxw9dBHfBZVCZ//qpKTGOR2fwCgvchw/KPNNEWzc6RyqVc5fn9f0k8D90qsUKsqZy0Bkn2TENUjpSM0cI7Yfk0/VIPaoymkZ251nrHq2kvR3oY/Vwfa5/lBlspleG4IDqFktx3jDDi7nW9TLgKrOUEE8ZhiNAYLiUs4y9r+TMQdL1AGRXViZzfYqfNIrZ2bsNypblvDAGnoz4mP+3XORhKAyqdF8BZ9htgD/2j2d/0bU60eEgBKxEeLUhfX1PMAatGJpyY8WR8iINXqFskMo+sXGdlKZm6OquzbwfdeKFQ/rSrqgeKR5AvZmc8PtkvdO9ksjPuxQjP5GQg+WqmqqeGTytT7dFK7H2wYlgwC5aiBLkKIrUb/ugtPQ57PhNswskp0l7LLiQ3lxSMItB9EU0EgU21hbGwgPGRzYTEwMjRAZXhhbXBsZS5vcmc+iHgEExECADgWIQT0Gp8H96mukJxQ6iMZQG4ejj2AtgUCauGNpAIbAwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRAZQG4ejj2AtmMdAKCSQee+BXaqrjprVvItO7S3Ksr9MgCgn8lbS2UoUDd3cjXITQ5mSk7K5Zs=",
            detached: #"""
-----BEGIN PGP SIGNATURE-----

iF0EABEIAB0WIQT0Gp8H96mukJxQ6iMZQG4ejj2AtgUCauGN2gAKCRAZQG4ejj2A
tn3zAKCwNSCHNRXNJlCPJd0MJW3R4SafTQCbB12/O08qDAOCnIn3ScUFXVdXcDM=
=eYJ3
-----END PGP SIGNATURE-----
"""#,
            clearSigned: #"""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

PGPony build 7 verify test
Second line.
-----BEGIN PGP SIGNATURE-----

iF0EAREIAB0WIQT0Gp8H96mukJxQ6iMZQG4ejj2AtgUCauGNsgAKCRAZQG4ejj2A
tsNDAKCLBBUZAw6Q8xKsl6eqh1fajgSKawCgn4s9ey0VkzfKQki827AMxtzNnlw=
=/Fs2
-----END PGP SIGNATURE-----
"""#,
            inline: #"""
-----BEGIN PGP MESSAGE-----

kA0DAAgRGUBuHo49gLYBrDViB21zZy50eHRq4Y2yUEdQb255IGJ1aWxkIDcgdmVy
aWZ5IHRlc3QKU2Vjb25kIGxpbmUuCohdBAARCAAdFiEE9BqfB/eprpCcUOojGUBu
Ho49gLYFAmrhjbIACgkQGUBuHo49gLbAZgCfVAmqkf9htl0fn35tO8P5W4xdcMAA
oK11qbY9DEcKBBdl4CeHa2xhkDCE
=mTyA
-----END PGP MESSAGE-----
"""#),
        SignedFixture(
            name: "bp256",
            userID: "BP256 Verify <bp256@example.org>",
            publicKey: "mFMEauGNpBMJKyQDAwIIAQEHAgMESxWjB8GT8lI9GP1ExIyCQLsh4TkUwcCqv0QK6gRNXtMp9MnD6cElpX0BMTCCsBIg5TIyGMa9jB7wPPHwvxdlnLQgQlAyNTYgVmVyaWZ5IDxicDI1NkBleGFtcGxlLm9yZz6IkAQTEwgAOBYhBMC6vFa+kJ7SY+4HC0ROSFYPfhzTBQJq4Y2kAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEEROSFYPfhzTLhIBAIDwqEOEIU7lS8EKRaLvxz7J1Sx+tzil5tfRbAd5I9uBAPwIDMG1BdA5jUguLg0+fx6Vka2IK7lqwkJv+O/qf7a8nQ==",
            detached: #"""
-----BEGIN PGP SIGNATURE-----

iHUEABMIAB0WIQTAurxWvpCe0mPuBwtETkhWD34c0wUCauGN2gAKCRBETkhWD34c
0/47AP9pIgSnBx2gydRVKlSugxI4lrm4JComFw7RzqjZ7vD1MQD7BubB1Pot5lJs
rI5oRXtGDhozkh6+mys7SAZib3ZHp80=
=qz+B
-----END PGP SIGNATURE-----
"""#,
            clearSigned: #"""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

PGPony build 7 verify test
Second line.
-----BEGIN PGP SIGNATURE-----

iHUEARMIAB0WIQTAurxWvpCe0mPuBwtETkhWD34c0wUCauGNsgAKCRBETkhWD34c
0/tAAP9ZbRamXGOAFtVhZptXsl8W6LPgUMK1qYfgmnZoTx/TZAD/fAoNxFYqT/Me
NfQx0aVXxdouBqJtaiXybFEFvDW+qIg=
=XY+v
-----END PGP SIGNATURE-----
"""#,
            inline: #"""
-----BEGIN PGP MESSAGE-----

kA0DAAgTRE5IVg9+HNMBrDViB21zZy50eHRq4Y2yUEdQb255IGJ1aWxkIDcgdmVy
aWZ5IHRlc3QKU2Vjb25kIGxpbmUuCoh1BAATCAAdFiEEwLq8Vr6QntJj7gcLRE5I
Vg9+HNMFAmrhjbIACgkQRE5IVg9+HNMzWAD+L7Fc/vTyPKX+x/JZsbWBx0jwoupz
fPotZtiD8QjH77QA/R985nnbNYIjEt+YsD5sFVWSI2XROcIVXCtCtHzwpLow
=RbMj
-----END PGP MESSAGE-----
"""#),
        SignedFixture(
            name: "bp256sha512",
            userID: "BP256 Verify <bp256@example.org>",
            publicKey: "mFMEauGNpBMJKyQDAwIIAQEHAgMESxWjB8GT8lI9GP1ExIyCQLsh4TkUwcCqv0QK6gRNXtMp9MnD6cElpX0BMTCCsBIg5TIyGMa9jB7wPPHwvxdlnLQgQlAyNTYgVmVyaWZ5IDxicDI1NkBleGFtcGxlLm9yZz6IkAQTEwgAOBYhBMC6vFa+kJ7SY+4HC0ROSFYPfhzTBQJq4Y2kAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEEROSFYPfhzTLhIBAIDwqEOEIU7lS8EKRaLvxz7J1Sx+tzil5tfRbAd5I9uBAPwIDMG1BdA5jUguLg0+fx6Vka2IK7lqwkJv+O/qf7a8nQ==",
            detached: #"""
-----BEGIN PGP SIGNATURE-----

iHQEABMKAB0WIQTAurxWvpCe0mPuBwtETkhWD34c0wUCauGN2gAKCRBETkhWD34c
0/S8APjyRqHM5IaOE+6GSUTnBdn9x/bwhFjgOXTbRtd2HvcxAP0YC7xj788SI+Kr
/h/27HiKLD2a6XoLj8tCTL+6hVgNoQ==
=/ARj
-----END PGP SIGNATURE-----
"""#,
            clearSigned: #"""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

PGPony build 7 verify test
Second line.
-----BEGIN PGP SIGNATURE-----

iHUEARMKAB0WIQTAurxWvpCe0mPuBwtETkhWD34c0wUCauGNsgAKCRBETkhWD34c
06G6AP40eBMehQMNI1h3tqqb5dbGL7H83qf+ElKWhFzleiaftwEAgxihonHFVIti
9LOapFPWWw8LYAXt7WEGGNVWqOfmF6I=
=+kC6
-----END PGP SIGNATURE-----
"""#,
            inline: #"""
-----BEGIN PGP MESSAGE-----

kA0DAAoTRE5IVg9+HNMBrDViB21zZy50eHRq4Y2yUEdQb255IGJ1aWxkIDcgdmVy
aWZ5IHRlc3QKU2Vjb25kIGxpbmUuCoh1BAATCgAdFiEEwLq8Vr6QntJj7gcLRE5I
Vg9+HNMFAmrhjbIACgkQRE5IVg9+HNOCbQD/eX2VzRS9ukuVBDmSTtNHy4RC1knL
S/Z3cQbhTKsdDjsA+wXfwiuEe3otFiJjQFKtasnCzOQ2bqS9XIzmmdU3SWuS
=fL8U
-----END PGP MESSAGE-----
"""#),
        SignedFixture(
            name: "bp384",
            userID: "BP384 Verify <bp384@example.org>",
            publicKey: "mHMEauGNpBMJKyQDAwIIAQELAwMEWSRxr5jhnG4u1QzTX9cuLQ50BU6QmbtCg3LWy36da3f0yirLXPnXvxb50Zf/Z2nlCH4h07gyQxUA8iz+OvLo6gNOus8zjqmG/Zar5gAYhdVsBKnJsbN6/guG1VhxFYI2tCBCUDM4NCBWZXJpZnkgPGJwMzg0QGV4YW1wbGUub3JnPoiwBBMTCQA4FiEE2IvH42+CYKZPqssmnPuT4ijDUr4FAmrhjaQCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQnPuT4ijDUr5g0QF/RxD3iu5o5JaR7CweUy71/asNJXSHKzYts1Eezn+bdVxo4sTLMvhGRsq1KLMpu/rLAX9xqrTY79dgtwG46HoS9w3FK8+iRgU7JSPuE/zcJyHDaFzgyd1ynyf8EbZqKbKOk7U=",
            detached: #"""
-----BEGIN PGP SIGNATURE-----

iJUEABMJAB0WIQTYi8fjb4Jgpk+qyyac+5PiKMNSvgUCauGN2gAKCRCc+5PiKMNS
vo5oAX9R8rLxLHwE8qwGqmw2a3Wo1lM2D+NBahZXRHmzxYIB+YvQshE42bDBh0qs
SDCy1EsBfiLvwNSHHAdx96+B6Q+i4r3X25nrYqrrhcC7syofzlt2USzWAK+XL/LH
sRK6X0k9gQ==
=TZ+U
-----END PGP SIGNATURE-----
"""#,
            clearSigned: #"""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA384

PGPony build 7 verify test
Second line.
-----BEGIN PGP SIGNATURE-----

iJUEARMJAB0WIQTYi8fjb4Jgpk+qyyac+5PiKMNSvgUCauGNswAKCRCc+5PiKMNS
vpWmAX9/W3zubAQf+j3GHx8SaQ+4U+ktCA0byUceZJDJcZWYUokGZxrAbKe0eoPM
gRRB0WIBf0wEOmAVI/gccd9DnA6i32uErSNbh9JI4G08z1ylGYRuw2YnpSDXfxrP
g7uL6WKTUw==
=jQX+
-----END PGP SIGNATURE-----
"""#,
            inline: #"""
-----BEGIN PGP MESSAGE-----

kA0DAAkTnPuT4ijDUr4BrDViB21zZy50eHRq4Y2zUEdQb255IGJ1aWxkIDcgdmVy
aWZ5IHRlc3QKU2Vjb25kIGxpbmUuCoiVBAATCQAdFiEE2IvH42+CYKZPqssmnPuT
4ijDUr4FAmrhjbMACgkQnPuT4ijDUr69XQF/e3NdnD/aBkzK94bG/Ni3IcEv35wC
wKVq05Dl+/7jw70VVoS8BkBg9DJCVm66UWazAX4/3x7DsBngebj0rfsOQ8aoKZtd
BgawfyMLN9th9kjxXRWdEByFfcFmV8Y2IbVOwWg=
=ZGJL
-----END PGP MESSAGE-----
"""#),
        SignedFixture(
            name: "bp512",
            userID: "BP512 Verify <bp512@example.org>",
            publicKey: "mJMEauGNpBMJKyQDAwIIAQENBAMEQamht7UgzDL3QUMeOuiO3xE5PG1fS9TyFWQ1tNJAiScv4TvCYAuQTVqk1u/YXM4WeU8VG7NO2i6ejx2142dPGwkR5oTvhZOrnLDBtesZB1VLcDKGa/lBVRMRPIpCCrBxusCuultFW5o9Xkba2gU7rx7YfVefkK3ZIbEg0tZCt5G0IEJQNTEyIFZlcmlmeSA8YnA1MTJAZXhhbXBsZS5vcmc+iNAEExMKADgWIQRxKsA9uKYIRQ6SXd0uIejxan48uwUCauGNpAIbAwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRAuIejxan48ux5ZAgCZ6+gflSbFNVQAmSa4v/c/XbcJw50e6kzFl+mFvfTdEhfjrFiWtDCBvvcp5sMsYVPVLTzG0wQ8NcDhdQ9pnsQaAf9Om6UG2sOjZKv0/zca7B3W7QL3VY40ATbVX+ckxoG68RyvqE2nia+v2ZHBtEsE/vHirKGAXo9ldi4ehvGN7ZrE",
            detached: #"""
-----BEGIN PGP SIGNATURE-----

iLUEABMKAB0WIQRxKsA9uKYIRQ6SXd0uIejxan48uwUCauGN2gAKCRAuIejxan48
u3MTAf9Tb/aUhuoy6VK+v/0LlGNru8/PnyNP1mON0akTobekLeUcUuXay2iXBs+u
qiQ18pNwWncNXPp55G3gkPxuDPbTAgCiZuVNAlm978Oj36H8VaXLN21SmAS3AlWX
AN5ikBoQ1FjCHW49IN8hChGHVe3VAQsovlYrHikipZs6FhRF+UMg
=Igc8
-----END PGP SIGNATURE-----
"""#,
            clearSigned: #"""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

PGPony build 7 verify test
Second line.
-----BEGIN PGP SIGNATURE-----

iLUEARMKAB0WIQRxKsA9uKYIRQ6SXd0uIejxan48uwUCauGNswAKCRAuIejxan48
uzGsAf4u4E19ExnblwcNeNlkZ1LgmpOBAk54BpOUxsX+JExT5KDWLCG3+70B/D4N
JPtE5hwbn7BfCA8iReSHRDQ5oIfNAf44Kzqc86d7Nsx0nO+eyIfnotsa4OhCdf2p
nBmZgAOUWZj9tKDPa56Lqf382IRCyxyrpg/7lwG+kJ7Zxc1vcCuN
=5Q+b
-----END PGP SIGNATURE-----
"""#,
            inline: #"""
-----BEGIN PGP MESSAGE-----

kA0DAAoTLiHo8Wp+PLsBrDViB21zZy50eHRq4Y2zUEdQb255IGJ1aWxkIDcgdmVy
aWZ5IHRlc3QKU2Vjb25kIGxpbmUuCoi1BAATCgAdFiEEcSrAPbimCEUOkl3dLiHo
8Wp+PLsFAmrhjbMACgkQLiHo8Wp+PLunNAH+OJINlfzuGZmHHgTtphlUr+twsyVK
5Lh7isQIXZAIyn4qyYg5125O7lqevO0zVthUM2/7kbVPw+V6IoClEj69AAIAmFlK
JOhezgAmPFo855cmEpaYw0LC22ggcoqGF5DzBsu1MvZ/VfxRrF+SsauvEaPyKg6p
dUcQaZDs0pRNpCfVPw==
=axJH
-----END PGP MESSAGE-----
"""#),
    ]
}
