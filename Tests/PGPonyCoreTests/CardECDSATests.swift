// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CardECDSATests.swift
// PGPonyCoreTests
//
// 8.4.0 build 10 (plan 5m): hardware key ECDSA signing on NIST curves, and the
// "N keys" count for a shared identity (Android 4.6.0 item 20).
//
// The card exchange itself needs hardware (checked on a Token2). What is tested
// here is everything around it: the C1 attributes to algorithm mapping, the hash
// per curve, the card input cut, the split of the card's r || s into MPIs, and
// the packet framing. The three vectors are v4 ECDSA signatures that gpg 2.4.4
// verified: a Python mirror of CardSigner signed each with a scratch NIST key
// (example.invalid User IDs) the way a card answers, r || s raw. ECDSA is not
// deterministic, so the Swift side rebuilds each packet body from its parts
// through `signatureMPIs(fromCardOutput:)` and `assembleSignatureBody` and must
// match the bytes gpg accepted, and the signature must verify over the digest
// `CardSignatureAlgorithm.digest` makes.
//
// Ported from the app's Build10CardTests.swift. The tests there that need the app's
// storage, models or secret-key unlock stay in the app.

import XCTest
import CryptoKit
@testable import PGPonyCore

@MainActor
final class CardECDSATests: XCTestCase {

    // MARK: - Fixtures

    private struct Vector {
        let curve: NISTCurve
        let point: String
        let message: String
        let packet: String
    }

    /// gpg 2.4.4 printed "Good signature" for each packet over its message.
    private let vectors: [Vector] = [
        Vector(
            curve: .p256,
            point: """
                04a42b159f136adf792aeb2624eb0a7587578e6f585169e6be34c0ba7c99758c9503ce5609b93714ab32cdeb4b36b925
                5588e80d458e234245b5a77ddc6bb8b0e0
                """,
            message: """
                0c9d668b0b779df3f9cb6278d0fe0d6cedded33cf4420711ea655364911130eb0361857f09aee46f319d1e096bda20f8
                df99636172642065636473612074657374
                """,
            packet: """
                c27504001308001d05026ae505ac162104f04610a8c40877e0140bb64a88076800e4d1de3e000a091088076800e4d1de
                3e4adf00fd1132abd601a5fe35d563df8ad3d797441da5976da018fd9de613e623b1957ff100ff51b2ae486b8573a8d9
                52b82318737d31d5b0ac4ae22782aa77d377884930fe78
                """
        ),
        Vector(
            curve: .p384,
            point: """
                0497206634a5b549621cd45c2de6d67822ab7b2c964ad7d9f658e4661eb87e90250e06c5400cca85944054d63a916bad
                06702da45a882c3885c46c24636513e6c68067705364c552d8eb14830fd32f51b715f81f3b4fc5287abc23743d7832dd
                b1
                """,
            message: """
                b738c39d0fbb189ba55362e285e29ec573031a5f00ba8f4e670d9e028a3f87adb049b720e76768cfc2be583e3582c0ae
                34c2636172642065636473612074657374
                """,
            packet: """
                c29504001309001d05026ae505ad162104f9f946cdaad0db8dbe1403a7e6fbbea7d8b122c3000a0910e6fbbea7d8b122
                c3ee4f0180db5d4466d71be5474b249fc708d6c62b1bb5df119d317d19667f3ae04ba9a1b9f43f0f2b91241b2bdbbf60
                7f8ee3f5fe0180e013888af3527d6da88467741b289b119d547d9edde6fc5ed3792d099f74270e0c5ed2813e0b0e63ef
                36876e9cad4a41
                """
        ),
        Vector(
            curve: .p521,
            point: """
                0401f0085622520bbc3d737ba0cde421d4ad79f6005ef731c60a60548a98bf2e7dd0e79411f52243d19388db005eaa53
                e35b71971fbf3e2af0c3d19842e4b9efd07f1f008ed0c4441d8b190adaa905761505a78c210bacb04d3ee8dbada12414
                fbdd5e644450451bf65cbb185f9c2273ab77a5da96f9d602d31780f0eb95485bc29b960848
                """,
            message: """
                d768d85d2973d67b4ccd4b6e2c1f31c0c86c609c37f65484fbfad7b01f26a858b268d0ad82c8195b1a7f2ef9be5d2576
                192d636172642065636473612074657374
                """,
            packet: """
                c2b80400130a001d05026ae505ae16210428dfeb0bfbee8d15247d1e8ae9138d28862cf567000a0910e9138d28862cf5
                679728020901a4cf2a220a61cd8655244ec55a5d6460fbee34baa869e1e49ca636e4cc327ff332498f9c1afdddfe6452
                1c7bd988cc49dac02b240239133db00ab3ced2e574de920208bcef86c48e34b7a2a27cde2006dbea21832b885274c764
                edc85d068682d9eeb5eb6874acc3617b398d9155431a534d0134902117cce7fa97e5d45545ef49f8700c
                """
        ),
    ]

    private func bytes(_ hex: String) -> [UInt8] {
        let clean = hex.filter { !$0.isWhitespace }
        var out: [UInt8] = []
        var i = clean.startIndex
        while i < clean.endIndex {
            let j = clean.index(i, offsetBy: 2)
            out.append(UInt8(clean[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    private func u16(_ b: [UInt8], _ i: Int) -> Int { Int(b[i]) << 8 | Int(b[i + 1]) }

    /// Parts of a v4 signature packet body, read by hand.
    private struct SigParts {
        let sigType: UInt8
        let pubAlgo: UInt8
        let hashAlgo: UInt8
        let hashed: [UInt8]
        let unhashed: [UInt8]
        let prefix: [UInt8]
        let mpis: [[UInt8]]
    }

    private func parts(_ body: [UInt8]) -> SigParts {
        var i = 4
        let hl = u16(body, i); i += 2
        let hashed = Array(body[i..<(i + hl)]); i += hl
        let ul = u16(body, i); i += 2
        let unhashed = Array(body[i..<(i + ul)]); i += ul
        let prefix = Array(body[i..<(i + 2)]); i += 2
        var mpis: [[UInt8]] = []
        while i < body.count {
            let bits = u16(body, i); i += 2
            let n = (bits + 7) / 8
            mpis.append(Array(body[i..<(i + n)])); i += n
        }
        return SigParts(sigType: body[1], pubAlgo: body[2], hashAlgo: body[3],
                        hashed: hashed, unhashed: unhashed, prefix: prefix, mpis: mpis)
    }

    private func attributes(_ curve: NISTCurve, algo: UInt8 = 0x13, format: UInt8? = nil) -> [UInt8] {
        [algo] + curve.oid + (format.map { [$0] } ?? [])
    }

    // MARK: - C1 attributes to algorithm

    func testECDSAAttributesMapToCurve() {
        for curve in NISTCurve.allCases {
            XCTAssertEqual(CardSignatureAlgorithm(attributes: attributes(curve)), .ecdsa(curve))
            // With the trailing format octet some cards add.
            XCTAssertEqual(CardSignatureAlgorithm(attributes: attributes(curve, format: 0xFF)), .ecdsa(curve))
            XCTAssertEqual(CardAlgorithmAttributes.nistCurve(attributes(curve)), curve)
            XCTAssertEqual(CardAlgorithmAttributes.nistCurve(attributes(curve, algo: 0x12)), curve)
        }
    }

    func testOtherAttributesKeepTheirMapping() {
        let ed25519: [UInt8] = [0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]
        XCTAssertEqual(CardSignatureAlgorithm(attributes: ed25519), .eddsa)
        XCTAssertEqual(CardSignatureAlgorithm(attributes: [0x01, 0x08, 0x00, 0x00, 0x11, 0x00]), .rsa)
        // ECDSA on brainpool or secp256k1 is not signed with.
        let brainpool: [UInt8] = [0x13, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07]
        let secp256k1: [UInt8] = [0x13, 0x2B, 0x81, 0x04, 0x00, 0x0A]
        XCTAssertNil(CardSignatureAlgorithm(attributes: brainpool))
        XCTAssertNil(CardSignatureAlgorithm(attributes: secp256k1))
        XCTAssertNil(CardSignatureAlgorithm(attributes: []))
        XCTAssertNil(CardAlgorithmAttributes.nistCurve(ed25519))
        // The bare ID still cannot name an ECDSA curve.
        XCTAssertNil(CardSignatureAlgorithm(cardAlgoID: 0x13))
        // Extra octets after OID and format are not a NIST curve.
        XCTAssertNil(CardAlgorithmAttributes.nistCurve(attributes(.p384) + [0xFF, 0x00]))
    }

    func testDisplayNameUnchangedForNISTAttributes() {
        XCTAssertEqual(CardAlgorithmAttributes.parse(attributes(.p256))?.displayName, "NIST P-256")
        XCTAssertEqual(CardAlgorithmAttributes.parse(attributes(.p521, format: 0xFF))?.displayName, "NIST P-521")
    }

    // MARK: - Hash, header, packet algorithm

    func testHashFollowsCurve() {
        XCTAssertEqual(CardSignatureAlgorithm.eddsa.hashAlgorithmID, 8)
        XCTAssertEqual(CardSignatureAlgorithm.rsa.hashAlgorithmID, 8)
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p256).hashAlgorithmID, 8)
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p384).hashAlgorithmID, 9)
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p521).hashAlgorithmID, 10)
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p256).armorHashName, "SHA256")
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p384).armorHashName, "SHA384")
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p521).armorHashName, "SHA512")
        XCTAssertEqual(CardSignatureAlgorithm.rsa.armorHashName, "SHA256")
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p384).packetAlgorithmID, 19)
    }

    func testDigestAndStreamingHasherAgree() {
        let data = Data((0..<1000).map { UInt8($0 & 0xFF) })
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p256).digest(data), Array(SHA256.hash(data: data)))
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p384).digest(data), Array(SHA384.hash(data: data)))
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p521).digest(data), Array(SHA512.hash(data: data)))
        XCTAssertEqual(CardSignatureAlgorithm.eddsa.digest(data), Array(SHA256.hash(data: data)))
        var hasher = CardDigestHasher(hashAlgorithmID: 9)
        hasher.update(data: Array(data.prefix(300)))
        hasher.update(data: Array(data.dropFirst(300)))
        XCTAssertEqual(hasher.finalize(), Array(SHA384.hash(data: data)))
    }

    // MARK: - Card input

    func testCardInputForECDSAIsTheHashCutToTheCurve() {
        let d32 = [UInt8](repeating: 0x11, count: 32)
        let d48 = [UInt8](repeating: 0x22, count: 48)
        let d64 = (0..<64).map { UInt8($0) }
        // Natural hashes go as they are, no DigestInfo.
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p256).cardInput(forDigest: d32), d32)
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p384).cardInput(forDigest: d48), d48)
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p521).cardInput(forDigest: d64), d64)
        // A longer hash keeps its leftmost field-size octets.
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p256).cardInput(forDigest: d64), Array(d64.prefix(32)))
        XCTAssertEqual(CardSignatureAlgorithm.ecdsa(.p384).cardInput(forDigest: d64), Array(d64.prefix(48)))
        // EdDSA and RSA as before.
        XCTAssertEqual(CardSignatureAlgorithm.eddsa.cardInput(forDigest: d32), d32)
        XCTAssertEqual(CardSignatureAlgorithm.rsa.cardInput(forDigest: d32), CardSigner.sha256DigestInfo(d32))
    }

    // MARK: - Card output

    func testRawOutputSplitsIntoRAndS() throws {
        for curve in NISTCurve.allCases {
            let r = [UInt8](repeating: 0x01, count: curve.fieldSize)
            let s = [UInt8](repeating: 0x02, count: curve.fieldSize)
            let mpis = try CardSignatureAlgorithm.ecdsa(curve).signatureMPIs(fromCardOutput: r + s)
            XCTAssertEqual(mpis, [r, s])
        }
    }

    func testWrongLengthIsRefused() {
        XCTAssertThrowsError(try CardSignatureAlgorithm.ecdsa(.p384).signatureMPIs(fromCardOutput: [UInt8](repeating: 1, count: 64)))
        XCTAssertThrowsError(try CardSignatureAlgorithm.ecdsa(.p256).signatureMPIs(fromCardOutput: []))
        XCTAssertThrowsError(try CardSignatureAlgorithm.eddsa.signatureMPIs(fromCardOutput: [UInt8](repeating: 1, count: 96)))
    }

    func testDERAnswerIsTakenAsAFallback() throws {
        // r with its top bit set (DER adds a 0x00), s short (DER drops zeros).
        let r: [UInt8] = [0x80] + [UInt8](repeating: 0x33, count: 31)
        let s: [UInt8] = [0x00, 0x00] + [UInt8](repeating: 0x44, count: 30)
        let derR: [UInt8] = [0x02, 0x21, 0x00] + r
        let derS: [UInt8] = [0x02, 0x1E] + Array(s.dropFirst(2))
        let der: [UInt8] = [0x30, UInt8(derR.count + derS.count)] + derR + derS
        XCTAssertEqual(CardSignatureAlgorithm.ecdsaRawSignature(der, curve: .p256), r + s)
        let mpis = try CardSignatureAlgorithm.ecdsa(.p256).signatureMPIs(fromCardOutput: der)
        XCTAssertEqual(mpis, [r, s])
        // Not DER and the wrong length.
        XCTAssertNil(CardSignatureAlgorithm.ecdsaRawSignature([0x30, 0x02, 0x02, 0x00], curve: .p256))
    }

    // MARK: - Packets gpg accepted

    func testSwiftFramingMatchesSignaturesGPGVerified() throws {
        for v in vectors {
            let algorithm = CardSignatureAlgorithm.ecdsa(v.curve)
            let packets = try OpenPGPPacketParser.parsePackets(data: bytes(v.packet))
            XCTAssertEqual(packets.count, 1)
            let body = try XCTUnwrap(packets.first).body
            let p = parts(body)
            XCTAssertEqual(p.pubAlgo, 19)
            XCTAssertEqual(p.hashAlgo, algorithm.hashAlgorithmID)
            XCTAssertEqual(p.mpis.count, 2)

            // The card's answer, r || s each padded to the field size.
            let r = try XCTUnwrap(v.curve.padded(p.mpis[0]))
            let s = try XCTUnwrap(v.curve.padded(p.mpis[1]))
            let rebuilt = CardSigner.assembleSignatureBody(
                pubkeyAlgo: algorithm.packetAlgorithmID, sigType: p.sigType,
                hashed: p.hashed, unhashed: p.unhashed, hashPrefix2: p.prefix,
                signatureMPIs: try algorithm.signatureMPIs(fromCardOutput: r + s),
                hashAlgorithm: algorithm.hashAlgorithmID
            )
            XCTAssertEqual(rebuilt, body, "\(v.curve)")

            // The digest CardSigner hashes, and the signature over it.
            let trailer: [UInt8] = [4, p.sigType, 19, p.hashAlgo, UInt8(p.hashed.count >> 8), UInt8(p.hashed.count & 0xFF)] + p.hashed
            let n = UInt32(trailer.count)
            var input = Data(bytes(v.message))
            input.append(contentsOf: trailer)
            input.append(contentsOf: [4, 0xFF, UInt8(n >> 24), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)])
            let digest = algorithm.digest(input)
            XCTAssertEqual(Array(digest.prefix(2)), p.prefix)
            XCTAssertEqual(algorithm.cardInput(forDigest: digest), digest)
            XCTAssertTrue(try NISTECDSAService.verify(r: r, s: s, digest: digest, curve: v.curve, publicPoint: bytes(v.point)), "\(v.curve)")
        }
    }

    func testAssembleSignatureBodyDefaultsToSHA256() {
        let body = CardSigner.assembleSignatureBody(
            pubkeyAlgo: 22, sigType: 0, hashed: [], unhashed: [], hashPrefix2: [0, 0], signatureMPIs: [])
        XCTAssertEqual(Array(body.prefix(4)), [4, 0, 22, 8])
    }
}
