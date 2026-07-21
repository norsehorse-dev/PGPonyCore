// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// LibrePGPEncryptTests.swift
// PGPony — Phase F (PQC), LibrePGP / GnuPG interop (encrypt side).
//
// Fixture: the real v5 Kyber (algorithm 8 = ML-KEM-768 + X25519) encryption
// subkey from a GnuPG 2.5.x public key ("pqc-pub.asc"). These tests prove
// LibrePGPEncryptService parses that subkey (v5 fingerprint / key ID match),
// emits a well-formed v3 PKESK with GnuPG's exact field framing, and produces a
// tag-20 OCB body that round-trips through PGPony's own tag-20 decoder (which
// was written to read GnuPG 2.4.x output). Full KEM correctness is proven
// separately by gpg decrypting a PGPony-produced message end to end.

import XCTest
@testable import PGPonyCore

final class LibrePGPEncryptTests: XCTestCase {

    // Real GnuPG v5 Kyber subkey packet (tag 14), key ID 9dc4fc553d3f79c3.
    private let subkeyPacket = hex("""
cec415056a56fdab08000004cb032b656e010740244e11ac55ddc2ded123c4e9274911351d7409
b0dd478ec2f4942af302adec27000004a0a4a00070888560456b03c5012d23a73f24cd47814f2f
d8ba2557ce66e35f405911ab32adccaabd42a9be8eec4d5e0716695c4ee3693ae0899d57ac605e
9692dabc7060a48b514b880d639bdf847568c580bc02adf5aa982fc01b907a8bbc9835ea6c5cce
16c08170089184bdd0fb55902a1c4f4b7d619460b2fa3e8019c1b588cebda090ae4555e024743c
9673f4a406ddbb7b9631244801bec8340bfe384a3a836633548499c12d3f1b41b824ced6f28a0b
d008005ac3317cc1467a6dc9aacdbee9b623974055091a831bc754a51f1e9a6543c69f951832e7
f019970920562a3bac690962dc979e8197b055beef9a65e4940622867f92484e51e7cc74f433ce
5b3040994c3214b5f54048680c05f93a53aafb8fd3235176966e13d86dc5d9269c21621f274eaa
2bac2016b21a2b1b91614c4049a24b365fb8cc3340bbaaa21cc41cd11509867a1c181a30a149f3
8b97a5556a7a61265d540fc0c23ab20a7a1e01aed6a3be71fb055a71aa87685d147432f7ec26ed
d25b5e1ca586334c1af16a292620865b61c33ac193223757718e7695b642dc7928dab35da48c7d
1ca50d9b5c9f2a7607ebaee5a05561bba61843b0dfa07fbf4b02f27b79d56a305792146148b99e
876c2f3279aeb81ebbe84043e00756441bd9781e78678d88bb64851bbfe1704acc5268a5a4b4e2
2b8847aba983f7516f2bc824528b7f38162fc9759b12a085d3c92fcb01520b5d24f6370b456116
3345f2a23dcdb5c9e7a96aedc2adc062a8f2931cfbd6879c03b77ab623bee42d0fb2c0db358085
abc6be6a902562ccd6e9bfdf6a4ece1091b84a8ea1198e458b827250a5535cb2aad14062c74370
131e3173aae4f409e057094311b833593f4afaaa3ac4a1b5194d5e1230319a9c83040704c52271
e654f3a5ccf974a4b3eb77cef75a2db61645e3131bea514e43c199778edc1667e92a033b64c846
f4ad66b1c520b1b20b237c407571f9a156f786285c2876751782a5c9c433f05a90c207a0c6c220
0bb806469d094073fdb8a1de0cb516a73e15eb77c0574ed87896f3515b42d5630313b834ec1fe4
939f41ca65788a2d0eb1822f5871df7a019c70b393601493d74cf4b63454fa59864794731a1c1f
d925fc35c8c680b0e88b39472b955346aff4bb7007b68097ec697f70a54a8322bab88801b881a3
7a26ce7abf389b5189294949492ae1a98ccb4009e8eccd0089a217f443fb762b73164fe7daa3a2
25704ea98c42b2839ed6748904cfc0d9035d0594112a2d97785029838ff4e878ab4a7532a0786a
eb43d5984d07d51f46893ba33b56c8f43e8cd114afbc4b9d35280f57b97d148a5f4220b1e870db
1b5fbc1785ec381b58d0692523685d950811c657e821a97702ab57e43ffe2a2995b65af7844d1e
49992faa5d538843aebab5e54aa31e32a27c240d511c68a4cba28b247c7e26bf9c0c315443709c
5b9c80f825f87b3aacb42d37241890bc0f1f7c90bc41a9c1b367640981bb63869a01573143b901
0bb5ab049e797bae1a97996db06280cb730aa5af045c08931a2b2da5584ea8a422172b9d7769de
5c16cf3a838a224a2135cc511b4cdd38680001af726363203c09ff7cbbe615822e5c91133c50f6
2d41aa197718ae0b324b48efc109c684d1042c22cbbadef0d2a414af61c169
""")

    private func recipient() throws -> LibrePGPEncryptService.Recipient {
        let packets = try OpenPGPPacketParser.parsePackets(data: [UInt8](subkeyPacket))
        let body = packets.first { $0.tag == 14 }!.body
        return try LibrePGPEncryptService.parseV5KyberSubkey(packetBody: body)
    }

    func testParsesRealGnuPGKyberSubkey() throws {
        let r = try recipient()
        XCTAssertEqual(r.eccPublic.count, 32, "X25519 public must be 32 octets")
        XCTAssertEqual(r.mlkemPublic.count, 1184, "ML-KEM-768 public must be 1184 octets")
        XCTAssertEqual(r.v5Fingerprint.count, 32)
        // v5 fingerprint (SHA-256, 0x9A prefix) — leading 8 octets are the PKESK key ID.
        XCTAssertEqual(hex(r.keyID), "9dc4fc553d3f79c3",
                       "parsed key ID must match GnuPG's PKESK key ID")
    }

    func testBuildsWellFormedV3PKESK() throws {
        let r = try recipient()
        let message = try LibrePGPEncryptService.encrypt(
            plaintext: Array("hello librepgp".utf8), recipient: r)

        let packets = try OpenPGPPacketParser.parsePackets(data: message)
        XCTAssertEqual(packets.count, 2, "message = PKESK(tag1) + OCB data(tag20)")
        let pkesk = packets[0]
        XCTAssertEqual(pkesk.tag, 1)
        let b = pkesk.body
        XCTAssertEqual(b[0], 3, "v3 PKESK")
        XCTAssertEqual(Array(b[1..<9]), r.keyID, "PKESK key ID = recipient key ID")
        XCTAssertEqual(b[9], 8, "public-key algorithm = Kyber (8)")
        // ecc ciphertext: 256-bit SOS = 0x01 0x00 || 32 octets.
        XCTAssertEqual(b[10], 0x01); XCTAssertEqual(b[11], 0x00)
        var o = 12 + 32
        // ml-kem ciphertext: 4-octet length = 1088.
        let mlen = Int(b[o]) << 24 | Int(b[o+1]) << 16 | Int(b[o+2]) << 8 | Int(b[o+3])
        XCTAssertEqual(mlen, 1088, "ML-KEM ciphertext length")
        o += 4 + mlen
        // wrapped session key: symAlgo(9=AES-256) || len(40) || C.
        XCTAssertEqual(b[o], 9, "session-key algorithm = AES-256")
        XCTAssertEqual(b[o+1], 40, "AES-256 key-wrap of a 32-octet key is 40 octets")
        XCTAssertEqual(b.count, o + 2 + 40, "PKESK has no trailing bytes")
    }

    func testTag20BodyRoundTripsThroughPGPonyDecoder() throws {
        // Known session key so we can decrypt with PGPony's tag-20 decoder.
        let sessionKey = (0..<32).map { UInt8($0 &* 7 &+ 1) }
        let plaintext = Array("The quick brown fox — LibrePGP OCB round trip.".utf8)

        let packet = try LibrePGPEncryptService.buildTag20OCB(
            plaintext: plaintext, sessionKey: sessionKey, filename: nil)

        let parsed = try OpenPGPPacketParser.parsePackets(data: packet)
        XCTAssertEqual(parsed.first?.tag, 20)
        let out = try OpenPGPPacketParser.decryptTag20AEAD(
            packetBody: parsed[0].body, sessionKey: sessionKey)

        // The decrypted inner stream is a literal data packet wrapping the text.
        XCTAssertNotNil(Data(out).range(of: Data(plaintext)),
                        "tag-20 OCB body must decrypt back to the original literal data")
    }

    /// Known-answer test for the composite KEK derivation — the exact step that
    /// was wrong at first (raw X25519 instead of SHA3-256(rawECDH‖ecc_ct‖ecc_pk)).
    /// Expected KEK computed independently (pycryptodome KMAC256 over GnuPG's
    /// framing); patterned inputs mirror LibrePGPCombinerTests.
    func testCompositeKEKKnownAnswer() {
        func pat(_ n: Int, _ a: Int, _ b: Int) -> [UInt8] { (0..<n).map { UInt8(($0 * a + b) & 0xff) } }
        let kek = LibrePGPEncryptService.compositeKEK(
            rawECDH: pat(32, 3, 1),
            eccCipherText: pat(32, 5, 2),
            eccPublic: pat(32, 7, 3),
            mlkemShared: pat(32, 11, 4),
            mlkemCipherText: pat(1088, 13, 5),
            sessionKeyAlgo: 9,
            v5Fingerprint: pat(32, 17, 6))
        XCTAssertEqual(hex(kek),
                       "a22bc5fd360a3b3440d863f1b03a3b79d175f292f95f6247182ca1edc26cafa1",
                       "composite KEK must match GnuPG's SHA3-256 ecc_ss + KMAC256 combiner")
    }

    /// Not a pass/fail assertion of KEM correctness (that needs GnuPG's secret,
    /// which is a gnu-mode1003 stub). Instead this emits a real PGPony-produced
    /// LibrePGP message as base64 in the test log. Runs in the Simulator sandbox,
    /// so it prints rather than writes a Mac file. To prove end-to-end interop,
    /// copy the base64 between the markers and on your Mac run:
    ///   pbpaste | base64 -d | gpg --passphrase pgpony-test -d
    /// (or: echo '<base64>' | base64 -d | gpg --passphrase pgpony-test -d)
    func testEmitMessageForGPGInterop() throws {
        let r = try recipient()
        let plaintext = Array("PGPony -> GnuPG LibrePGP PQC interop OK\n".utf8)
        let message = try LibrePGPEncryptService.encrypt(plaintext: plaintext, recipient: r)
        let b64 = Data(message).base64EncodedString()
        print("LIBREPGP-INTEROP-BEGIN")
        print(b64)
        print("LIBREPGP-INTEROP-END (\(message.count) bytes)")
        XCTAssertGreaterThan(message.count, 1100)   // PKESK(~1178) + tag20 body
    }

    private static func hex(_ s: String) -> Data {
        let c = s.filter { $0.isHexDigit }; var o = Data(capacity: c.count/2); var i = c.startIndex
        while i < c.endIndex { let n = c.index(i, offsetBy: 2); o.append(UInt8(c[i..<n], radix: 16)!); i = n }
        return o
    }
    private func hex(_ s: String) -> Data { Self.hex(s) }
    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
}
