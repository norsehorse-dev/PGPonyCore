// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// LibrePGPKeyGenTests.swift
// PGPony — Phase F (PQC), LibrePGP (algorithm 8) key generation.
//
// Ed25519KeyGenerator.generate(pqcEncryption: true) produces the GnuPG-flavored
// LibrePGP PQC key: a v4 EdDSA primary with a v5 Kyber (ML-KEM-768 + X25519,
// algorithm 8) encryption subkey, bound by a v4 subkey-binding signature that
// hashes the v5 subkey with the 0x9A/4-octet framing GnuPG expects. Tests cover
// the byte layout, that the binding + certification signatures actually verify
// (strict-MPI, the way GnuPG reads them), and emit the cert for gpg interop.

import XCTest
import CryptoKit
@testable import PGPonyCore

final class LibrePGPKeyGenTests: XCTestCase {

    private func generated(pqc: Bool = true) throws -> Ed25519KeyGeneratorResult {
        try Ed25519KeyGenerator.generate(
            name: "PGPony LibrePGP", email: "librepgp@pgpony.test",
            passphrase: nil, expirationInterval: nil, pqcEncryption: pqc)
    }

    func testGeneratesV4PrimaryWithV5KyberSubkey() throws {
        let r = try generated()
        let pkts = try OpenPGPPacketParser.parsePackets(data: [UInt8](r.publicKeyData))

        let prim = pkts.first { $0.tag == 6 }
        XCTAssertNotNil(prim)
        XCTAssertEqual(prim!.body[0], 4, "primary must be v4")
        XCTAssertEqual(prim!.body[5], 22, "primary must be EdDSA (22)")

        let sub = pkts.first { $0.tag == 14 }
        XCTAssertNotNil(sub)
        let b = sub!.body
        XCTAssertEqual(b[0], 5, "subkey must be v5")
        XCTAssertEqual(b[5], 8, "subkey must be Kyber (algorithm 8)")
        let keyMatLen = Int(b[6]) << 24 | Int(b[7]) << 16 | Int(b[8]) << 8 | Int(b[9])
        XCTAssertEqual(keyMatLen, 1227, "OID(4) + eccSOS(35) + mlkemLen+key(1188)")
        XCTAssertEqual(Array(b[10..<14]), [0x03, 0x2b, 0x65, 0x6e])
        XCTAssertEqual(b[14], 0x01); XCTAssertEqual(b[15], 0x07)
        XCTAssertEqual(b[16], 0x40)
        let mlkemLen = Int(b[49]) << 24 | Int(b[50]) << 16 | Int(b[51]) << 8 | Int(b[52])
        XCTAssertEqual(mlkemLen, 1184)

        let subIdx = pkts.firstIndex { $0.tag == 14 }!
        let bind = pkts[(subIdx + 1)...].first { $0.tag == 2 }
        XCTAssertNotNil(bind)
        XCTAssertEqual(bind!.body[0], 4, "binding sig is v4")
        XCTAssertEqual(bind!.body[1], 0x18, "type 0x18 subkey binding")
    }

    /// The LibrePGP subkey-binding signature must verify under strict-MPI reading
    /// (0x9A/4-octet v5 subkey framing).
    func testLibrePGPBindingSignatureVerifies() throws {
        let r = try generated()
        let pkts = try OpenPGPPacketParser.parsePackets(data: [UInt8](r.publicKeyData))
        try verifyBinding(pkts, subkeyIsV5: true)
    }

    /// Regression for the EdDSA R/S MPI leading-zero bug: an R or S with a high
    /// zero octet was serialized as an over-long MPI that GnuPG/Sequoia rejected.
    /// Generate many classical keys and strict-verify each binding + cert sig so a
    /// leading-zero case (~1/256 per value) is very likely to be exercised.
    func testEdDSASignatureMPIsAreCanonical() throws {
        for _ in 0..<200 {
            let r = try generated(pqc: false)
            let pkts = try OpenPGPPacketParser.parsePackets(data: [UInt8](r.publicKeyData))
            try verifyBinding(pkts, subkeyIsV5: false)
            try verifyCertification(pkts)
        }
    }

    func testEmitLibrePGPKeyForGPGInterop() throws {
        let r = try generated()
        let pub = XCTAttachment(data: Data(r.armoredPublicKey.utf8))
        pub.name = "pgpony-librepgp-pub.asc"; pub.lifetime = .keepAlways; add(pub)
        let sec = XCTAttachment(data: Data(r.armoredPrivateKey.utf8))
        sec.name = "pgpony-librepgp-sec.asc"; sec.lifetime = .keepAlways; add(sec)
    }

    // MARK: - Strict-MPI signature verification helpers

    private func edPublicKey(fromPrimary body: [UInt8]) throws -> Curve25519.Signing.PublicKey {
        var o = 1 + 4 + 1                       // version + ctime + algo
        let oidLen = Int(body[o]); o += 1 + oidLen
        let bits = Int(body[o]) << 8 | Int(body[o + 1]); o += 2
        let nb = (bits + 7) / 8
        var q = Array(body[o..<(o + nb)])
        if q.first == 0x40 { q.removeFirst() }
        return try Curve25519.Signing.PublicKey(rawRepresentation: Data(q))
    }

    /// Parse a v4 signature; return (hashAlgo, hashed portion, 64-byte R‖S) reading
    /// each MPI as exactly ceil(bitlen/8) octets — the strict behaviour of GnuPG.
    private func parseSig(_ s: [UInt8]) -> (UInt8, [UInt8], Data) {
        let ha = s[3]
        let hlen = Int(s[4]) << 8 | Int(s[5])
        let hp = Array(s[0..<(6 + hlen)])
        var o = 6 + hlen
        let ulen = Int(s[o]) << 8 | Int(s[o + 1]); o += 2 + ulen
        o += 2                                  // left-16-bits quick check
        func mpi(_ off: Int) -> ([UInt8], Int) {
            let bits = Int(s[off]) << 8 | Int(s[off + 1]); let n = (bits + 7) / 8
            return (Array(s[(off + 2)..<(off + 2 + n)]), off + 2 + n)
        }
        let (r, o2) = mpi(o); let (ss, _) = mpi(o2)
        func pad(_ b: [UInt8]) -> [UInt8] { [UInt8](repeating: 0, count: 32 - b.count) + b }
        return (ha, hp, Data(pad(r) + pad(ss)))
    }

    private func keyFrame(_ body: [UInt8], prefix: UInt8, lenBytes: Int) -> [UInt8] {
        var out: [UInt8] = [prefix]
        let n = body.count
        if lenBytes == 2 { out += [UInt8(n >> 8), UInt8(n & 0xFF)] }
        else { out += [UInt8(n >> 24), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)] }
        return out + body
    }

    private func trailer(_ hp: [UInt8]) -> [UInt8] {
        let n = hp.count
        return [0x04, 0xFF, UInt8(n >> 24), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)]
    }

    private func verifyBinding(_ pkts: [ParsedPacket], subkeyIsV5: Bool) throws {
        let primary = pkts.first { $0.tag == 6 }!.body
        let subkey = pkts.first { $0.tag == 14 }!.body
        let subIdx = pkts.firstIndex { $0.tag == 14 }!
        let bind = pkts[(subIdx + 1)...].first { $0.tag == 2 }!.body
        let (ha, hp, sig) = parseSig(bind)
        XCTAssertEqual(ha, 8, "SHA-256")
        let subFrame = subkeyIsV5
            ? keyFrame(subkey, prefix: 0x9A, lenBytes: 4)
            : keyFrame(subkey, prefix: 0x99, lenBytes: 2)
        let hashData = keyFrame(primary, prefix: 0x99, lenBytes: 2) + subFrame + hp + trailer(hp)
        let digest = Data(SHA256.hash(data: Data(hashData)))
        let pub = try edPublicKey(fromPrimary: primary)
        XCTAssertTrue(pub.isValidSignature(sig, for: digest),
                      "subkey-binding signature must verify (strict MPI)")
    }

    private func verifyCertification(_ pkts: [ParsedPacket]) throws {
        let primary = pkts.first { $0.tag == 6 }!.body
        let uid = pkts.first { $0.tag == 13 }!.body
        let cert = pkts.first { $0.tag == 2 }!.body     // first sig = UID self-cert
        let (ha, hp, sig) = parseSig(cert)
        XCTAssertEqual(ha, 8)
        let n = uid.count
        let uidFrame: [UInt8] = [0xB4, UInt8(n >> 24), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)] + uid
        let hashData = keyFrame(primary, prefix: 0x99, lenBytes: 2) + uidFrame + hp + trailer(hp)
        let digest = Data(SHA256.hash(data: Data(hashData)))
        let pub = try edPublicKey(fromPrimary: primary)
        XCTAssertTrue(pub.isValidSignature(sig, for: digest),
                      "user-ID certification signature must verify (strict MPI)")
    }
}
