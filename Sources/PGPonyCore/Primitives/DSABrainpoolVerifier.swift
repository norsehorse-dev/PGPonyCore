// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// DSABrainpoolVerifier.swift
// PGPony
//
// 8.4.0 build 7 (plan K3, K4): the OpenPGP side of the DSA and brainpool
// ECDSA verifiers. Reads the signer's key out of its v4 key packet, hashes
// a v4 signature the RFC 9580 section 5.2.4 way, checks the two-octet hash
// prefix, reads the (r, s) MPIs and hands them to `DSAVerifier` or
// `BrainpoolECDSA`. Used by `CertificateValidator.verify` (User ID
// certifications, subkey bindings, back-signatures, direct-key and
// revocation signatures, so these keys no longer need pins) and by
// `SigningService` (detached, clear-signed and inline data signatures).
//
// Only v4 keys and v4 signatures: RFC 9580 forbids DSA in v6, GnuPG makes
// brainpool keys as v4, and a LibrePGP v5 key stays uncheckable as before.
// The hash algorithm is chosen by whoever made the signature, so an
// unsupported one fails (false), it never makes a signature uncheckable.

import Foundation
import CryptoKit
import CommonCrypto

enum DSABrainpoolVerifier {

    /// The public key a check needs.
    enum PublicKey {
        /// DSA (algorithm 17): the MPIs p, q, g, y.
        case dsa(p: [UInt8], q: [UInt8], g: [UInt8], y: [UInt8])
        /// ECDSA (algorithm 19) on a brainpool curve: the SEC 1 point.
        case brainpool(BrainpoolCurve, point: [UInt8])
    }

    /// The key in a v4 public-key or public-subkey packet body when it is a
    /// DSA key or an ECDSA key on a brainpool curve; nil for anything else
    /// (NIST and other curves, every other algorithm, other versions).
    static func publicKey(fromKeyPacketBody body: [UInt8]) -> PublicKey? {
        guard body.count > 7, body[0] == 4 else { return nil }
        switch body[5] {
        case 17:
            var offset = 6
            guard let p = readMPI(body, &offset), let q = readMPI(body, &offset),
                  let g = readMPI(body, &offset), let y = readMPI(body, &offset) else { return nil }
            return .dsa(p: p, q: q, g: g, y: y)
        case 19:
            let oidLength = Int(body[6])
            guard oidLength > 0, 7 + oidLength <= body.count,
                  let curve = BrainpoolCurve.forOID(Array(body[7..<(7 + oidLength)])) else { return nil }
            var offset = 7 + oidLength
            guard let point = readMPI(body, &offset), point.count == curve.pointLength else { return nil }
            return .brainpool(curve, point: point)
        default:
            return nil
        }
    }

    /// True for a key this verifier checks (see `publicKey(fromKeyPacketBody:)`).
    static func handles(keyBody: [UInt8]) -> Bool {
        publicKey(fromKeyPacketBody: keyBody) != nil
    }

    /// Verify `sig` over `document` (the bytes before the signature's own
    /// hashed area: the data, or the framed key and User ID for a
    /// certification) with the key whose public body is `keyBody`.
    /// Nil when the key is not one this verifier checks; false for a
    /// signature that does not verify, has the wrong version or algorithm,
    /// or uses a hash this device does not have.
    static func verify(_ sig: OpenPGPPacketParser.ParsedSignature, document: [UInt8], keyBody: [UInt8]) -> Bool? {
        guard let key = publicKey(fromKeyPacketBody: keyBody) else { return nil }
        guard sig.version == 4, sig.publicKeyAlgorithm == keyBody[5],
              let digest = hash(Data(document) + Data(trailer(of: sig)), algorithm: sig.hashAlgorithm) else {
            return false
        }
        return verify(sig, digest: digest, key: key)
    }

    /// Verify a DETACHED signature over a file read from disk in chunks
    /// (a file too large to hold in memory). Same answers as `verify`.
    static func verify(_ sig: OpenPGPPacketParser.ParsedSignature, fileAt url: URL, keyBody: [UInt8]) throws -> Bool? {
        guard let key = publicKey(fromKeyPacketBody: keyBody) else { return nil }
        guard sig.version == 4, sig.publicKeyAlgorithm == keyBody[5],
              let digest = try streamingHash(fileAt: url, suffix: trailer(of: sig), algorithm: sig.hashAlgorithm) else {
            return false
        }
        return verify(sig, digest: digest, key: key)
    }

    /// The check itself, over a finished digest (also for a caller that
    /// hashed the data as it streamed past).
    static func verify(_ sig: OpenPGPPacketParser.ParsedSignature, digest: [UInt8], key: PublicKey) -> Bool {
        guard digest.count >= 2, sig.hashPrefix.count >= 2,
              digest[0] == sig.hashPrefix[0], digest[1] == sig.hashPrefix[1] else { return false }
        var offset = 0
        guard let r = readMPI(sig.signatureData, &offset), let s = readMPI(sig.signatureData, &offset) else {
            return false
        }
        switch key {
        case let .dsa(p, q, g, y):
            return DSAVerifier.verify(r: r, s: s, digest: digest, p: p, q: q, g: g, y: y)
        case let .brainpool(curve, point):
            return BrainpoolECDSA.verify(r: r, s: s, digest: digest, curve: curve, publicPoint: point)
        }
    }

    // MARK: - Hashing

    /// What a v4 signature hashes after the document: its hashed portion,
    /// then 0x04 0xFF and that portion's length in four octets.
    static func trailer(of sig: OpenPGPPacketParser.ParsedSignature) -> [UInt8] {
        let count = UInt32(sig.rawHashedPortion.count)
        return sig.rawHashedPortion + [0x04, 0xFF,
                                       UInt8((count >> 24) & 0xFF), UInt8((count >> 16) & 0xFF),
                                       UInt8((count >> 8) & 0xFF), UInt8(count & 0xFF)]
    }

    /// SHA-1 (2), SHA-256 (8), SHA-384 (9), SHA-512 (10), SHA-224 (11),
    /// SHA3-256 (12), SHA3-512 (14); nil for any other id.
    static func hash(_ input: Data, algorithm: UInt8) -> [UInt8]? {
        switch algorithm {
        case 2: return Array(Insecure.SHA1.hash(data: input))
        case 8: return Array(SHA256.hash(data: input))
        case 9: return Array(SHA384.hash(data: input))
        case 10: return Array(SHA512.hash(data: input))
        case 11:
            var out = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
            input.withUnsafeBytes { _ = CC_SHA224($0.baseAddress, CC_LONG(input.count), &out) }
            return out
        case 12: return Keccak.sha3_256(Array(input))
        case 14: return Keccak.sha3_512(Array(input))
        default: return nil
        }
    }

    /// The same digests over a file followed by `suffix`, 64 KB at a time.
    private static func streamingHash(fileAt url: URL, suffix: [UInt8], algorithm: UInt8) throws -> [UInt8]? {
        func run<H: HashFunction>(_ initial: H) throws -> [UInt8] {
            var hasher = initial
            try forEachChunk(of: url) { hasher.update(data: $0) }
            hasher.update(data: Data(suffix))
            return Array(hasher.finalize())
        }
        switch algorithm {
        case 2: return try run(Insecure.SHA1())
        case 8: return try run(SHA256())
        case 9: return try run(SHA384())
        case 10: return try run(SHA512())
        case 11:
            var context = CC_SHA256_CTX()
            CC_SHA224_Init(&context)
            try forEachChunk(of: url) { chunk in
                chunk.withUnsafeBytes { _ = CC_SHA224_Update(&context, $0.baseAddress, CC_LONG(chunk.count)) }
            }
            suffix.withUnsafeBytes { _ = CC_SHA224_Update(&context, $0.baseAddress, CC_LONG(suffix.count)) }
            var out = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
            CC_SHA224_Final(&out, &context)
            return out
        case 12: return try run(SHA3_256())
        case 14: return try run(SHA3_512())
        default: return nil
        }
    }

    private static func forEachChunk(of url: URL, _ body: (Data) -> Void) throws {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        while true {
            let done: Bool = try autoreleasepool {
                guard let chunk = try handle.read(upToCount: 1 << 16), !chunk.isEmpty else { return true }
                body(chunk)
                return false
            }
            if done { break }
        }
    }

    // MARK: - MPIs

    private static func readMPI(_ bytes: [UInt8], _ offset: inout Int) -> [UInt8]? {
        guard offset + 2 <= bytes.count else { return nil }
        let bits = Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
        offset += 2
        let length = (bits + 7) / 8
        guard offset + length <= bytes.count else { return nil }
        defer { offset += length }
        return Array(bytes[offset..<(offset + length)])
    }
}
