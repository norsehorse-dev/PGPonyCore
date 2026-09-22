// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// NISTCurveService.swift
// PGPony
//
// 8.3.0 (PLANNING-8.3.0-NIST, areas A to E): operate on imported NIST
// P-256 / P-384 / P-521 keys instead of only recognizing them. ECDH decrypt
// and encrypt (RFC 6637), ECDSA verify and sign (software), all on CryptoKit,
// which has all three curves for both key agreement and signing. No new
// dependency. brainpool stays recognition-only (CryptoKit has no brainpool).
//
// The trap this file exists for: a NIST ECDH subkey is algorithm 18, the same
// octet as Cv25519, and a NIST ECDSA key is algorithm 19. Before 8.3.0 an
// algorithm-18 NIST subkey entered the Cv25519 path, failed its 32-octet
// guard and was swallowed; an ECDSA signature hit the verify switch's
// default and read as "unverifiable". So nothing here is an in-place type
// swap: the curve rides on the key (`Cv25519Recipient.curve`,
// `Cv25519DecryptionKey.curve`, the point length of an ECDSA public key) and
// the routing branches on it.
//
// Encodings (RFC 6637 sections 6 and 8): a NIST point is the uncompressed
// SEC 1 form 0x04 || X || Y, 1 + 2 * fieldSize octets (P-256 65, P-384 97,
// P-521 133), which is CryptoKit's x963Representation. The shared secret is
// the X coordinate, which CryptoKit's SharedSecret yields. A private scalar
// is a big-endian MPI, padded on the left to the field size for CryptoKit's
// rawRepresentation (GnuPG strips leading zero octets). An ECDSA signature
// is two MPIs r and s, each padded to the field size for CryptoKit's
// rawRepresentation (r || s, no DER).

import Foundation
import CryptoKit

// MARK: - Curves

enum NISTCurve: String, CaseIterable {
    case p256
    case p384
    case p521

    init?(_ curve: ECCurve) {
        switch curve {
        case .nistP256: self = .p256
        case .nistP384: self = .p384
        case .nistP521: self = .p521
        default: return nil
        }
    }

    var ecCurve: ECCurve {
        switch self {
        case .p256: return .nistP256
        case .p384: return .nistP384
        case .p521: return .nistP521
        }
    }

    /// The DER OID body as it sits in a v4 key packet after the length octet.
    var oid: [UInt8] {
        switch self {
        case .p256: return [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
        case .p384: return [0x2B, 0x81, 0x04, 0x00, 0x22]
        case .p521: return [0x2B, 0x81, 0x04, 0x00, 0x23]
        }
    }

    /// Octets of a coordinate, a scalar, and of each ECDSA signature half.
    var fieldSize: Int {
        switch self {
        case .p256: return 32
        case .p384: return 48
        case .p521: return 66
        }
    }

    /// 0x04 || X || Y.
    var pointLength: Int { 1 + 2 * fieldSize }

    /// The curve of an uncompressed point by its length, the one property that
    /// tells a NIST public key from a 32-octet Ed25519 / X25519 one.
    static func fromPointLength(_ count: Int) -> NISTCurve? {
        allCases.first { $0.pointLength == count }
    }

    /// The hash GnuPG pairs with the curve for signatures and the ECDH KDF
    /// (SHA-256, SHA-384, SHA-512), and its OpenPGP id.
    var hashAlgorithmID: UInt8 {
        switch self {
        case .p256: return 8
        case .p384: return 9
        case .p521: return 10
        }
    }

    var keyAlgorithm: KeyAlgorithm {
        switch self {
        case .p256: return .nistP256
        case .p384: return .nistP384
        case .p521: return .nistP521
        }
    }

    var displayName: String { ecCurve.displayName }

    /// Left-pad a big-endian integer to the field size (an MPI GnuPG wrote
    /// with its leading zero octets stripped), or nil when it is too long.
    func padded(_ value: [UInt8]) -> [UInt8]? {
        guard value.count <= fieldSize else { return nil }
        return [UInt8](repeating: 0, count: fieldSize - value.count) + value
    }
}

// MARK: - A digest CryptoKit takes as is

/// CryptoKit's ECDSA sign and verify take a `Digest`, and hash raw data
/// themselves with SHA-256 otherwise. OpenPGP hands us the finished digest
/// (the salt, document and trailer already hashed with the signature's own
/// algorithm), so these wrap it in the protocol without rehashing. One type
/// per size, as `byteCount` is static.
/// `nonisolated`: the extension target compiles with MainActor default
/// isolation, and CryptoKit's `Digest` (a `Sendable` generic parameter to
/// the ECDSA sign and verify calls) needs an isolation-free conformance.
nonisolated protocol RawDigest: Digest, Sendable {
    init?(_ bytes: [UInt8])
}

nonisolated struct RawDigest32: RawDigest {
    static var byteCount: Int { 32 }
    private let bytes: [UInt8]
    init?(_ bytes: [UInt8]) { guard bytes.count == Self.byteCount else { return nil }; self.bytes = bytes }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R { try bytes.withUnsafeBytes(body) }
    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
    var description: String { "RawDigest32" }
}

nonisolated struct RawDigest48: RawDigest {
    static var byteCount: Int { 48 }
    private let bytes: [UInt8]
    init?(_ bytes: [UInt8]) { guard bytes.count == Self.byteCount else { return nil }; self.bytes = bytes }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R { try bytes.withUnsafeBytes(body) }
    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
    var description: String { "RawDigest48" }
}

nonisolated struct RawDigest64: RawDigest {
    static var byteCount: Int { 64 }
    private let bytes: [UInt8]
    init?(_ bytes: [UInt8]) { guard bytes.count == Self.byteCount else { return nil }; self.bytes = bytes }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R { try bytes.withUnsafeBytes(body) }
    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
    var description: String { "RawDigest64" }
}

// MARK: - ECDH (RFC 6637 key agreement on the NIST curves)

enum NISTECDHService {

    enum Failure: LocalizedError {
        case invalidPoint
        case invalidScalar
        case agreementFailed(String)

        var errorDescription: String? {
            switch self {
            case .invalidPoint: return "The NIST public key point is malformed."
            case .invalidScalar: return "The NIST private key is malformed."
            case .agreementFailed(let why): return "NIST key agreement failed: \(why)"
            }
        }
    }

    /// A fresh ephemeral key: (scalar, 0x04 || X || Y).
    static func generateEphemeral(curve: NISTCurve) -> (scalar: [UInt8], point: [UInt8]) {
        switch curve {
        case .p256:
            let k = P256.KeyAgreement.PrivateKey()
            return (Array(k.rawRepresentation), Array(k.publicKey.x963Representation))
        case .p384:
            let k = P384.KeyAgreement.PrivateKey()
            return (Array(k.rawRepresentation), Array(k.publicKey.x963Representation))
        case .p521:
            let k = P521.KeyAgreement.PrivateKey()
            return (Array(k.rawRepresentation), Array(k.publicKey.x963Representation))
        }
    }

    /// The X coordinate of scalar * point (RFC 6637: the shared secret ZZ).
    static func sharedSecret(curve: NISTCurve, scalar: [UInt8], peerPoint: [UInt8]) throws -> [UInt8] {
        guard let padded = curve.padded(scalar) else { throw Failure.invalidScalar }
        guard peerPoint.count == curve.pointLength, peerPoint.first == 0x04 else { throw Failure.invalidPoint }
        do {
            let secret: SharedSecret
            switch curve {
            case .p256:
                let sk = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(padded))
                let pk = try P256.KeyAgreement.PublicKey(x963Representation: Data(peerPoint))
                secret = try sk.sharedSecretFromKeyAgreement(with: pk)
            case .p384:
                let sk = try P384.KeyAgreement.PrivateKey(rawRepresentation: Data(padded))
                let pk = try P384.KeyAgreement.PublicKey(x963Representation: Data(peerPoint))
                secret = try sk.sharedSecretFromKeyAgreement(with: pk)
            case .p521:
                let sk = try P521.KeyAgreement.PrivateKey(rawRepresentation: Data(padded))
                let pk = try P521.KeyAgreement.PublicKey(x963Representation: Data(peerPoint))
                secret = try sk.sharedSecretFromKeyAgreement(with: pk)
            }
            return secret.withUnsafeBytes { Array($0) }
        } catch let e as Failure {
            throw e
        } catch {
            throw Failure.agreementFailed(error.localizedDescription)
        }
    }

    /// The public point for a scalar, to confirm an unlocked secret against
    /// its packet's public key before it is used.
    static func publicPoint(curve: NISTCurve, scalar: [UInt8]) throws -> [UInt8] {
        guard let padded = curve.padded(scalar) else { throw Failure.invalidScalar }
        do {
            switch curve {
            case .p256: return Array(try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(padded)).publicKey.x963Representation)
            case .p384: return Array(try P384.KeyAgreement.PrivateKey(rawRepresentation: Data(padded)).publicKey.x963Representation)
            case .p521: return Array(try P521.KeyAgreement.PrivateKey(rawRepresentation: Data(padded)).publicKey.x963Representation)
            }
        } catch {
            throw Failure.invalidScalar
        }
    }
}

// MARK: - ECDSA

enum NISTECDSAService {

    enum Failure: LocalizedError {
        case unsupportedHash(UInt8)
        case invalidPoint
        case invalidScalar
        case signingFailed(String)

        var errorDescription: String? {
            switch self {
            case .unsupportedHash(let id): return "ECDSA over hash algorithm \(id) is not supported."
            case .invalidPoint: return "The ECDSA public key point is malformed."
            case .invalidScalar: return "The ECDSA private key is malformed."
            case .signingFailed(let why): return "ECDSA signing failed: \(why)"
            }
        }
    }

    /// Whether `digest` (already hashed with `hashAlgorithmID`) is one of the
    /// sizes this path signs and verifies: SHA-256, SHA-384, SHA-512.
    static func supportsHash(_ hashAlgorithmID: UInt8) -> Bool {
        hashAlgorithmID == 8 || hashAlgorithmID == 9 || hashAlgorithmID == 10
    }

    /// Verify r || s (each padded to the field size, or shorter as read off
    /// the MPIs) over a finished digest.
    static func verify(r: [UInt8], s: [UInt8], digest: [UInt8], curve: NISTCurve, publicPoint: [UInt8]) throws -> Bool {
        guard publicPoint.count == curve.pointLength, publicPoint.first == 0x04 else { throw Failure.invalidPoint }
        guard let rr = curve.padded(r), let ss = curve.padded(s) else { return false }
        let raw = Data(rr + ss)
        do {
            switch curve {
            case .p256:
                let key = try P256.Signing.PublicKey(x963Representation: Data(publicPoint))
                let sig = try P256.Signing.ECDSASignature(rawRepresentation: raw)
                return try withDigest(digest) { key.isValidSignature(sig, for: $0) }
            case .p384:
                let key = try P384.Signing.PublicKey(x963Representation: Data(publicPoint))
                let sig = try P384.Signing.ECDSASignature(rawRepresentation: raw)
                return try withDigest(digest) { key.isValidSignature(sig, for: $0) }
            case .p521:
                let key = try P521.Signing.PublicKey(x963Representation: Data(publicPoint))
                let sig = try P521.Signing.ECDSASignature(rawRepresentation: raw)
                return try withDigest(digest) { key.isValidSignature(sig, for: $0) }
            }
        } catch let e as Failure {
            throw e
        } catch {
            return false
        }
    }

    /// Sign a finished digest; (r, s) each exactly the field size.
    static func sign(digest: [UInt8], curve: NISTCurve, scalar: [UInt8]) throws -> (r: [UInt8], s: [UInt8]) {
        guard let padded = curve.padded(scalar) else { throw Failure.invalidScalar }
        let raw: Data
        do {
            switch curve {
            case .p256:
                let key = try P256.Signing.PrivateKey(rawRepresentation: Data(padded))
                raw = try withDigest(digest) { try key.signature(for: $0).rawRepresentation }
            case .p384:
                let key = try P384.Signing.PrivateKey(rawRepresentation: Data(padded))
                raw = try withDigest(digest) { try key.signature(for: $0).rawRepresentation }
            case .p521:
                let key = try P521.Signing.PrivateKey(rawRepresentation: Data(padded))
                raw = try withDigest(digest) { try key.signature(for: $0).rawRepresentation }
            }
        } catch let e as Failure {
            throw e
        } catch {
            throw Failure.signingFailed(error.localizedDescription)
        }
        let bytes = Array(raw)
        guard bytes.count == 2 * curve.fieldSize else { throw Failure.signingFailed("unexpected signature length \(bytes.count)") }
        return (Array(bytes[0..<curve.fieldSize]), Array(bytes[curve.fieldSize...]))
    }

    /// The public point for a scalar.
    static func publicPoint(curve: NISTCurve, scalar: [UInt8]) throws -> [UInt8] {
        guard let padded = curve.padded(scalar) else { throw Failure.invalidScalar }
        do {
            switch curve {
            case .p256: return Array(try P256.Signing.PrivateKey(rawRepresentation: Data(padded)).publicKey.x963Representation)
            case .p384: return Array(try P384.Signing.PrivateKey(rawRepresentation: Data(padded)).publicKey.x963Representation)
            case .p521: return Array(try P521.Signing.PrivateKey(rawRepresentation: Data(padded)).publicKey.x963Representation)
            }
        } catch {
            throw Failure.invalidScalar
        }
    }

    /// Run `body` with the digest wrapped in the `Digest` type of its size.
    private static func withDigest<R>(_ digest: [UInt8], _ body: (any Digest) throws -> R) throws -> R {
        switch digest.count {
        case 32: return try body(RawDigest32(digest)!)
        case 48: return try body(RawDigest48(digest)!)
        case 64: return try body(RawDigest64(digest)!)
        default: throw Failure.unsupportedHash(UInt8(clamping: digest.count))
        }
    }
}
