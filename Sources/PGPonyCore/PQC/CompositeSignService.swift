// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CompositeSignService.swift
// PGPony
//
// 8.3.0 planning 4.1 (Android 4.4.0): RFC 9980 composite ML-DSA + EdDSA
// signatures. The iOS counterpart of Android's CompositeSignSuite,
// CompositeSigner, CompositeSigVerifier and CompositeSigHash, mirrored
// deliberately so the two apps produce and accept the same bytes.
//
// RFC 9980 Table 1 registers two composite signature code points, both
// v6-only (Sections 5.3.1, 5.3.2):
//
//   algo 30  ML-DSA-65 + Ed25519   (generate, sign, verify, certify here)
//   algo 31  ML-DSA-87 + Ed448     (import and label; verify needs Ed448,
//                                   which nothing on iOS provides yet)
//
// Byte layout, all fixed length, the EdDSA component FIRST (Tables 6 and 7):
//
//   public key material:  EdDSA public  || ML-DSA public
//   secret key material:  EdDSA secret  || ML-DSA seed (32 octets, xi)
//   signature value:      EdDSA sig     || ML-DSA sig
//
// Both component signatures are made over the SAME v6 signature digest
// (RFC 9580 Section 5.2.4): PureEdDSA over the digest with an empty context,
// and pure hedged ML-DSA over the digest with an empty context. A verifier
// accepts the composite only when BOTH components verify. The digest is
// SHA-256 (salt 16), the hash Android writes for every composite signature,
// document and self-signature alike.
//
// ML-DSA comes from CryptoKit (MLDSA65 / MLDSA87, iOS 26), the only
// implementation on the platform that takes the 32-octet FIPS 204 seed the
// OpenPGP secret packet carries; liboqs 0.14 exposes no seed-based ML-DSA
// keygen, so an expanded key could never be re-derived from what is stored.
// The app's deployment target stays 17.6 (K2): on an earlier OS a composite
// key still imports, labels and encrypts (its ML-KEM subkey needs no ML-DSA),
// and signing or verifying with it reports the OS requirement instead of
// failing silently.

import Foundation
import CryptoKit

// MARK: - Suite

enum CompositeSignSuite: UInt8, CaseIterable {
    case mldsa65Ed25519 = 30
    case mldsa87Ed448 = 31

    static func forAlgorithm(_ id: UInt8) -> CompositeSignSuite? {
        CompositeSignSuite(rawValue: id)
    }

    /// True for a public-key algorithm octet naming a composite signature key.
    static func isComposite(_ id: UInt8) -> Bool {
        forAlgorithm(id) != nil
    }

    /// The hash every composite signature uses (Android writes SHA-256), and
    /// its v6 salt length (RFC 9580 Table 23).
    static let hashAlgorithm: UInt8 = 8
    static let saltLength = 16

    static let mldsaSeedLength = 32

    var eddsaPublicLength: Int {
        switch self {
        case .mldsa65Ed25519: return 32
        case .mldsa87Ed448: return 57
        }
    }

    var eddsaSecretLength: Int { eddsaPublicLength }

    var eddsaSignatureLength: Int {
        switch self {
        case .mldsa65Ed25519: return 64
        case .mldsa87Ed448: return 114
        }
    }

    var mldsaPublicLength: Int {
        switch self {
        case .mldsa65Ed25519: return 1952
        case .mldsa87Ed448: return 2592
        }
    }

    var mldsaSignatureLength: Int {
        switch self {
        case .mldsa65Ed25519: return 3309
        case .mldsa87Ed448: return 4627
        }
    }

    var compositePublicLength: Int { eddsaPublicLength + mldsaPublicLength }
    var compositeSecretLength: Int { eddsaSecretLength + Self.mldsaSeedLength }
    var compositeSignatureLength: Int { eddsaSignatureLength + mldsaSignatureLength }

    var keyAlgorithm: KeyAlgorithm {
        switch self {
        case .mldsa65Ed25519: return .v6MLDSA65
        case .mldsa87Ed448: return .v6MLDSA87
        }
    }

    var displayName: String {
        switch self {
        case .mldsa65Ed25519: return "ML-DSA-65+Ed25519"
        case .mldsa87Ed448: return "ML-DSA-87+Ed448"
        }
    }

    /// (eddsaPublic, mldsaPublic), or nil when the length is wrong.
    func splitPublic(_ material: [UInt8]) -> (eddsa: [UInt8], mldsa: [UInt8])? {
        guard material.count == compositePublicLength else { return nil }
        return (Array(material[0..<eddsaPublicLength]), Array(material[eddsaPublicLength...]))
    }

    /// (eddsaSecret, mldsaSeed), or nil when the length is wrong.
    func splitSecret(_ material: [UInt8]) -> (eddsa: [UInt8], mldsaSeed: [UInt8])? {
        guard material.count == compositeSecretLength else { return nil }
        return (Array(material[0..<eddsaSecretLength]), Array(material[eddsaSecretLength...]))
    }

    /// (eddsaSignature, mldsaSignature), or nil when the length is wrong.
    func splitSignature(_ value: [UInt8]) -> (eddsa: [UInt8], mldsa: [UInt8])? {
        guard value.count == compositeSignatureLength else { return nil }
        return (Array(value[0..<eddsaSignatureLength]), Array(value[eddsaSignatureLength...]))
    }
}

// MARK: - ML-DSA primitive (CryptoKit, iOS 26)

enum MLDSAService {

    enum Failure: LocalizedError {
        case unavailable
        case badInputSize(field: String, expected: Int, got: Int)
        case operationFailed(String)

        var errorDescription: String? {
            switch self {
            case .unavailable:
                return String(localized: "ML-DSA signatures need iOS 26 or later on this device.")
            case let .badInputSize(field, expected, got):
                return "ML-DSA \(field) has the wrong size: expected \(expected) bytes, got \(got)."
            case let .operationFailed(op):
                return "ML-DSA \(op) failed."
            }
        }
    }

    /// True when the OS provides ML-DSA (CryptoKit MLDSA65 / MLDSA87).
    static var isAvailable: Bool {
        if #available(iOS 26.0, macOS 26.0, *) { return true }
        return false
    }

    /// The public key for a 32-octet FIPS 204 seed.
    static func publicKey(fromSeed seed: [UInt8], suite: CompositeSignSuite) throws -> [UInt8] {
        guard seed.count == CompositeSignSuite.mldsaSeedLength else {
            throw Failure.badInputSize(field: "seed", expected: CompositeSignSuite.mldsaSeedLength, got: seed.count)
        }
        guard #available(iOS 26.0, macOS 26.0, *) else { throw Failure.unavailable }
        do {
            switch suite {
            case .mldsa65Ed25519:
                let key = try MLDSA65.PrivateKey(seedRepresentation: Data(seed), publicKey: nil)
                return Array(key.publicKey.rawRepresentation)
            case .mldsa87Ed448:
                let key = try MLDSA87.PrivateKey(seedRepresentation: Data(seed), publicKey: nil)
                return Array(key.publicKey.rawRepresentation)
            }
        } catch let e as Failure {
            throw e
        } catch {
            throw Failure.operationFailed("key expansion")
        }
    }

    /// A fresh 32-octet seed.
    static func randomSeed() throws -> [UInt8] {
        try SecureRandom.bytes(CompositeSignSuite.mldsaSeedLength)
    }

    /// Pure hedged ML-DSA over `message` (the OpenPGP digest) with an empty
    /// context, from the seed.
    static func sign(message: [UInt8], seed: [UInt8], suite: CompositeSignSuite) throws -> [UInt8] {
        guard seed.count == CompositeSignSuite.mldsaSeedLength else {
            throw Failure.badInputSize(field: "seed", expected: CompositeSignSuite.mldsaSeedLength, got: seed.count)
        }
        guard #available(iOS 26.0, macOS 26.0, *) else { throw Failure.unavailable }
        let signature: Data
        do {
            switch suite {
            case .mldsa65Ed25519:
                let key = try MLDSA65.PrivateKey(seedRepresentation: Data(seed), publicKey: nil)
                signature = try key.signature(for: Data(message))
            case .mldsa87Ed448:
                let key = try MLDSA87.PrivateKey(seedRepresentation: Data(seed), publicKey: nil)
                signature = try key.signature(for: Data(message))
            }
        } catch {
            throw Failure.operationFailed("sign")
        }
        guard signature.count == suite.mldsaSignatureLength else {
            throw Failure.badInputSize(field: "signature", expected: suite.mldsaSignatureLength, got: signature.count)
        }
        return Array(signature)
    }

    /// Pure ML-DSA verification over `message` with an empty context.
    static func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8], suite: CompositeSignSuite) throws -> Bool {
        guard publicKey.count == suite.mldsaPublicLength else {
            throw Failure.badInputSize(field: "public key", expected: suite.mldsaPublicLength, got: publicKey.count)
        }
        guard signature.count == suite.mldsaSignatureLength else { return false }
        guard #available(iOS 26.0, macOS 26.0, *) else { throw Failure.unavailable }
        do {
            switch suite {
            case .mldsa65Ed25519:
                let key = try MLDSA65.PublicKey(rawRepresentation: Data(publicKey))
                return key.isValidSignature(Data(signature), for: Data(message))
            case .mldsa87Ed448:
                let key = try MLDSA87.PublicKey(rawRepresentation: Data(publicKey))
                return key.isValidSignature(Data(signature), for: Data(message))
            }
        } catch {
            throw Failure.operationFailed("public key decoding")
        }
    }
}

// MARK: - Composite key material

/// The secret half of a composite signing key as the app holds it after the
/// secret packet is unlocked, alongside the Ed25519 half that already rides in
/// Ed25519SigningInfo.privateKey.
struct CompositeSigningInfo {
    let suite: CompositeSignSuite
    /// The 32-octet ML-DSA seed.
    let mldsaSeed: [UInt8]
    /// EdDSA public || ML-DSA public, the key packet's material.
    let compositePublic: [UInt8]

    /// EdDSA secret || ML-DSA seed, the secret packet's material.
    func compositeSecret(eddsaSecret: [UInt8]) -> [UInt8] {
        eddsaSecret + mldsaSeed
    }
}

// MARK: - Signer and verifier

enum CompositeSigner {

    enum Failure: LocalizedError {
        case unsupportedSuite(CompositeSignSuite)
        case badSecret

        var errorDescription: String? {
            switch self {
            case .unsupportedSuite(let s):
                return String(localized: "Signing with \(s.displayName) is not supported on this device.")
            case .badSecret:
                return String(localized: "The composite secret key has the wrong size.")
            }
        }
    }

    /// EdDSA signature || ML-DSA signature over `digest`, per `suite`.
    /// `compositeSecret` is EdDSA secret || ML-DSA seed.
    static func sign(suite: CompositeSignSuite, compositeSecret: [UInt8], digest: [UInt8]) throws -> [UInt8] {
        guard let parts = suite.splitSecret(compositeSecret) else { throw Failure.badSecret }
        guard suite == .mldsa65Ed25519 else { throw Failure.unsupportedSuite(suite) }
        let ed = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(parts.eddsa))
        let edSig = Array(try ed.signature(for: Data(digest)))
        guard edSig.count == suite.eddsaSignatureLength else { throw Failure.badSecret }
        let mlSig = try MLDSAService.sign(message: digest, seed: parts.mldsaSeed, suite: suite)
        return edSig + mlSig
    }

    /// The public material for a composite secret: EdDSA public || ML-DSA public.
    static func publicMaterial(suite: CompositeSignSuite, compositeSecret: [UInt8]) throws -> [UInt8] {
        guard let parts = suite.splitSecret(compositeSecret) else { throw Failure.badSecret }
        guard suite == .mldsa65Ed25519 else { throw Failure.unsupportedSuite(suite) }
        let ed = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(parts.eddsa))
        let edPub = Array(ed.publicKey.rawRepresentation)
        let mlPub = try MLDSAService.publicKey(fromSeed: parts.mldsaSeed, suite: suite)
        return edPub + mlPub
    }
}

/// Thrown by the verify paths when a composite signature cannot be checked on
/// this device at all (an OS requirement, an unsupported curve). Distinct from
/// a false result: the bytes were not found wrong, they were not checkable.
struct CompositeVerifyUnsupported: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

enum CompositeSigVerifier {

    enum Outcome: Equatable {
        case valid
        case invalid
        /// The signature could not be checked at all on this device; the
        /// text says why (an OS requirement, an unsupported curve).
        case unsupported(String)

        /// true / false for a checked signature; throws for an uncheckable one.
        func asBool() throws -> Bool {
            switch self {
            case .valid: return true
            case .invalid: return false
            case .unsupported(let why): throw CompositeVerifyUnsupported(message: why)
            }
        }
    }

    /// Both components over the same digest; `compositePublic` is EdDSA
    /// public || ML-DSA public and `signature` EdDSA sig || ML-DSA sig.
    /// - Parameter classicalHalfWhenUnavailable: 8.3.0 (hardening). For a
    ///   certificate binding check only: on a system without ML-DSA, answer
    ///   from the Ed25519 half alone instead of "unsupported", so an
    ///   ML-DSA-65 + Ed25519 key's subkey bindings can still be checked on
    ///   iOS 18. Never used for message signatures, where the
    ///   user is told the signature could not be checked.
    static func verify(suite: CompositeSignSuite, compositePublic: [UInt8], signature: [UInt8], digest: [UInt8],
                       classicalHalfWhenUnavailable: Bool = false) -> Outcome {
        guard let pub = suite.splitPublic(compositePublic) else { return .invalid }
        guard let sig = suite.splitSignature(signature) else { return .invalid }
        guard suite == .mldsa65Ed25519 else {
            return .unsupported(String(localized: "Signatures made with \(suite.displayName) cannot be verified on this device yet."))
        }
        guard let edKey = try? Curve25519.Signing.PublicKey(rawRepresentation: Data(pub.eddsa)) else { return .invalid }
        let edOK = edKey.isValidSignature(Data(sig.eddsa), for: Data(digest))
        guard MLDSAService.isAvailable else {
            if classicalHalfWhenUnavailable { return edOK ? .valid : .invalid }
            return .unsupported(MLDSAService.Failure.unavailable.errorDescription ?? "ML-DSA unavailable")
        }
        let mlOK: Bool
        do {
            mlOK = try MLDSAService.verify(signature: sig.mldsa, message: digest, publicKey: pub.mldsa, suite: suite)
        } catch let e as MLDSAService.Failure {
            if case .unavailable = e {
                return .unsupported(e.errorDescription ?? "ML-DSA unavailable")
            }
            return .invalid
        } catch {
            return .invalid
        }
        return (edOK && mlOK) ? .valid : .invalid
    }
}

// MARK: - The key a v6 signature is made with

/// What a v6 signature builder needs from its signer beyond the digest: the
/// public-key algorithm octet written into the packet and hashed into the
/// trailer, the hash it must use, and the signature value. Ed25519 keeps the
/// SHA-512 self-signatures and SHA-256 document signatures the app has always
/// written; a composite key signs everything with SHA-256, as Android does.
enum V6SignatureKey {
    case ed25519(Curve25519.Signing.PrivateKey)
    case composite(CompositeSignSuite, compositeSecret: [UInt8])

    /// From an unlocked signing key: composite when the info carries the
    /// ML-DSA half, plain Ed25519 otherwise.
    init(_ info: Ed25519SigningInfo) {
        if let c = info.composite {
            self = .composite(c.suite, compositeSecret: c.compositeSecret(eddsaSecret: Array(info.privateKey.rawRepresentation)))
        } else {
            self = .ed25519(info.privateKey)
        }
    }

    var publicKeyAlgorithm: UInt8 {
        switch self {
        case .ed25519: return 27
        case .composite(let suite, _): return suite.rawValue
        }
    }

    var isComposite: Bool {
        if case .composite = self { return true }
        return false
    }

    /// The hash a self-signature by this key uses (document signatures are
    /// SHA-256 for both; see the builders).
    var selfSignatureHashAlgorithm: UInt8 {
        switch self {
        case .ed25519: return 10
        case .composite: return CompositeSignSuite.hashAlgorithm
        }
    }

    var selfSignatureSaltLength: Int {
        switch self {
        case .ed25519: return 32
        case .composite: return CompositeSignSuite.saltLength
        }
    }

    var signatureLength: Int {
        switch self {
        case .ed25519: return 64
        case .composite(let suite, _): return suite.compositeSignatureLength
        }
    }

    func sign(digest: [UInt8]) throws -> [UInt8] {
        switch self {
        case .ed25519(let key):
            return Array(try key.signature(for: Data(digest)))
        case .composite(let suite, let secret):
            return try CompositeSigner.sign(suite: suite, compositeSecret: secret, digest: digest)
        }
    }

    /// Hash `input` with `hashAlgorithm`: SHA-256 (8, what this app writes),
    /// SHA-512 (10), SHA3-256 (12) or SHA3-512 (14), the four RFC 9980 allows.
    static func digest(_ input: Data, hashAlgorithm: UInt8) -> [UInt8] {
        switch hashAlgorithm {
        case 10: return Array(SHA512.hash(data: input))
        case 12: return Keccak.sha3_256(Array(input))
        case 14: return Keccak.sha3_512(Array(input))
        default: return Array(SHA256.hash(data: input))
        }
    }
}

// MARK: - Reading composite public keys

extension CompositeSignSuite {
    /// The composite public material of a v6 key packet body (tag 5, 6, 7 or
    /// 14) whose algorithm is 30 or 31, or nil for any other packet.
    static func publicMaterial(fromKeyPacketBody body: [UInt8]) -> (suite: CompositeSignSuite, material: [UInt8])? {
        guard body.count >= 10, body[0] == 6, let suite = forAlgorithm(body[5]) else { return nil }
        let matLen = Int(body[6]) << 24 | Int(body[7]) << 16 | Int(body[8]) << 8 | Int(body[9])
        guard matLen == suite.compositePublicLength, body.count >= 10 + matLen else { return nil }
        return (suite, Array(body[10..<(10 + matLen)]))
    }

    /// The KeyAlgorithm of a transferable key whose PRIMARY is a composite
    /// signature key, or nil. The algorithm-detection scans (import, backup
    /// restore, exchange) call this before their post-quantum SUBKEY scan:
    /// a composite primary always carries an ML-KEM subkey, and the subkey
    /// scan alone would label the whole key by that subkey.
    static func primaryAlgorithm(inPackets packets: [ParsedPacket]) -> KeyAlgorithm? {
        guard let primary = packets.first(where: { $0.tag == 5 || $0.tag == 6 }),
              primary.body.count > 5, primary.body[0] == 6,
              let suite = forAlgorithm(primary.body[5]) else { return nil }
        return suite.keyAlgorithm
    }
}
