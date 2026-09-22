// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// V6KeyGenerator.swift
// PGPony — v5.0 Phase 2b
//
// Generates RFC 9580 (v6) Ed25519 signing primary keys with X25519 encryption
// subkeys, using Apple CryptoKit for key material and hand-constructed
// OpenPGP v6 packets.
//
// Differences from the v4 Ed25519KeyGenerator:
//   • Version byte 6 in all key packets
//   • Algorithm 27 (Ed25519 native) and 25 (X25519 native) — no OIDs
//   • Key material: raw 32-byte values with 4-byte BE length prefix (no MPI)
//   • Fingerprint: SHA-256 of (0x9B || 4-byte BE length || body) — 32 bytes
//   • Key ID: first 8 bytes of fingerprint (not last 8)
//   • Self-signatures use v6 framing:
//       - 4-byte subpacket lengths (not 2)
//       - Trailer: 0x06 0xFF + 8-byte BE length
//       - 16-byte salt prepended to hash input (for SHA-256)
//       - Raw 64-byte signature output (no MPI wrapping)
//
// v5.0 scope simplification: v6 secret keys are stored UNPROTECTED (S2K usage
// byte 0). v6 passphrase protection uses AEAD-OCB which is deferred to a later
// release. Keychain at-rest encryption protects the material in the meantime.

import Foundation
import CryptoKit
import CommonCrypto

// MARK: - Result

struct V6KeyGeneratorResult {
    let fingerprint: String       // 64 hex chars (SHA-256)
    let publicKeyData: Data       // Full v6 transferable public key packet stream
    let privateKeyData: Data      // Full v6 transferable secret key packet stream
    let armoredPublicKey: String
    let armoredPrivateKey: String
}

// MARK: - Errors

enum V6KeyGeneratorError: LocalizedError {
    case passphraseNotSupportedYet

    var errorDescription: String? {
        switch self {
        case .passphraseNotSupportedYet:
            return "Passphrase protection for v6 keys requires AEAD-OCB and is not yet supported in this release."
        }
    }
}

// MARK: - Generator

class V6KeyGenerator {

    // Algorithm IDs (RFC 9580)
    private static let algoEd25519: UInt8 = 27   // v6 native Ed25519
    private static let algoX25519: UInt8 = 25    // v6 native X25519
    private static let algoMLKEM768X25519: UInt8 = 35   // RFC 9980 ML-KEM-768 + X25519 composite
    private static let algoMLKEM1024X448: UInt8 = 36    // RFC 9980 ML-KEM-1024 + X448 composite (v8.2.0 §1)

    private static let hashSHA512: UInt8 = 10
    private static let saltLenSHA512 = 32

    // MARK: - Generate

    static func generate(
        name: String,
        email: String,
        passphrase: String?,
        expirationInterval: TimeInterval?,
        pqcEncryption: Bool = false,
        pqcSuite: CompositeSuite = .ietf768
    ) throws -> V6KeyGeneratorResult {

        let genStart = Date()

        // v6.0 Phase V6-I: passphrase-protected v6 keys use S2K (Argon2id) + AEAD-OCB
        // per RFC 9580 §5.5.3 (S2K usage octet 253). An empty/nil passphrase yields
        // unprotected (S2K usage 0) secret material, as before.
        //
        // Argon2id is run ONCE per key (not per component): all three secret packets
        // share the salt + derived S2K key, but each gets its own random nonce and a
        // per-component KEK via HKDF (the info parameter differs by packet tag ID).
        // This keeps generation responsive — three independent 2 GiB derivations on
        // a pure-Swift Argon2 would hang the device.
        let lock: V6SecretLock? = try lockPassphrase(from: passphrase).map { try makeV6Lock(passphrase: $0) }
        let afterLock = Date()

        let creationTime = UInt32(Date().timeIntervalSince1970)

        // Generate Ed25519 signing primary (CERTIFY-ONLY — see DirectKey flags)
        let signingKey = Curve25519.Signing.PrivateKey()
        let signingPub  = Array(signingKey.publicKey.rawRepresentation)
        let signingPriv = Array(signingKey.rawRepresentation)

        // Generate Ed25519 SIGNING subkey (data signatures live here, not on the
        // certify-only primary).
        let signSubkey = Curve25519.Signing.PrivateKey()
        let signSubPub  = Array(signSubkey.publicKey.rawRepresentation)
        let signSubPriv = Array(signSubkey.rawRepresentation)

        // Generate the encryption subkey. Classical: X25519 (algorithm 25).
        // PQC (RFC 9980): an ML-KEM + ECDH composite. The ECC public leads,
        // followed by the ML-KEM public; the secret material is the ECC
        // scalar followed by the 64-byte ML-KEM seed (d‖z), which is what
        // the composite decrypt path expects. v8.2.0 §1: `pqcSuite` selects
        // 768+X25519 (algo 35, sizes 32/1184) or 1024+X448 (algo 36, sizes
        // 56/1568); the layout is identical, only the halves grow.
        let encryptionKey = Curve25519.KeyAgreement.PrivateKey()
        let encryptionPub  = Array(encryptionKey.publicKey.rawRepresentation)
        let encryptionPriv = Array(encryptionKey.rawRepresentation)

        let encAlgorithm: UInt8
        let encKeyMaterial: [UInt8]
        let encRawPrivate: [UInt8]
        if pqcEncryption {
            let mlkemSeed = try secureRandomBytes(64)                       // d‖z
            let (mlkemPub, _) = try MLKEMService.generateKeyPair(seed: Data(mlkemSeed),
                                                                 level: pqcSuite.mlkemLevel)
            let eccPub: [UInt8]
            let eccPriv: [UInt8]
            switch pqcSuite {
            case .ietf768:
                // The X25519 keypair generated above serves as the ECC half,
                // exactly as before this function knew about suites.
                eccPub = encryptionPub
                eccPriv = encryptionPriv
            case .ietf1024:
                // X448 half from the hand-rolled curve (X448.swift). The
                // Curve25519 keypair above goes unused on this path.
                let x448Priv = try X448.generatePrivateKey()
                let x448Pub = try X448.publicKey(for: x448Priv)
                eccPub = Array(x448Pub)
                eccPriv = Array(x448Priv)
            }
            encAlgorithm  = pqcSuite.algId
            encKeyMaterial = eccPub + Array(mlkemPub)     // 1216 @35, 1624 @36
            encRawPrivate  = eccPriv + mlkemSeed          // 96 @35, 120 @36
        } else {
            encAlgorithm  = algoX25519
            encKeyMaterial = encryptionPub
            encRawPrivate  = encryptionPriv
        }

        // Build v6 primary public-key packet body
        let primaryPubBody = buildV6PublicKeyBody(
            creationTime: creationTime,
            algorithm: algoEd25519,
            keyMaterial: signingPub
        )

        // v6 fingerprint = SHA-256(0x9B || 4-byte BE length || body)
        let fingerprint = computeV6Fingerprint(packetBody: primaryPubBody)
        let keyID = Array(fingerprint.prefix(8))   // v6: first 8 bytes

        // User ID. 8.3.0 (6.1): the address is optional.
        let userID = UserIDFormat.compose(name: name, email: email)
        let userIDBytes = Array(userID.utf8)

        // Build v6 cert structure following RFC 9580 §10.1.1:
        //   primary | DirectKey-sig (algorithm prefs, key flags) | userID | PositiveCertification |
        //   subkey | SubkeyBinding-sig
        // Sequoia and strict v6 validators require the DirectKey sig to hold the
        // certificate-wide policy (prefs, features, key flags). The cert sig over
        // the user ID is then simpler.

        // Direct Key Signature (type 0x1F) — anchors algorithm preferences for the cert
        let directKeySig = try buildV6DirectKeySignature(
            signer: .ed25519(signingKey),
            primaryKeyBody: primaryPubBody,
            primaryFingerprint: fingerprint,
            creationTime: creationTime,
            expirationInterval: expirationInterval
        )

        // Self-signature on the user ID (cert type 0x13) — simpler now, just binds UID
        let selfSig = try buildV6CertificationSignature(
            signer: .ed25519(signingKey),
            primaryKeyBody: primaryPubBody,
            primaryFingerprint: fingerprint,
            userIDBytes: userIDBytes,
            creationTime: creationTime
        )

        // Subkey 1: v6 Ed25519 SIGNING subkey
        let signSubBody = buildV6PublicKeyBody(
            creationTime: creationTime,
            algorithm: algoEd25519,
            keyMaterial: signSubPub
        )
        let signSubFingerprint = computeV6Fingerprint(packetBody: signSubBody)

        // The signing subkey's primary-key-binding (0x19) back-signature, made BY
        // the subkey over (primary ‖ subkey). Embedded into its 0x18 binding below.
        let signSubBackSig = try buildV6PrimaryKeyBindingSignature(
            subkeySigner: .ed25519(signSubkey),
            primaryKeyBody: primaryPubBody,
            subkeyBody: signSubBody,
            subkeyFingerprint: signSubFingerprint,
            creationTime: creationTime
        )

        // Subkey binding (0x18) for the signing subkey: key flags 0x02 (sign) and
        // the embedded back-sig, signed by the primary.
        let signSubBindingSig = try buildV6SubkeyBindingSignature(
            signer: .ed25519(signingKey),
            primaryKeyBody: primaryPubBody,
            primaryFingerprint: fingerprint,
            subkeyBody: signSubBody,
            creationTime: creationTime,
            expirationInterval: expirationInterval,
            keyFlags: 0x02,
            embeddedBackSignature: signSubBackSig
        )

        // Subkey 2: v6 encryption subkey — X25519 (algo 25) or ML-KEM composite (algo 35/36)
        let subkeyPubBody = buildV6PublicKeyBody(
            creationTime: creationTime,
            algorithm: encAlgorithm,
            keyMaterial: encKeyMaterial
        )

        // Subkey binding signature (type 0x18) — encrypt flags 0x0C (no back-sig)
        let subkeyBindingSig = try buildV6SubkeyBindingSignature(
            signer: .ed25519(signingKey),
            primaryKeyBody: primaryPubBody,
            primaryFingerprint: fingerprint,
            subkeyBody: subkeyPubBody,
            creationTime: creationTime,
            expirationInterval: expirationInterval,
            keyFlags: 0x0C
        )

        // 8.3.0 (planning 4.2): a post-quantum v6 key also carries a standalone
        // X25519 subkey, the downgrade path for correspondents whose software
        // does not do RFC 9980 (Android 4.4.0's v6 composite layout). It is a
        // fresh keypair, never the X25519 half of the composite. PGPony and
        // other RFC 9980 senders address the composite; everyone else this one.
        var classicalSubBody: [UInt8] = []
        var classicalSubSecretBody: [UInt8] = []
        var classicalSubBindingSig: [UInt8] = []
        if pqcEncryption {
            let classicalKey = Curve25519.KeyAgreement.PrivateKey()
            classicalSubBody = buildV6PublicKeyBody(
                creationTime: creationTime,
                algorithm: algoX25519,
                keyMaterial: Array(classicalKey.publicKey.rawRepresentation)
            )
            classicalSubBindingSig = try buildV6SubkeyBindingSignature(
                signer: .ed25519(signingKey),
                primaryKeyBody: primaryPubBody,
                primaryFingerprint: fingerprint,
                subkeyBody: classicalSubBody,
                creationTime: creationTime,
                expirationInterval: expirationInterval,
                keyFlags: 0x0C
            )
            classicalSubSecretBody = try buildV6SecretKeyBody(
                publicBody: classicalSubBody,
                rawPrivateKey: Array(classicalKey.rawRepresentation),
                lock: lock,
                packetTagID: 0xC7
            )
        }

        // Assemble transferable public-key packet stream (v6 cert layout):
        //   primary | DirectKey | UID | PositiveCert | signSub | signBind | [x25519Sub | bind] | encSub | encBind
        var pubKeyPackets = Data()
        pubKeyPackets.append(buildPacket(tag: 6,  body: Data(primaryPubBody)))
        pubKeyPackets.append(buildPacket(tag: 2,  body: Data(directKeySig)))
        pubKeyPackets.append(buildPacket(tag: 13, body: Data(userIDBytes)))
        pubKeyPackets.append(buildPacket(tag: 2,  body: Data(selfSig)))
        pubKeyPackets.append(buildPacket(tag: 14, body: Data(signSubBody)))
        pubKeyPackets.append(buildPacket(tag: 2,  body: Data(signSubBindingSig)))
        if pqcEncryption {
            pubKeyPackets.append(buildPacket(tag: 14, body: Data(classicalSubBody)))
            pubKeyPackets.append(buildPacket(tag: 2,  body: Data(classicalSubBindingSig)))
        }
        pubKeyPackets.append(buildPacket(tag: 14, body: Data(subkeyPubBody)))
        pubKeyPackets.append(buildPacket(tag: 2,  body: Data(subkeyBindingSig)))

        // Build v6 secret-key bodies — unprotected (S2K usage 0) when `lock` is nil,
        // or Argon2id + AEAD-OCB protected (S2K usage 253) when set.
        // packetTagID is the OpenPGP-format Packet Type ID octet used in the AEAD
        // KEK info and additional-data: 0xC5 for a Secret-Key (tag 5) primary,
        // 0xC7 for a Secret-Subkey (tag 7).
        let primarySecretBody = try buildV6SecretKeyBody(
            publicBody: primaryPubBody,
            rawPrivateKey: signingPriv,
            lock: lock,
            packetTagID: 0xC5
        )
        let signSubSecretBody = try buildV6SecretKeyBody(
            publicBody: signSubBody,
            rawPrivateKey: signSubPriv,
            lock: lock,
            packetTagID: 0xC7
        )
        let subkeySecretBody = try buildV6SecretKeyBody(
            publicBody: subkeyPubBody,
            rawPrivateKey: encRawPrivate,
            lock: lock,
            packetTagID: 0xC7
        )

        // Assemble transferable secret-key packet stream (same structure, secret bodies)
        var secretKeyPackets = Data()
        secretKeyPackets.append(buildPacket(tag: 5,  body: Data(primarySecretBody)))
        secretKeyPackets.append(buildPacket(tag: 2,  body: Data(directKeySig)))
        secretKeyPackets.append(buildPacket(tag: 13, body: Data(userIDBytes)))
        secretKeyPackets.append(buildPacket(tag: 2,  body: Data(selfSig)))
        secretKeyPackets.append(buildPacket(tag: 7,  body: Data(signSubSecretBody)))
        secretKeyPackets.append(buildPacket(tag: 2,  body: Data(signSubBindingSig)))
        if pqcEncryption {
            secretKeyPackets.append(buildPacket(tag: 7,  body: Data(classicalSubSecretBody)))
            secretKeyPackets.append(buildPacket(tag: 2,  body: Data(classicalSubBindingSig)))
        }
        secretKeyPackets.append(buildPacket(tag: 7,  body: Data(subkeySecretBody)))
        secretKeyPackets.append(buildPacket(tag: 2,  body: Data(subkeyBindingSig)))

        // Armor
        let armoredPub = armorData(pubKeyPackets, type: .publicKey)
        let armoredSec = armorData(secretKeyPackets, type: .secretKey)

        let fingerprintHex = fingerprint.map { String(format: "%02x", $0) }.joined()

        let now = Date()
        pgpDebugLog(String(format: "DEBUG V6 gen: total=%.2fs (lock/Argon2=%.2fs, keygen+sigs+assembly=%.2fs)",
                     now.timeIntervalSince(genStart),
                     afterLock.timeIntervalSince(genStart),
                     now.timeIntervalSince(afterLock)))

        return V6KeyGeneratorResult(
            fingerprint: fingerprintHex,
            publicKeyData: pubKeyPackets,
            privateKeyData: secretKeyPackets,
            armoredPublicKey: armoredPub,
            armoredPrivateKey: armoredSec
        )
    }

    // MARK: - Generate (composite ML-DSA + EdDSA primary; 8.3.0 planning 4.1)

    /// An RFC 9980 composite SIGNATURE key in the Android 4.4.0 layout
    /// (CompositePrimaryKeyGen.assemble): an ML-DSA-65 + Ed25519 primary
    /// (algorithm 30) that certifies and signs, one user ID with its 0x13
    /// certification, and an ML-KEM-768 + X25519 encryption subkey (algorithm
    /// 35) bound by a composite 0x18 (no back-signature; an encryption subkey
    /// makes none). Every self-signature is SHA-256 with a 16-octet salt, as
    /// Android writes them. The secret packets hold EdDSA secret || ML-DSA seed
    /// (primary) and X25519 secret || ML-KEM seed (subkey), locked exactly as
    /// `generate` locks its material (Argon2id + AES-256-OCB, S2K usage 253).
    static func generateComposite(
        name: String,
        email: String,
        passphrase: String?,
        expirationInterval: TimeInterval?,
        suite: CompositeSignSuite = .mldsa65Ed25519
    ) throws -> V6KeyGeneratorResult {
        guard suite == .mldsa65Ed25519 else { throw CompositeSigner.Failure.unsupportedSuite(suite) }
        let genStart = Date()
        let lock: V6SecretLock? = try lockPassphrase(from: passphrase).map { try makeV6Lock(passphrase: $0) }
        let creationTime = UInt32(Date().timeIntervalSince1970)

        // Primary: an Ed25519 keypair and a 32-octet ML-DSA seed (FIPS 204),
        // the seed expanded to its public key by CryptoKit.
        let edKey = Curve25519.Signing.PrivateKey()
        let mldsaSeed = try MLDSAService.randomSeed()
        let mldsaPub = try MLDSAService.publicKey(fromSeed: mldsaSeed, suite: suite)
        let primaryPublic = Array(edKey.publicKey.rawRepresentation) + mldsaPub
        let primarySecret = Array(edKey.rawRepresentation) + mldsaSeed
        let signer = V6SignatureKey.composite(suite, compositeSecret: primarySecret)

        let primaryPubBody = buildV6PublicKeyBody(
            creationTime: creationTime, algorithm: suite.rawValue, keyMaterial: primaryPublic)
        let fingerprint = computeV6Fingerprint(packetBody: primaryPubBody)

        let userID = UserIDFormat.compose(name: name, email: email)
        let userIDBytes = Array(userID.utf8)

        // Direct Key (0x1F, flags certify | sign, prefs, features) and the
        // user ID certification (0x13), both by the composite primary.
        let directKeySig = try buildV6DirectKeySignature(
            signer: signer, primaryKeyBody: primaryPubBody, primaryFingerprint: fingerprint,
            creationTime: creationTime, expirationInterval: expirationInterval)
        let selfSig = try buildV6CertificationSignature(
            signer: signer, primaryKeyBody: primaryPubBody, primaryFingerprint: fingerprint,
            userIDBytes: userIDBytes, creationTime: creationTime)

        // Encryption subkey: ML-KEM-768 + X25519 (algorithm 35), built exactly
        // as `generate(pqcEncryption: true)` builds it.
        let xKey = Curve25519.KeyAgreement.PrivateKey()
        let mlkemSeed = try secureRandomBytes(64)                            // d‖z
        let (mlkemPub, _) = try MLKEMService.generateKeyPair(seed: Data(mlkemSeed),
                                                             level: CompositeSuite.ietf768.mlkemLevel)
        let encPubBody = buildV6PublicKeyBody(
            creationTime: creationTime, algorithm: algoMLKEM768X25519,
            keyMaterial: Array(xKey.publicKey.rawRepresentation) + Array(mlkemPub))
        let encSecret = Array(xKey.rawRepresentation) + mlkemSeed          // 96 octets
        let encBindingSig = try buildV6SubkeyBindingSignature(
            signer: signer, primaryKeyBody: primaryPubBody, primaryFingerprint: fingerprint,
            subkeyBody: encPubBody, creationTime: creationTime,
            expirationInterval: expirationInterval, keyFlags: 0x0C)

        var pubKeyPackets = Data()
        pubKeyPackets.append(buildPacket(tag: 6,  body: Data(primaryPubBody)))
        pubKeyPackets.append(buildPacket(tag: 2,  body: Data(directKeySig)))
        pubKeyPackets.append(buildPacket(tag: 13, body: Data(userIDBytes)))
        pubKeyPackets.append(buildPacket(tag: 2,  body: Data(selfSig)))
        pubKeyPackets.append(buildPacket(tag: 14, body: Data(encPubBody)))
        pubKeyPackets.append(buildPacket(tag: 2,  body: Data(encBindingSig)))

        let primarySecretBody = try buildV6SecretKeyBody(
            publicBody: primaryPubBody, rawPrivateKey: primarySecret, lock: lock, packetTagID: 0xC5)
        let encSecretBody = try buildV6SecretKeyBody(
            publicBody: encPubBody, rawPrivateKey: encSecret, lock: lock, packetTagID: 0xC7)

        var secretKeyPackets = Data()
        secretKeyPackets.append(buildPacket(tag: 5,  body: Data(primarySecretBody)))
        secretKeyPackets.append(buildPacket(tag: 2,  body: Data(directKeySig)))
        secretKeyPackets.append(buildPacket(tag: 13, body: Data(userIDBytes)))
        secretKeyPackets.append(buildPacket(tag: 2,  body: Data(selfSig)))
        secretKeyPackets.append(buildPacket(tag: 7,  body: Data(encSecretBody)))
        secretKeyPackets.append(buildPacket(tag: 2,  body: Data(encBindingSig)))

        pgpDebugLog(String(format: "DEBUG V6 composite gen: total=%.2fs", Date().timeIntervalSince(genStart)))

        return V6KeyGeneratorResult(
            fingerprint: fingerprint.map { String(format: "%02x", $0) }.joined(),
            publicKeyData: pubKeyPackets,
            privateKeyData: secretKeyPackets,
            armoredPublicKey: armorData(pubKeyPackets, type: .publicKey),
            armoredPrivateKey: armorData(secretKeyPackets, type: .secretKey)
        )
    }

    // MARK: - v6 expiration edit (issue #4)

    enum V6EditError: LocalizedError {
        case noPrimary
        case expiryBeforeCreation
        case signingSubkeyUnavailable
        case signingSubkeyMismatch

        var errorDescription: String? {
            switch self {
            case .noPrimary: return "No primary key packet in the v6 key."
            case .expiryBeforeCreation: return "The chosen expiration is before the key was created."
            case .signingSubkeyUnavailable: return "The signing subkey's secret is needed to re-date its binding."
            case .signingSubkeyMismatch: return "The signing subkey secret does not match the key's signing subkey."
            }
        }
    }

    /// Re-date a v6 key's expiration by SUPERSEDING its self-signatures, landing the
    /// new Key Expiration Time on the primary (direct-key signature) AND on every
    /// subkey binding, including the signing subkey (with a fresh embedded 0x19
    /// back-signature made BY the subkey) and the ML-KEM composite encryption
    /// subkey. Only signatures change: the public-key packets, and thus the
    /// fingerprint, are untouched. Reuses the same v6 signature builders as
    /// generation, so the output is byte-shaped like a freshly generated key and
    /// verifies under gpg / sq.
    ///
    /// The Key Expiration Time is relative to EACH key's own creation time, so the
    /// interval is recomputed per key. `expiresAt == nil` clears the expiration.
    ///
    /// `signingSubkey` / `signingSubkeyFingerprint` are the signing subkey's secret
    /// and 32-byte v6 fingerprint, used only to make the back-signature its binding
    /// must embed. Pass nil for both to leave a signing subkey untouched (e.g. a
    /// hardware card that cannot sign as the subkey), matching the card path.
    /// CORE SEAM: the app answers this with SubkeyEditService (its subkey
    /// editor, which reads the SwiftData-free ring scan too); the core keeps
    /// the one question the expiry editor asks. Packet indices of the subkeys
    /// the primary has revoked: a self-issued 0x28 under the subkey.
    static func revokedSubkeyPositions(packets: [ParsedPacket]) -> Set<Int> {
        guard let primary = packets.first(where: { $0.tag == 6 || $0.tag == 5 }),
              let version = primary.body.first else { return [] }
        let publicBody: [UInt8]
        if primary.tag == 5 {
            if version == 6, primary.body.count >= 10 {
                let n = Int(primary.body[6]) << 24 | Int(primary.body[7]) << 16 | Int(primary.body[8]) << 8 | Int(primary.body[9])
                publicBody = Array(primary.body.prefix(10 + n))
            } else {
                publicBody = OpenPGPPacketParser.v4PublicPrefix(secretBody: primary.body) ?? primary.body
            }
        } else {
            publicBody = primary.body
        }
        let fp = version == 6 ? OpenPGPPacketParser.computeV6Fingerprint(packetBody: publicBody)
                              : OpenPGPPacketParser.computeV4Fingerprint(packetBody: publicBody)
        func issuedByPrimary(_ sig: OpenPGPPacketParser.ParsedSignature) -> Bool {
            if let issuer = sig.issuerFingerprint {
                return version == 6 ? Array(issuer.prefix(32)) == fp : Array(issuer.suffix(20)) == fp
            }
            if let keyID = sig.issuerKeyID {
                return keyID == (version == 6 ? Array(fp.prefix(8)) : Array(fp.suffix(8)))
            }
            return false
        }
        var revoked = Set<Int>()
        var current: Int? = nil
        for (index, packet) in packets.enumerated() {
            switch packet.tag {
            case 14, 7:
                current = index
            case 13, 17, 6, 5:
                current = nil
            case 2:
                guard let sub = current,
                      let sig = try? OpenPGPPacketParser.parseSignaturePacket(body: packet.body),
                      sig.signatureType == 0x28, issuedByPrimary(sig) else { continue }
                revoked.insert(sub)
            default:
                break
            }
        }
        return revoked
    }

    static func editV6Expiration(
        publicKeyData: Data,
        secretKeyData: Data,
        primarySigner: V6SignatureKey,
        primaryFingerprint: [UInt8],
        signingSubkey: Curve25519.Signing.PrivateKey?,
        signingSubkeyFingerprint: [UInt8]?,
        expiresAt: Date?
    ) throws -> (publicKeyData: Data, secretKeyData: Data) {
        let sigCreation = UInt32(Date().timeIntervalSince1970)
        let pubPackets = try OpenPGPPacketParser.parsePackets(data: Array(publicKeyData))

        guard let primaryPkt = pubPackets.first(where: { $0.tag == 6 }) else { throw V6EditError.noPrimary }
        let primaryBody = primaryPkt.body
        let primaryCreation = try OpenPGPPacketParser.parsePublicKeyFields(body: primaryBody).creationTime

        func relInterval(creation: UInt32) throws -> TimeInterval? {
            guard let expiresAt else { return nil }   // nil clears the expiry
            let exp = expiresAt.timeIntervalSince1970
            guard exp > Double(creation) else { throw V6EditError.expiryBeforeCreation }
            return exp - Double(creation)
        }

        // Fresh primary direct-key self-signature (0x1F) carrying the new expiry.
        let newDirectKeySig = try buildV6DirectKeySignature(
            signer: primarySigner,
            primaryKeyBody: primaryBody,
            primaryFingerprint: primaryFingerprint,
            creationTime: sigCreation,
            expirationInterval: try relInterval(creation: primaryCreation)
        )

        // A fresh 0x18 binding per subkey, in ring order, carrying the new expiry.
        // A sign-capable subkey (key flag 0x02) also gets a fresh embedded 0x19
        // back-signature; its key flags are read from the existing binding so an
        // imported layout keeps its capabilities.
        // 8.3.0 (4.6): a subkey the primary has revoked keeps its old binding
        // (a fresh, newer one would let a verifier that ranks self-signatures
        // by date treat the soft revocation as superseded), and it needs no
        // back-signature either.
        let revokedSubkeys = revokedSubkeyPositions(packets: pubPackets)
        var newBindings: [[UInt8]?] = []         // indexed by subkey order; nil keeps the old binding
        for (idx, pkt) in pubPackets.enumerated() where pkt.tag == 14 {
            if revokedSubkeys.contains(idx) {
                newBindings.append(nil)
                continue
            }
            let subBody = pkt.body
            let subCreation = try OpenPGPPacketParser.parsePublicKeyFields(body: subBody).creationTime
            var keyFlags: UInt8 = 0x0C
            if idx + 1 < pubPackets.count, pubPackets[idx + 1].tag == 2 {
                let sig = try OpenPGPPacketParser.parseSignaturePacket(body: pubPackets[idx + 1].body)
                if let kf = sig.hashedSubpackets.first(where: { $0.type == 27 })?.data.first { keyFlags = kf }
            }

            var backSig: [UInt8]? = nil
            if (keyFlags & 0x02) != 0 {
                guard let signingSubkey, let signingSubkeyFingerprint else {
                    throw V6EditError.signingSubkeyUnavailable
                }
                let subFP = computeV6Fingerprint(packetBody: subBody)
                guard subFP == signingSubkeyFingerprint else { throw V6EditError.signingSubkeyMismatch }
                backSig = try buildV6PrimaryKeyBindingSignature(
                    subkeySigner: .ed25519(signingSubkey),
                    primaryKeyBody: primaryBody,
                    subkeyBody: subBody,
                    subkeyFingerprint: subFP,
                    creationTime: sigCreation
                )
            }

            let binding = try buildV6SubkeyBindingSignature(
                signer: primarySigner,
                primaryKeyBody: primaryBody,
                primaryFingerprint: primaryFingerprint,
                subkeyBody: subBody,
                creationTime: sigCreation,
                expirationInterval: try relInterval(creation: subCreation),
                keyFlags: keyFlags,
                embeddedBackSignature: backSig
            )
            newBindings.append(binding)
        }

        // Splice the fresh signatures into a ring (public tags 6/14, secret 5/7).
        // Replace the direct-key self-sig (a 0x1F in primary context) and each
        // subkey's 0x18 binding by ring order; keep the UID and its cert (0x13).
        func splice(_ packets: [ParsedPacket]) -> Data {
            enum Ctx { case none, primary, uid, subkey }
            var ctx: Ctx = .none
            var order = -1
            var out = Data()
            for pkt in packets {
                switch pkt.tag {
                case 6, 5:
                    ctx = .primary
                    out.append(buildPacket(tag: pkt.tag, body: Data(pkt.body)))
                case 13:
                    ctx = .uid
                    out.append(buildPacket(tag: 13, body: Data(pkt.body)))
                case 14, 7:
                    ctx = .subkey
                    order += 1
                    out.append(buildPacket(tag: pkt.tag, body: Data(pkt.body)))
                case 2:
                    let sig = (try? OpenPGPPacketParser.parseSignaturePacket(body: pkt.body))?.signatureType
                    if ctx == .primary, sig == 0x1F {
                        out.append(buildPacket(tag: 2, body: Data(newDirectKeySig)))
                    } else if ctx == .subkey, sig == 0x18, order >= 0, order < newBindings.count,
                              let fresh = newBindings[order] {
                        out.append(buildPacket(tag: 2, body: Data(fresh)))
                    } else {
                        out.append(buildPacket(tag: 2, body: Data(pkt.body)))
                    }
                default:
                    out.append(buildPacket(tag: pkt.tag, body: Data(pkt.body)))
                }
            }
            return out
        }

        let newPublic = splice(pubPackets)
        let secretPackets = try OpenPGPPacketParser.parsePackets(data: Array(secretKeyData))
        let newSecret = splice(secretPackets)
        return (publicKeyData: newPublic, secretKeyData: newSecret)
    }

    // MARK: - v6 add-subkey (issue #4 / full v6 management)

    struct V6AddSubkeyResult {
        let publicKeyData: Data
        let secretKeyData: Data
        let armoredPublicKey: String
        let subkeyFingerprintHex: String
    }

    /// Append a new v6 subkey (Ed25519 sign or X25519 encrypt) to an existing v6
    /// key, signing its 0x18 binding with the primary and, for a sign subkey,
    /// embedding a fresh 0x19 back-signature made BY the new subkey. The existing
    /// packets (and the primary fingerprint) are untouched. The new secret subkey
    /// is protected with the same passphrase as the rest of the key (a fresh
    /// per-packet Argon2 salt) when one is supplied, or written in the clear when
    /// the key is unprotected. Reuses the same v6 builders as generation.
    static func addV6Subkey(
        publicKeyData: Data,
        secretKeyData: Data,
        primarySigner: V6SignatureKey,
        primaryFingerprint: [UInt8],
        sign: Bool,
        expirationInterval: TimeInterval?,
        passphrase: String?
    ) throws -> V6AddSubkeyResult {
        try addV6Subkey(publicKeyData: publicKeyData, secretKeyData: secretKeyData,
                        primarySigner: primarySigner, primaryFingerprint: primaryFingerprint,
                        kind: sign ? .ed25519Sign : .x25519Encrypt,
                        expirationInterval: expirationInterval, passphrase: passphrase)
    }

    /// 8.3.0 (planning 4.6): the subkey shapes a v6 key can grow. The two
    /// classical ones keygen has always made, the RFC 9980 ML-KEM composites
    /// (Android 4.4.0 item 7: a post-quantum encryption subkey on an existing
    /// key), and a composite ML-DSA-65 + Ed25519 signing subkey, bound with an
    /// embedded 0x19 back-signature the composite subkey itself makes.
    enum V6SubkeyKind: String, CaseIterable, Identifiable {
        case ed25519Sign
        case x25519Encrypt
        case mlkem768Encrypt
        case mlkem1024Encrypt
        case mldsa65Sign
        /// 8.3.0 build 4: an Ed25519 authentication subkey (key flag 0x20, for
        /// SSH through gpg-agent), as v4 has had since 4.6. Not signing-capable,
        /// so no back-signature. Offered by Add Subkey, not by the keygen set.
        case ed25519Auth

        var id: String { rawValue }

        /// The kinds the advanced keygen offers on this device (the composite
        /// ML-DSA signer needs the OS's ML-DSA, iOS 26).
        static var composable: [V6SubkeyKind] {
            var list: [V6SubkeyKind] = [.mlkem768Encrypt, .mlkem1024Encrypt, .ed25519Sign, .x25519Encrypt]
            if MLDSAService.isAvailable { list.insert(.mldsa65Sign, at: 2) }
            return list
        }

        var isEncryption: Bool {
            switch self {
            case .x25519Encrypt, .mlkem768Encrypt, .mlkem1024Encrypt: return true
            case .ed25519Sign, .mldsa65Sign, .ed25519Auth: return false
            }
        }
    }

    /// 8.3.0 (4.6, granular keygen): both rings without every subkey of
    /// `algorithm` and the signatures that follow each one (its binding, any
    /// revocation). Used to strip the default X25519 subkey a fresh v6 key
    /// carries before the chosen set is grafted on. Packets are re-framed
    /// with the generator's own new-format writer.
    static func removingSubkeys(algorithm: UInt8, publicKeyData: Data, secretKeyData: Data) throws -> (publicKeyData: Data, secretKeyData: Data) {
        func strip(_ data: Data) throws -> Data {
            let packets = try OpenPGPPacketParser.parsePackets(data: Array(data))
            var out = Data()
            var skipping = false
            for p in packets {
                switch p.tag {
                case 5, 6, 13, 17:
                    skipping = false
                case 7, 14:
                    skipping = p.body.count > 5 && p.body[5] == algorithm
                default:
                    break
                }
                if skipping { continue }
                out.append(buildPacket(tag: p.tag, body: Data(p.body)))
            }
            return out
        }
        return (try strip(publicKeyData), try strip(secretKeyData))
    }

    static func addV6Subkey(
        publicKeyData: Data,
        secretKeyData: Data,
        primarySigner: V6SignatureKey,
        primaryFingerprint: [UInt8],
        kind: V6SubkeyKind,
        expirationInterval: TimeInterval?,
        passphrase: String?
    ) throws -> V6AddSubkeyResult {
        let creationTime = UInt32(Date().timeIntervalSince1970)

        let pubPackets = try OpenPGPPacketParser.parsePackets(data: Array(publicKeyData))
        guard let primaryPkt = pubPackets.first(where: { $0.tag == 6 }) else { throw V6EditError.noPrimary }
        let primaryBody = primaryPkt.body

        // Match the key's protection: a fresh Argon2+AEAD lock from the passphrase,
        // or nil (unprotected). lockPassphrase returns nil for a nil/empty string.
        let lock: V6SecretLock? = try lockPassphrase(from: passphrase).map { try makeV6Lock(passphrase: $0) }

        let subBody: [UInt8]
        let subSecretBody: [UInt8]
        let keyFlags: UInt8
        var backSig: [UInt8]? = nil

        switch kind {
        case .ed25519Sign:
            let sk = Curve25519.Signing.PrivateKey()
            let pub = Array(sk.publicKey.rawRepresentation)
            let priv = Array(sk.rawRepresentation)
            subBody = buildV6PublicKeyBody(creationTime: creationTime, algorithm: algoEd25519, keyMaterial: pub)
            subSecretBody = try buildV6SecretKeyBody(publicBody: subBody, rawPrivateKey: priv, lock: lock, packetTagID: 0xC7)
            keyFlags = 0x02
            let subFP = computeV6Fingerprint(packetBody: subBody)
            backSig = try buildV6PrimaryKeyBindingSignature(
                subkeySigner: .ed25519(sk), primaryKeyBody: primaryBody,
                subkeyBody: subBody, subkeyFingerprint: subFP, creationTime: creationTime)
        case .ed25519Auth:
            let sk = Curve25519.Signing.PrivateKey()
            subBody = buildV6PublicKeyBody(creationTime: creationTime, algorithm: algoEd25519,
                                           keyMaterial: Array(sk.publicKey.rawRepresentation))
            subSecretBody = try buildV6SecretKeyBody(publicBody: subBody, rawPrivateKey: Array(sk.rawRepresentation),
                                                     lock: lock, packetTagID: 0xC7)
            keyFlags = 0x20
        case .x25519Encrypt:
            let ek = Curve25519.KeyAgreement.PrivateKey()
            let pub = Array(ek.publicKey.rawRepresentation)
            let priv = Array(ek.rawRepresentation)
            subBody = buildV6PublicKeyBody(creationTime: creationTime, algorithm: algoX25519, keyMaterial: pub)
            subSecretBody = try buildV6SecretKeyBody(publicBody: subBody, rawPrivateKey: priv, lock: lock, packetTagID: 0xC7)
            keyFlags = 0x0C
        case .mlkem768Encrypt, .mlkem1024Encrypt:
            // The composite ML-KEM subkey exactly as `generate(pqcEncryption:)`
            // builds it: ECC public ‖ ML-KEM public, secret ECC scalar ‖ 64-octet seed.
            let suite: CompositeSuite = (kind == .mlkem768Encrypt) ? .ietf768 : .ietf1024
            let mlkemSeed = try secureRandomBytes(64)
            let (mlkemPub, _) = try MLKEMService.generateKeyPair(seed: Data(mlkemSeed), level: suite.mlkemLevel)
            let eccPub: [UInt8]
            let eccPriv: [UInt8]
            switch suite {
            case .ietf768:
                let ek = Curve25519.KeyAgreement.PrivateKey()
                eccPub = Array(ek.publicKey.rawRepresentation)
                eccPriv = Array(ek.rawRepresentation)
            case .ietf1024:
                let x448Priv = try X448.generatePrivateKey()
                eccPub = Array(try X448.publicKey(for: x448Priv))
                eccPriv = Array(x448Priv)
            }
            subBody = buildV6PublicKeyBody(creationTime: creationTime, algorithm: suite.algId,
                                           keyMaterial: eccPub + Array(mlkemPub))
            subSecretBody = try buildV6SecretKeyBody(publicBody: subBody, rawPrivateKey: eccPriv + mlkemSeed,
                                                     lock: lock, packetTagID: 0xC7)
            keyFlags = 0x0C
        case .mldsa65Sign:
            // A composite ML-DSA-65 + Ed25519 signing subkey (RFC 9980 algorithm
            // 30), its 0x19 back-signature made by the composite subkey itself.
            let suite = CompositeSignSuite.mldsa65Ed25519
            let edKey = Curve25519.Signing.PrivateKey()
            let mldsaSeed = try MLDSAService.randomSeed()
            let mldsaPub = try MLDSAService.publicKey(fromSeed: mldsaSeed, suite: suite)
            let secret = Array(edKey.rawRepresentation) + mldsaSeed
            subBody = buildV6PublicKeyBody(creationTime: creationTime, algorithm: suite.rawValue,
                                           keyMaterial: Array(edKey.publicKey.rawRepresentation) + mldsaPub)
            subSecretBody = try buildV6SecretKeyBody(publicBody: subBody, rawPrivateKey: secret, lock: lock, packetTagID: 0xC7)
            keyFlags = 0x02
            let subFP = computeV6Fingerprint(packetBody: subBody)
            backSig = try buildV6PrimaryKeyBindingSignature(
                subkeySigner: .composite(suite, compositeSecret: secret), primaryKeyBody: primaryBody,
                subkeyBody: subBody, subkeyFingerprint: subFP, creationTime: creationTime)
        }

        let subFP = computeV6Fingerprint(packetBody: subBody)
        let binding = try buildV6SubkeyBindingSignature(
            signer: primarySigner,
            primaryKeyBody: primaryBody,
            primaryFingerprint: primaryFingerprint,
            subkeyBody: subBody,
            creationTime: creationTime,
            expirationInterval: expirationInterval,
            keyFlags: keyFlags,
            embeddedBackSignature: backSig
        )

        var newPublic = publicKeyData
        newPublic.append(buildPacket(tag: 14, body: Data(subBody)))
        newPublic.append(buildPacket(tag: 2, body: Data(binding)))

        var newSecret = secretKeyData
        newSecret.append(buildPacket(tag: 7, body: Data(subSecretBody)))
        newSecret.append(buildPacket(tag: 2, body: Data(binding)))

        return V6AddSubkeyResult(
            publicKeyData: newPublic,
            secretKeyData: newSecret,
            armoredPublicKey: armorData(newPublic, type: .publicKey),
            subkeyFingerprintHex: subFP.map { String(format: "%02x", $0) }.joined()
        )
    }

    // MARK: - v6 Public Key Body

    /// Build a v6 public-key packet body (used for both primary tag 6 and subkey tag 14):
    ///   version(1)=6 | creationTime(4) | algo(1) | keyMaterialLen(4 BE) | keyMaterial
    private static func buildV6PublicKeyBody(
        creationTime: UInt32,
        algorithm: UInt8,
        keyMaterial: [UInt8]
    ) -> [UInt8] {
        var body: [UInt8] = []
        body.append(6)                                  // version
        body.append(contentsOf: creationTime.bigEndianBytes)
        body.append(algorithm)

        // 4-byte BE key material length
        let len = UInt32(keyMaterial.count)
        body.append(UInt8((len >> 24) & 0xFF))
        body.append(UInt8((len >> 16) & 0xFF))
        body.append(UInt8((len >>  8) & 0xFF))
        body.append(UInt8( len        & 0xFF))

        body.append(contentsOf: keyMaterial)
        return body
    }

    // MARK: - v6 Secret Key Body (unprotected or S2K-AEAD protected)

    /// A passphrase-derived secret-key lock, computed ONCE per key and shared
    /// across all secret packets. Holds the Argon2 salt + parameters (written into
    /// each packet's S2K specifier) and the derived S2K key (the HKDF IKM). Each
    /// packet still gets its own random nonce and a per-tag KEK.
    private struct V6SecretLock {
        let salt: [UInt8]        // 16-byte Argon2 salt
        let s2kKey: [UInt8]      // Argon2id output (HKDF IKM)
        let t: Int               // passes
        let p: Int               // parallelism
        let m: Int               // memory exponent (2^m KiB)
        let cipherAlgo: UInt8    // 9 = AES-256
        let aeadAlgo: UInt8      // 2 = OCB
    }

    private static func lockPassphrase(from passphrase: String?) -> String? {
        (passphrase?.isEmpty == false) ? passphrase : nil
    }

    private static func secureRandomBytes(_ n: Int) throws -> [UInt8] {
        var buf = [UInt8](repeating: 0, count: n)
        guard SecRandomCopyBytes(kSecRandomDefault, n, &buf) == errSecSuccess else {
            throw NSError(domain: "PGPony.V6KeyGen", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "Random generation failed"])
        }
        return buf
    }

    /// Run Argon2id once for the whole key. Memory cost dominates Argon2's run
    /// time, and the pure-Swift implementation here is far slower than a native
    /// one, so on-device we use t=3, p=4, m=2^14 KiB (16 MiB) — keeping RFC 9106's
    /// "raise the pass count when lowering memory" trade-off (t=3) for brute-force
    /// resistance while staying responsive (~2 s) for a per-decrypt unlock. The
    /// secret is additionally protected at rest by the iOS Keychain + biometrics.
    /// Importers (gpg, sq) read these parameters from each packet's S2K specifier,
    /// so the choice remains fully interoperable.
    private static func makeV6Lock(passphrase: String) throws -> V6SecretLock {
        let t = 3, p = 4, m = 14
        let salt = try secureRandomBytes(16)
        let argonStart = Date()
        let s2kKey = try Argon2Service.deriveKey(
            passphrase: passphrase,
            salt: salt,
            iterations: t,
            parallelism: p,
            memoryExponent: m,
            hashLength: 32          // AES-256 key size
        )
        pgpDebugLog(String(format: "DEBUG V6 gen: Argon2id (t=%d p=%d m=2^%d=%d MiB) took %.2fs",
                     t, p, m, (1 << m) / 1024, Date().timeIntervalSince(argonStart)))
        return V6SecretLock(salt: salt, s2kKey: s2kKey, t: t, p: p, m: m,
                            cipherAlgo: 9, aeadAlgo: 2)
    }

    /// Build a v6 secret-key packet body.
    ///
    /// When `lock` is nil, the body is UNPROTECTED (S2K usage 0):
    ///   public-key body | 0x00 | raw private key bytes
    /// (RFC 9580 §5.5.3 — for v6 the raw key material follows immediately, no checksum.)
    ///
    /// When a lock is supplied, the secret material is protected with Argon2id
    /// (S2K) + AES-256-OCB (AEAD), S2K usage octet 253. See `lockV6SecretMaterial`.
    private static func buildV6SecretKeyBody(
        publicBody: [UInt8],
        rawPrivateKey: [UInt8],
        lock: V6SecretLock?,
        packetTagID: UInt8
    ) throws -> [UInt8] {
        if let lock = lock {
            return try lockV6SecretMaterial(
                publicBody: publicBody,
                rawPrivateKey: rawPrivateKey,
                lock: lock,
                packetTagID: packetTagID
            )
        }
        var body = publicBody
        body.append(0)   // S2K usage octet = 0 (unprotected)
        body.append(contentsOf: rawPrivateKey)
        return body
    }

    /// Protect v6 secret key material with Argon2id (S2K) + AES-256-OCB (AEAD),
    /// per RFC 9580 §5.5.3 (S2K usage octet 253). Wire layout after the public body:
    ///
    ///   0xFD                       S2K usage = 253 (AEAD)
    ///   len1 (1 octet)             cumulative length of all conditional fields
    ///                              that follow, INCLUDING the nonce
    ///   cipher-algo (1)            9 = AES-256
    ///   AEAD-algo  (1)             2 = OCB
    ///   len2 (1 octet)            length of the S2K specifier that follows
    ///   S2K specifier (20)         Argon2: 0x04 | salt(16) | t | p | encoded_m
    ///   nonce (15)                 OCB IV (unique per packet)
    ///   ciphertext | tag(16)       AEAD-encrypted raw secret + auth tag
    ///
    /// KEK = HKDF-SHA256(IKM = Argon2 key, no salt,
    ///                   info = [packetTagID, 0x06, cipher-algo, AEAD-algo]).
    /// AAD = packetTagID || public-key packet body (from the version octet).
    /// The salt + S2K key come from the shared `lock`; the nonce is fresh per call,
    /// so reusing the S2K key across packets never reuses a (key, nonce) pair, and
    /// the KEK additionally differs by packet tag.
    /// No checksum or SHA-1 is used with usage 253 — only the AEAD tag.
    private static func lockV6SecretMaterial(
        publicBody: [UInt8],
        rawPrivateKey: [UInt8],
        lock: V6SecretLock,
        packetTagID: UInt8
    ) throws -> [UInt8] {
        let cipherAlgo = lock.cipherAlgo
        let aeadAlgo = lock.aeadAlgo

        let nonce = try secureRandomBytes(AEADService.nonceSize(for: aeadAlgo))  // OCB = 15

        // KEK via HKDF-SHA256 for key separation (RFC 9580 §5.5.3 ¶9).
        let info: [UInt8] = [packetTagID, 0x06, cipherAlgo, aeadAlgo]
        let kek = try OpenPGPPacketParser.hkdfSHA256(
            ikm: lock.s2kKey, salt: [], info: info, outputLength: 32
        )

        // Additional data: tag ID octet || public-key packet body.
        let aad: [UInt8] = [packetTagID] + publicBody

        // Single-chunk AEAD encryption of the raw secret; 16-byte tag appended.
        let ciphertextWithTag = try AEADService.encryptWithAppendedTag(
            plaintext: rawPrivateKey,
            key: kek,
            nonce: nonce,
            aeadAlgo: aeadAlgo,
            associatedData: aad
        )

        // Argon2 S2K specifier (20 octets).
        var s2kSpec: [UInt8] = [0x04]
        s2kSpec.append(contentsOf: lock.salt)
        s2kSpec.append(UInt8(lock.t))
        s2kSpec.append(UInt8(lock.p))
        s2kSpec.append(UInt8(lock.m))

        // v6 length #1: cipher(1) + aead(1) + len2-octet(1) + specifier + nonce.
        let len1 = 1 + 1 + 1 + s2kSpec.count + nonce.count

        var body = publicBody
        body.append(253)                    // S2K usage = AEAD
        body.append(UInt8(len1))            // v6 length #1
        body.append(cipherAlgo)
        body.append(aeadAlgo)
        body.append(UInt8(s2kSpec.count))   // v6 length #2 (= 20)
        body.append(contentsOf: s2kSpec)
        body.append(contentsOf: nonce)
        body.append(contentsOf: ciphertextWithTag)
        return body
    }

    // MARK: - v6 Direct Key Signature (type 0x1F)

    /// Build a v6 Direct Key self-signature. This is the foundational signature for
    /// a v6 certificate (RFC 9580 §10.1.1). It binds algorithm preferences, key flags,
    /// and other cert-wide policy to the primary key — independent of any user ID.
    /// Strict v6 verifiers (Sequoia) consider a v6 cert invalid without this signature.
    private static func buildV6DirectKeySignature(
        signer: V6SignatureKey,
        primaryKeyBody: [UInt8],
        primaryFingerprint: [UInt8],
        creationTime: UInt32,
        expirationInterval: TimeInterval?
    ) throws -> [UInt8] {

        var hashedSubpackets = Data()

        // Type 2: signature creation time (critical: high bit set on type)
        hashedSubpackets.append(buildSubpacket(type: 2, data: creationTime.bigEndianBytes, critical: true))

        // Type 27: key flags (critical). Ed25519: certify ONLY. The primary no
        // longer signs data directly — a dedicated Ed25519 signing subkey does —
        // matching the sq/GnuPG/PGPony-Android default v6 layout. (Certify, 0x01,
        // still lets the primary issue its own self-sigs and subkey bindings.)
        // 8.3.0 (4.1): a composite ML-DSA + EdDSA primary certifies AND signs
        // (0x03), Android's composite layout; it has no signing subkey.
        hashedSubpackets.append(buildSubpacket(type: 27, data: [signer.isComposite ? 0x03 : 0x01], critical: true))

        // Type 11: preferred symmetric algorithms (AES-256, AES-128) — match Sequoia's defaults
        hashedSubpackets.append(buildSubpacket(type: 11, data: [9, 7]))

        // Type 21: preferred hash algorithms (SHA-512, SHA-256); a composite
        // key prefers SHA-256 first (Android: 8, 10, 9), the hash it signs with.
        hashedSubpackets.append(buildSubpacket(type: 21, data: signer.isComposite ? [8, 10, 9] : [10, 8]))

        // Type 30: features = SEIPDv1 + SEIPDv2
        hashedSubpackets.append(buildSubpacket(type: 30, data: [0x09]))

        // Type 33: issuer fingerprint (v6 = byte 6 + 32 bytes)
        var fpData: [UInt8] = [6]
        fpData.append(contentsOf: primaryFingerprint)
        hashedSubpackets.append(buildSubpacket(type: 33, data: fpData))

        // Type 9: key expiration time (critical)
        if let interval = expirationInterval {
            let expSecs = UInt32(interval)
            hashedSubpackets.append(buildSubpacket(type: 9, data: expSecs.bigEndianBytes, critical: true))
        }

        let unhashedSubpackets = Data()

        // Direct Key signatures hash ONLY the primary key — no user ID, no subkey.
        return try assembleV6Signature(
            signer: signer,
            sigType: 0x1F,
            documentHashChunks: directKeyDocumentChunks(primaryKeyBody: primaryKeyBody),
            hashedSubpackets: Array(hashedSubpackets),
            unhashedSubpackets: Array(unhashedSubpackets)
        )
    }

    // MARK: - v6 Certification Signature (type 0x13)

    /// Build a v6 positive-certification self-signature over (primary key | user ID).
    /// With the new v6 cert structure, this sig is much simpler — algorithm prefs and
    /// key flags now live in the Direct Key sig. The cert sig just binds the user ID.
    private static func buildV6CertificationSignature(
        signer: V6SignatureKey,
        primaryKeyBody: [UInt8],
        primaryFingerprint: [UInt8],
        userIDBytes: [UInt8],
        creationTime: UInt32
    ) throws -> [UInt8] {

        var hashedSubpackets = Data()

        // Type 2: creation time (critical)
        hashedSubpackets.append(buildSubpacket(type: 2, data: creationTime.bigEndianBytes, critical: true))

        // 8.3.0 (4.1): a composite primary repeats its key flags (certify |
        // sign) on the user ID certification, as Android writes them, for
        // verifiers that read flags off the UID self-signature.
        if signer.isComposite {
            hashedSubpackets.append(buildSubpacket(type: 27, data: [0x03], critical: true))
        }

        // Type 25: Primary User ID flag — marks this UID as primary (critical)
        hashedSubpackets.append(buildSubpacket(type: 25, data: [0x01], critical: true))

        // Type 33: issuer fingerprint (v6)
        var fpData: [UInt8] = [6]
        fpData.append(contentsOf: primaryFingerprint)
        hashedSubpackets.append(buildSubpacket(type: 33, data: fpData))

        let unhashedSubpackets = Data()

        return try assembleV6Signature(
            signer: signer,
            sigType: 0x13,
            documentHashChunks: certificationDocumentChunks(
                primaryKeyBody: primaryKeyBody,
                userIDBytes: userIDBytes
            ),
            hashedSubpackets: Array(hashedSubpackets),
            unhashedSubpackets: Array(unhashedSubpackets)
        )
    }

    // MARK: - v6 Subkey Binding Signature (type 0x18)

    private static func buildV6SubkeyBindingSignature(
        signer: V6SignatureKey,
        primaryKeyBody: [UInt8],
        primaryFingerprint: [UInt8],
        subkeyBody: [UInt8],
        creationTime: UInt32,
        expirationInterval: TimeInterval? = nil,
        keyFlags: UInt8 = 0x0C,
        embeddedBackSignature: [UInt8]? = nil
    ) throws -> [UInt8] {

        var hashedSubpackets = Data()

        // Signature creation time (critical)
        hashedSubpackets.append(buildSubpacket(type: 2, data: creationTime.bigEndianBytes, critical: true))

        // Key expiration time (critical) if provided — placed before key flags to
        // match Sequoia's subpacket order ([2, 9, 27, (32), 33]).
        if let interval = expirationInterval {
            let expSecs = UInt32(interval)
            hashedSubpackets.append(buildSubpacket(type: 9, data: expSecs.bigEndianBytes, critical: true))
        }

        // Key flags (critical): 0x0C (encrypt comms+storage) for an encryption
        // subkey, 0x02 (sign) for a signing subkey.
        hashedSubpackets.append(buildSubpacket(type: 27, data: [keyFlags], critical: true))

        // Embedded Signature (type 32, critical): the primary-key-binding (0x19)
        // back-signature a signing subkey MUST carry (RFC 9580 §5.2.3.34). Sequoia
        // places it in the HASHED, critical subpacket area, so we match that.
        if let backSig = embeddedBackSignature {
            hashedSubpackets.append(buildSubpacket(type: 32, data: backSig, critical: true))
        }

        // Issuer fingerprint (v6) — the PRIMARY key (it makes the binding sig).
        var fpData: [UInt8] = [6]
        fpData.append(contentsOf: primaryFingerprint)
        hashedSubpackets.append(buildSubpacket(type: 33, data: fpData))

        let unhashedSubpackets = Data()

        return try assembleV6Signature(
            signer: signer,
            sigType: 0x18,
            documentHashChunks: subkeyBindingDocumentChunks(
                primaryKeyBody: primaryKeyBody,
                subkeyBody: subkeyBody
            ),
            hashedSubpackets: Array(hashedSubpackets),
            unhashedSubpackets: Array(unhashedSubpackets)
        )
    }

    // MARK: - v6 Primary Key Binding Signature (type 0x19, "back-signature")

    /// A signing subkey must prove it consents to being bound to the primary by
    /// embedding a primary-key-binding signature (type 0x19) that the SUBKEY makes
    /// over (primary key ‖ subkey) — the same hashed content as the 0x18 binding.
    /// This 0x19 is then embedded (subpacket type 32) inside the 0x18 binding sig.
    /// `subkeySigningKey` is the signing subkey's own private key; `subkeyFingerprint`
    /// is the subkey's v6 fingerprint (issuer of this back-sig).
    private static func buildV6PrimaryKeyBindingSignature(
        subkeySigner: V6SignatureKey,
        primaryKeyBody: [UInt8],
        subkeyBody: [UInt8],
        subkeyFingerprint: [UInt8],
        creationTime: UInt32
    ) throws -> [UInt8] {

        var hashedSubpackets = Data()

        // Creation time (critical)
        hashedSubpackets.append(buildSubpacket(type: 2, data: creationTime.bigEndianBytes, critical: true))

        // Issuer fingerprint (v6) — the SUBKEY signs this back-sig.
        var fpData: [UInt8] = [6]
        fpData.append(contentsOf: subkeyFingerprint)
        hashedSubpackets.append(buildSubpacket(type: 33, data: fpData))

        return try assembleV6Signature(
            signer: subkeySigner,
            sigType: 0x19,
            documentHashChunks: subkeyBindingDocumentChunks(
                primaryKeyBody: primaryKeyBody,
                subkeyBody: subkeyBody
            ),
            hashedSubpackets: Array(hashedSubpackets),
            unhashedSubpackets: []
        )
    }

    // MARK: - v6 Signature Assembly (shared)

    /// Build a v6 signature packet body. `documentHashChunks` is the prefix of the hash
    /// input — the content being signed (key + user ID for cert, key + subkey for binding,
    /// or raw bytes for binary document sigs).
    ///
    /// Hash input = salt(16) || documentHashChunks || rawHashedPortion || trailer
    /// Where:
    ///   rawHashedPortion = version(1)=6 | sigType(1) | pubAlgo(1)=27 | hashAlgo(1)=8
    ///                    | hashedLen(4 BE) | hashedSubpackets
    ///   trailer          = 0x06 || 0xFF || 8-byte BE length of rawHashedPortion
    static func assembleV6Signature(
        signingKey: Curve25519.Signing.PrivateKey,
        sigType: UInt8,
        documentHashChunks: [UInt8],
        hashedSubpackets: [UInt8],
        unhashedSubpackets: [UInt8]
    ) throws -> [UInt8] {
        try assembleV6Signature(
            signer: .ed25519(signingKey),
            sigType: sigType,
            documentHashChunks: documentHashChunks,
            hashedSubpackets: hashedSubpackets,
            unhashedSubpackets: unhashedSubpackets
        )
    }

    /// 8.3.0 (4.1): the same v6 signature, made by any v6 signer. Ed25519 keeps
    /// the SHA-512 / 32-octet-salt self-signatures this app has always written;
    /// a composite ML-DSA + EdDSA key writes SHA-256 with a 16-octet salt, the
    /// hash Android uses for every composite signature, and its algorithm
    /// octet (30/31) and composite signature value.
    static func assembleV6Signature(
        signer: V6SignatureKey,
        sigType: UInt8,
        documentHashChunks: [UInt8],
        hashedSubpackets: [UInt8],
        unhashedSubpackets: [UInt8]
    ) throws -> [UInt8] {
        let hashAlgo = signer.selfSignatureHashAlgorithm
        let pubAlgo = signer.publicKeyAlgorithm

        // Random salt, sized for the hash (RFC 9580 Table 23)
        var salt = [UInt8](repeating: 0, count: signer.selfSignatureSaltLength)
        guard SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt) == errSecSuccess else {
            throw NSError(domain: "PGPony.V6KeyGen", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Salt generation failed"])
        }

        // Build the raw hashed portion of the sig packet
        var rawHashedPortion: [UInt8] = []
        rawHashedPortion.append(6)                // version
        rawHashedPortion.append(sigType)
        rawHashedPortion.append(pubAlgo)          // 27, or 30/31 composite
        rawHashedPortion.append(hashAlgo)         // 10, or 8 composite

        let hashedLen = UInt32(hashedSubpackets.count)
        rawHashedPortion.append(UInt8((hashedLen >> 24) & 0xFF))
        rawHashedPortion.append(UInt8((hashedLen >> 16) & 0xFF))
        rawHashedPortion.append(UInt8((hashedLen >>  8) & 0xFF))
        rawHashedPortion.append(UInt8( hashedLen        & 0xFF))
        rawHashedPortion.append(contentsOf: hashedSubpackets)

        // Build hash input
        var hashInput = Data()
        hashInput.append(contentsOf: salt)
        hashInput.append(contentsOf: documentHashChunks)
        hashInput.append(contentsOf: rawHashedPortion)

        // v6 trailer: 0x06 0xFF + 4-byte BE length of rawHashedPortion
        // (RFC 9580 §5.2.4 — four octets for v4/v6; 8 was the dropped v5 form).
        let totalHashed = UInt32(rawHashedPortion.count)
        hashInput.append(0x06)
        hashInput.append(0xFF)
        hashInput.append(UInt8((totalHashed >> 24) & 0xFF))
        hashInput.append(UInt8((totalHashed >> 16) & 0xFF))
        hashInput.append(UInt8((totalHashed >>  8) & 0xFF))
        hashInput.append(UInt8( totalHashed        & 0xFF))

        let digestBytes = V6SignatureKey.digest(hashInput, hashAlgorithm: hashAlgo)

        // Sign the digest
        let sigBytes = try signer.sign(digest: digestBytes)
        guard sigBytes.count == signer.signatureLength else {
            throw NSError(domain: "PGPony.V6KeyGen", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "v6 signature must be \(signer.signatureLength) bytes, got \(sigBytes.count)"])
        }

        // Assemble the v6 sig packet body
        var sigBody: [UInt8] = []
        sigBody.append(6)
        sigBody.append(sigType)
        sigBody.append(pubAlgo)
        sigBody.append(hashAlgo)

        sigBody.append(UInt8((hashedLen >> 24) & 0xFF))
        sigBody.append(UInt8((hashedLen >> 16) & 0xFF))
        sigBody.append(UInt8((hashedLen >>  8) & 0xFF))
        sigBody.append(UInt8( hashedLen        & 0xFF))
        sigBody.append(contentsOf: hashedSubpackets)

        let unhashedLen = UInt32(unhashedSubpackets.count)
        sigBody.append(UInt8((unhashedLen >> 24) & 0xFF))
        sigBody.append(UInt8((unhashedLen >> 16) & 0xFF))
        sigBody.append(UInt8((unhashedLen >>  8) & 0xFF))
        sigBody.append(UInt8( unhashedLen        & 0xFF))
        sigBody.append(contentsOf: unhashedSubpackets)

        // Hash prefix
        sigBody.append(digestBytes[0])
        sigBody.append(digestBytes[1])

        // Salt length + salt
        sigBody.append(UInt8(salt.count))
        sigBody.append(contentsOf: salt)

        // Signature data: raw bytes (no MPI)
        sigBody.append(contentsOf: sigBytes)

        return sigBody
    }

    // MARK: - Document chunks for cert / subkey-binding / direct-key sigs

    /// For a v6 Direct Key sig (type 0x1F), the signed content is just the primary key:
    ///   0x9B || 4-byte BE body length || primary key body
    static func directKeyDocumentChunks(
        primaryKeyBody: [UInt8]
    ) -> [UInt8] {
        var out: [UInt8] = []
        out.append(0x9B)
        let keyLen = UInt32(primaryKeyBody.count)
        out.append(UInt8((keyLen >> 24) & 0xFF))
        out.append(UInt8((keyLen >> 16) & 0xFF))
        out.append(UInt8((keyLen >>  8) & 0xFF))
        out.append(UInt8( keyLen        & 0xFF))
        out.append(contentsOf: primaryKeyBody)
        return out
    }

    /// For a v6 cert sig (type 0x13), the signed content is:
    ///   v6 primary key as: 0x9B || 4-byte BE body length || body
    ///   user ID as:        0xB4 || 4-byte BE body length || body
    private static func certificationDocumentChunks(
        primaryKeyBody: [UInt8],
        userIDBytes: [UInt8]
    ) -> [UInt8] {
        var out: [UInt8] = []

        // Primary key wrapped with v6 prefix (0x9B)
        out.append(0x9B)
        let keyLen = UInt32(primaryKeyBody.count)
        out.append(UInt8((keyLen >> 24) & 0xFF))
        out.append(UInt8((keyLen >> 16) & 0xFF))
        out.append(UInt8((keyLen >>  8) & 0xFF))
        out.append(UInt8( keyLen        & 0xFF))
        out.append(contentsOf: primaryKeyBody)

        // User ID wrapped with 0xB4 + 4-byte length
        let uidLen = UInt32(userIDBytes.count)
        out.append(0xB4)
        out.append(UInt8((uidLen >> 24) & 0xFF))
        out.append(UInt8((uidLen >> 16) & 0xFF))
        out.append(UInt8((uidLen >>  8) & 0xFF))
        out.append(UInt8( uidLen        & 0xFF))
        out.append(contentsOf: userIDBytes)

        return out
    }

    /// For a v6 subkey binding sig (type 0x18), the signed content is:
    ///   primary key:  0x9B || 4-byte length || body
    ///   subkey:       0x9B || 4-byte length || body
    private static func subkeyBindingDocumentChunks(
        primaryKeyBody: [UInt8],
        subkeyBody: [UInt8]
    ) -> [UInt8] {
        var out: [UInt8] = []

        out.append(0x9B)
        let kLen = UInt32(primaryKeyBody.count)
        out.append(UInt8((kLen >> 24) & 0xFF))
        out.append(UInt8((kLen >> 16) & 0xFF))
        out.append(UInt8((kLen >>  8) & 0xFF))
        out.append(UInt8( kLen        & 0xFF))
        out.append(contentsOf: primaryKeyBody)

        out.append(0x9B)
        let sLen = UInt32(subkeyBody.count)
        out.append(UInt8((sLen >> 24) & 0xFF))
        out.append(UInt8((sLen >> 16) & 0xFF))
        out.append(UInt8((sLen >>  8) & 0xFF))
        out.append(UInt8( sLen        & 0xFF))
        out.append(contentsOf: subkeyBody)

        return out
    }

    // MARK: - v6 Fingerprint

    /// SHA-256 of (0x9B || 4-byte BE length || body) — returns 32 bytes.
    private static func computeV6Fingerprint(packetBody: [UInt8]) -> [UInt8] {
        var input: [UInt8] = []
        input.append(0x9B)
        let len = UInt32(packetBody.count)
        input.append(UInt8((len >> 24) & 0xFF))
        input.append(UInt8((len >> 16) & 0xFF))
        input.append(UInt8((len >>  8) & 0xFF))
        input.append(UInt8( len        & 0xFF))
        input.append(contentsOf: packetBody)

        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256(input, CC_LONG(input.count), &hash)
        return hash
    }

    // MARK: - Subpacket / packet encoding (same as v4)

    private static func buildSubpacket(type: UInt8, data: [UInt8], critical: Bool = false) -> Data {
        var out = Data()
        let totalLen = data.count + 1
        if totalLen < 192 {
            out.append(UInt8(totalLen))
        } else if totalLen < 8384 {
            let adj = totalLen - 192
            out.append(UInt8((adj >> 8) + 192))
            out.append(UInt8(adj & 0xFF))
        } else {
            out.append(0xFF)
            out.append(UInt8((totalLen >> 24) & 0xFF))
            out.append(UInt8((totalLen >> 16) & 0xFF))
            out.append(UInt8((totalLen >>  8) & 0xFF))
            out.append(UInt8( totalLen        & 0xFF))
        }
        // Critical bit is the high bit of the type octet (RFC 9580 §5.2.3.7)
        out.append(critical ? (type | 0x80) : type)
        out.append(contentsOf: data)
        return out
    }

    private static func buildPacket(tag: UInt8, body: Data) -> Data {
        var out = Data()
        out.append(0xC0 | (tag & 0x3F))
        let n = body.count
        if n < 192 {
            out.append(UInt8(n))
        } else if n < 8384 {
            let adj = n - 192
            out.append(UInt8((adj >> 8) + 192))
            out.append(UInt8(adj & 0xFF))
        } else {
            out.append(0xFF)
            out.append(UInt8((n >> 24) & 0xFF))
            out.append(UInt8((n >> 16) & 0xFF))
            out.append(UInt8((n >>  8) & 0xFF))
            out.append(UInt8( n        & 0xFF))
        }
        out.append(body)
        return out
    }

    // MARK: - Armor

    private enum ArmorType {
        case publicKey
        case secretKey
        var header: String {
            switch self {
            case .publicKey: return "-----BEGIN PGP PUBLIC KEY BLOCK-----"
            case .secretKey: return "-----BEGIN PGP PRIVATE KEY BLOCK-----"
            }
        }
        var footer: String {
            switch self {
            case .publicKey: return "-----END PGP PUBLIC KEY BLOCK-----"
            case .secretKey: return "-----END PGP PRIVATE KEY BLOCK-----"
            }
        }
    }

    private static func armorData(_ data: Data, type: ArmorType) -> String {
        let base64 = data.base64EncodedString(options: .lineLength76Characters)
        let crc = crc24(data)
        let crcBase64 = Data(crc).base64EncodedString()
        return "\(type.header)\n\n\(base64)\n=\(crcBase64)\n\(type.footer)"
    }

    private static func crc24(_ data: Data) -> [UInt8] {
        var crc: UInt32 = 0xB704CE
        for byte in data {
            crc ^= UInt32(byte) << 16
            for _ in 0..<8 {
                crc <<= 1
                if crc & 0x1000000 != 0 { crc ^= 0x1864CFB }
            }
        }
        crc &= 0xFFFFFF
        return [
            UInt8((crc >> 16) & 0xFF),
            UInt8((crc >>  8) & 0xFF),
            UInt8( crc        & 0xFF)
        ]
    }
}

// MARK: - Byte helpers (file-scoped to avoid clashing with v4 generator's extensions)

private extension UInt32 {
    var bigEndianBytes: [UInt8] {
        [
            UInt8((self >> 24) & 0xFF),
            UInt8((self >> 16) & 0xFF),
            UInt8((self >>  8) & 0xFF),
            UInt8( self        & 0xFF)
        ]
    }
}
