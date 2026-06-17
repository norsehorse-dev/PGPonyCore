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

    private static let hashSHA512: UInt8 = 10
    private static let saltLenSHA512 = 32

    // MARK: - Generate

    static func generate(
        name: String,
        email: String,
        passphrase: String?,
        expirationInterval: TimeInterval?
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

        // Generate X25519 encryption subkey
        let encryptionKey = Curve25519.KeyAgreement.PrivateKey()
        let encryptionPub  = Array(encryptionKey.publicKey.rawRepresentation)
        let encryptionPriv = Array(encryptionKey.rawRepresentation)

        // Build v6 primary public-key packet body
        let primaryPubBody = buildV6PublicKeyBody(
            creationTime: creationTime,
            algorithm: algoEd25519,
            keyMaterial: signingPub
        )

        // v6 fingerprint = SHA-256(0x9B || 4-byte BE length || body)
        let fingerprint = computeV6Fingerprint(packetBody: primaryPubBody)
        let keyID = Array(fingerprint.prefix(8))   // v6: first 8 bytes

        // User ID
        let userID = "\(name) <\(email)>"
        let userIDBytes = Array(userID.utf8)

        // Build v6 cert structure following RFC 9580 §10.1.1:
        //   primary | DirectKey-sig (algorithm prefs, key flags) | userID | PositiveCertification |
        //   subkey | SubkeyBinding-sig
        // Sequoia and strict v6 validators require the DirectKey sig to hold the
        // certificate-wide policy (prefs, features, key flags). The cert sig over
        // the user ID is then simpler.

        // Direct Key Signature (type 0x1F) — anchors algorithm preferences for the cert
        let directKeySig = try buildV6DirectKeySignature(
            signingKey: signingKey,
            primaryKeyBody: primaryPubBody,
            primaryFingerprint: fingerprint,
            creationTime: creationTime,
            expirationInterval: expirationInterval
        )

        // Self-signature on the user ID (cert type 0x13) — simpler now, just binds UID
        let selfSig = try buildV6CertificationSignature(
            signingKey: signingKey,
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
            subkeySigningKey: signSubkey,
            primaryKeyBody: primaryPubBody,
            subkeyBody: signSubBody,
            subkeyFingerprint: signSubFingerprint,
            creationTime: creationTime
        )

        // Subkey binding (0x18) for the signing subkey: key flags 0x02 (sign) and
        // the embedded back-sig, signed by the primary.
        let signSubBindingSig = try buildV6SubkeyBindingSignature(
            signingKey: signingKey,
            primaryKeyBody: primaryPubBody,
            primaryFingerprint: fingerprint,
            subkeyBody: signSubBody,
            creationTime: creationTime,
            expirationInterval: expirationInterval,
            keyFlags: 0x02,
            embeddedBackSignature: signSubBackSig
        )

        // Subkey 2: v6 X25519 encryption subkey
        let subkeyPubBody = buildV6PublicKeyBody(
            creationTime: creationTime,
            algorithm: algoX25519,
            keyMaterial: encryptionPub
        )

        // Subkey binding signature (type 0x18) — encrypt flags 0x0C (no back-sig)
        let subkeyBindingSig = try buildV6SubkeyBindingSignature(
            signingKey: signingKey,
            primaryKeyBody: primaryPubBody,
            primaryFingerprint: fingerprint,
            subkeyBody: subkeyPubBody,
            creationTime: creationTime,
            expirationInterval: expirationInterval,
            keyFlags: 0x0C
        )

        // Assemble transferable public-key packet stream (v6 cert layout):
        //   primary | DirectKey | UID | PositiveCert | signSub | signBind | encSub | encBind
        var pubKeyPackets = Data()
        pubKeyPackets.append(buildPacket(tag: 6,  body: Data(primaryPubBody)))
        pubKeyPackets.append(buildPacket(tag: 2,  body: Data(directKeySig)))
        pubKeyPackets.append(buildPacket(tag: 13, body: Data(userIDBytes)))
        pubKeyPackets.append(buildPacket(tag: 2,  body: Data(selfSig)))
        pubKeyPackets.append(buildPacket(tag: 14, body: Data(signSubBody)))
        pubKeyPackets.append(buildPacket(tag: 2,  body: Data(signSubBindingSig)))
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
            rawPrivateKey: encryptionPriv,
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
        signingKey: Curve25519.Signing.PrivateKey,
        primaryKeyBody: [UInt8],
        primaryFingerprint: [UInt8],
        creationTime: UInt32,
        expirationInterval: TimeInterval?
    ) throws -> [UInt8] {

        var hashedSubpackets = Data()

        // Type 2: signature creation time (critical: high bit set on type)
        hashedSubpackets.append(buildSubpacket(type: 2, data: creationTime.bigEndianBytes, critical: true))

        // Type 27: key flags = certify ONLY (critical). The primary no longer
        // signs data directly — a dedicated Ed25519 signing subkey does — matching
        // the sq/GnuPG/PGPony-Android default v6 layout. (Certify, 0x01, still lets
        // the primary issue its own self-sigs and subkey bindings.)
        hashedSubpackets.append(buildSubpacket(type: 27, data: [0x01], critical: true))

        // Type 11: preferred symmetric algorithms (AES-256, AES-128) — match Sequoia's defaults
        hashedSubpackets.append(buildSubpacket(type: 11, data: [9, 7]))

        // Type 21: preferred hash algorithms (SHA-512, SHA-256)
        hashedSubpackets.append(buildSubpacket(type: 21, data: [10, 8]))

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
            signingKey: signingKey,
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
        signingKey: Curve25519.Signing.PrivateKey,
        primaryKeyBody: [UInt8],
        primaryFingerprint: [UInt8],
        userIDBytes: [UInt8],
        creationTime: UInt32
    ) throws -> [UInt8] {

        var hashedSubpackets = Data()

        // Type 2: creation time (critical)
        hashedSubpackets.append(buildSubpacket(type: 2, data: creationTime.bigEndianBytes, critical: true))

        // Type 25: Primary User ID flag — marks this UID as primary (critical)
        hashedSubpackets.append(buildSubpacket(type: 25, data: [0x01], critical: true))

        // Type 33: issuer fingerprint (v6)
        var fpData: [UInt8] = [6]
        fpData.append(contentsOf: primaryFingerprint)
        hashedSubpackets.append(buildSubpacket(type: 33, data: fpData))

        let unhashedSubpackets = Data()

        return try assembleV6Signature(
            signingKey: signingKey,
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
        signingKey: Curve25519.Signing.PrivateKey,
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
            signingKey: signingKey,
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
        subkeySigningKey: Curve25519.Signing.PrivateKey,
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
            signingKey: subkeySigningKey,
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

        // Generate 16-byte random salt
        var salt = [UInt8](repeating: 0, count: saltLenSHA512)
        guard SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt) == errSecSuccess else {
            throw NSError(domain: "PGPony.V6KeyGen", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Salt generation failed"])
        }

        // Build the raw hashed portion of the sig packet
        var rawHashedPortion: [UInt8] = []
        rawHashedPortion.append(6)                // version
        rawHashedPortion.append(sigType)
        rawHashedPortion.append(algoEd25519)      // 27
        rawHashedPortion.append(hashSHA512)       // 10

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

        let digest = SHA512.hash(data: hashInput)
        let digestBytes = Array(digest)

        // Sign the digest
        let rawSig = try signingKey.signature(for: Data(digestBytes))
        let sigBytes = Array(rawSig)
        guard sigBytes.count == 64 else {
            throw NSError(domain: "PGPony.V6KeyGen", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "Ed25519 sig must be 64 bytes"])
        }

        // Assemble the v6 sig packet body
        var sigBody: [UInt8] = []
        sigBody.append(6)
        sigBody.append(sigType)
        sigBody.append(algoEd25519)
        sigBody.append(hashSHA512)

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

        // Signature data: raw 64 bytes
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
