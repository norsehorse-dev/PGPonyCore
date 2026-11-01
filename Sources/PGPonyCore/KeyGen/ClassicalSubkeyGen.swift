// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// ClassicalSubkeyGen.swift
// PGPony
//
// v8.2.0 stage 3 (planning §2.2, the hard half): add a subkey to an existing
// software key pair. This is the iOS counterpart of Android 4.2.0's
// ClassicalSubkeyGen (workstream H). Scope matches it: classical subkeys on a
// v4 ring: Ed25519 (sign), Cv25519 (encrypt), and RSA 2048/4096 (sign or
// encrypt), plus, since 8.3.0 (planning 4.6, Android 4.4.0 #49), Ed25519 and
// RSA authentication subkeys (key flag 0x20, for SSH through gpg-agent; no
// back-signature, which the RFC asks of signing-capable subkeys only).
// Composite / PQC subkey types and v6 rings are deliberately out of
// scope here (the "expose deliberately, not accidentally" note in the plan).
//
// The primary must be a v4 software key, either Ed25519 or RSA, because the
// new subkey's binding signature is issued BY the primary: an Ed25519 primary
// signs it with CryptoKit, an RSA primary with the Security framework (reusing
// PGPService's vetted RSA secret unlock and SecKey build). v6 rings and
// hardware (card) primaries are still out of scope and refused with a clear
// message.
//
// What a subkey addition writes (RFC 4880):
//   * a Public-Subkey (tag 14) / Secret-Subkey (tag 7) packet for the new key,
//   * a Subkey Binding Signature (type 0x18) made by the PRIMARY over
//     (primary ‖ subkey), carrying the key-flags subpacket that grants the
//     subkey its capability, and, for a SIGN-capable subkey, an embedded
//     Primary Key Binding Signature (type 0x19, a "back-signature") made BY
//     the subkey over the same (primary ‖ subkey), without which gpg rejects a
//     signing subkey ("no valid binding").
//
// Unlike the UID edits, this never rewrites existing packets: the new subkey
// packet and its binding are APPENDED to the end of each ring, so every
// existing byte (primary, UIDs, their certs, prior subkeys) is preserved
// exactly and the fingerprint is untouched.
//
// The crypto primitives are reused from Ed25519KeyGenerator rather than
// reimplemented (canonicalMPI, the S2K key derivation and AES-128-CFB writer,
// the public-body and fingerprint builders) so the bytes match what PGPony
// already ships and gpg already accepts. RSA key material comes from the
// Security framework (SecKey), whose PKCS#1 external representation maps to
// OpenPGP's (n,e,d,p,q,u) with no big-integer work; see generateRSA().
//
// 8.4.0 build 10 (plan 5m): a LibrePGP v5 Ed448 primary (GnuPG 2.4) takes the
// v4 Ed25519 and Curve25519 subkeys gpg 2.4.4 `--quick-add-key` adds under
// it: a v4 key packet, bound by a version 5 0x18 signature
// (OpenPGP448.keySignatureBody, the primary framed 0x9A | len4, the v4
// subkey 0x99 | len2), the back-signature of a signing subkey a v4 0x19 made
// by the subkey over the same document and carried in the binding's
// unhashed area, as gpg writes both. Checked with gpg 2.4.4.
//
// VERIFICATION RECIPE (on the armoredPublicKey / an export of the secret ring):
//   gpg --no-default-keyring --keyring /tmp/x.gpg --import edited.asc
//   gpg --no-default-keyring --keyring /tmp/x.gpg --check-sigs <FPR>
// Target: the new subkey lists with the right capability and its binding reads
// sig! (and, for a sign subkey, gpg accepts it, proof the 0x19 back-sig is
// valid); the primary fingerprint is unchanged.

import Foundation
import CryptoKit
import CommonCrypto
import Security

enum ClassicalSubkeyGen {

    // MARK: - Public surface

    enum SubkeyType: String, CaseIterable, Identifiable {
        case ed25519Sign
        case cv25519Encrypt
        case rsa2048Sign
        case rsa2048Encrypt
        case rsa4096Sign
        case rsa4096Encrypt
        // 8.3.0 (planning 4.6, Android 4.4.0 #49): authentication subkeys, key
        // flag 0x20, for SSH through gpg-agent. No back-signature: the RFC
        // asks for one on a signing-capable subkey only.
        case ed25519Auth
        case rsa2048Auth
        case rsa4096Auth
        // v8.2.0 (full v6 management): v6 subkeys are added by V6KeyGenerator, not
        // this v4 path. They ride the same enum so the Add Subkey sheet can offer
        // them; performAddSubkey routes them by `isV6`.
        case v6Ed25519Sign
        case v6X25519Encrypt
        // 8.3.0 (planning 4.6, Android 4.4.0 item 7): post-quantum subkeys on
        // an existing key. The RFC 9980 ML-KEM composites on a v6 key (V6KeyGenerator
        // graft), a composite ML-DSA-65 + Ed25519 signing subkey on a v6 key
        // (iOS 26), and the algorithm 35 subkey on a v4 key, which turns a
        // classical v4 key into the 4.3 interop shape while its Cv25519 subkey
        // keeps classical decrypt alive.
        case v6MLKEM768Encrypt
        case v6MLKEM1024Encrypt
        case v6MLDSA65Sign
        case v4MLKEM768Encrypt
        // 8.3.0 build 4: the v6 authentication subkey (V6KeyGenerator .ed25519Auth).
        case v6Ed25519Auth
        // 8.4.0 build 9 (plan 5l): an ML-DSA-87 + Ed448 signing subkey
        // (algorithm 31) on a v6 key, next to the ML-DSA-65 one (iOS 26), and
        // (Android 4.6.0 item 21) RSA subkeys, v6-framed, under a composite
        // ML-DSA primary (algorithm 30 or 31). V6KeyGenerator builds them
        // (`v6AddOnlyKind`); the keygen set does not offer them.
        case v6MLDSA87Sign
        case v6RSA2048Sign
        case v6RSA2048Encrypt
        case v6RSA2048Auth
        case v6RSA4096Sign
        case v6RSA4096Encrypt
        case v6RSA4096Auth
        // 8.4.0 build 10 (plan 5m): RFC 9580 Ed448 and X448 subkeys, offered
        // under an RFC 9580 Ed448 primary (V6KeyGenerator's add-only shapes).
        case v6Ed448Sign
        case v6X448Encrypt

        var id: String { rawValue }

        /// 8.4.0 build 9 (plan 5l): the RSA types offered under a composite
        /// ML-DSA primary.
        static let v6RSATypes: [SubkeyType] = [.v6RSA2048Sign, .v6RSA2048Encrypt, .v6RSA2048Auth,
                                              .v6RSA4096Sign, .v6RSA4096Encrypt, .v6RSA4096Auth]

        var isV6RSA: Bool { Self.v6RSATypes.contains(self) }

        /// 8.4.0 build 9 (plan 5l): the V6KeyGenerator shape of a type Add
        /// Subkey offers outside the keygen set; nil for every other type.
        var v6AddOnlyKind: V6KeyGenerator.V6AddOnlySubkeyKind? {
            switch self {
            case .v6MLDSA87Sign: return .mldsa87Sign
            case .v6RSA2048Sign, .v6RSA2048Encrypt, .v6RSA2048Auth,
                 .v6RSA4096Sign, .v6RSA4096Encrypt, .v6RSA4096Auth:
                return .rsa(bits: rsaBits ?? 2048, keyFlags: keyFlags)
            case .v6Ed448Sign: return .ed448Sign
            case .v6X448Encrypt: return .x448Encrypt
            default: return nil
            }
        }

        /// v6 subkeys are generated by V6KeyGenerator (v6 packet + salted binding),
        /// not by this v4 add-subkey path.
        var isV6: Bool {
            switch self {
            case .v6Ed25519Sign, .v6X25519Encrypt, .v6MLKEM768Encrypt, .v6MLKEM1024Encrypt, .v6MLDSA65Sign, .v6Ed25519Auth,
                 .v6MLDSA87Sign, .v6RSA2048Sign, .v6RSA2048Encrypt, .v6RSA2048Auth,
                 .v6RSA4096Sign, .v6RSA4096Encrypt, .v6RSA4096Auth,
                 .v6Ed448Sign, .v6X448Encrypt: return true
            default: return false
            }
        }

        /// 8.3.0 (4.6): the V6KeyGenerator shape of a v6 type; nil for v4 types.
        var v6Kind: V6KeyGenerator.V6SubkeyKind? {
            switch self {
            case .v6Ed25519Sign: return .ed25519Sign
            case .v6X25519Encrypt: return .x25519Encrypt
            case .v6MLKEM768Encrypt: return .mlkem768Encrypt
            case .v6MLKEM1024Encrypt: return .mlkem1024Encrypt
            case .v6MLDSA65Sign: return .mldsa65Sign
            case .v6Ed25519Auth: return .ed25519Auth
            default: return nil
            }
        }

        var isPostQuantum: Bool {
            switch self {
            case .v6MLKEM768Encrypt, .v6MLKEM1024Encrypt, .v6MLDSA65Sign, .v4MLKEM768Encrypt, .v6MLDSA87Sign: return true
            default: return false
            }
        }

        var isSign: Bool {
            switch self {
            case .ed25519Sign, .rsa2048Sign, .rsa4096Sign, .v6Ed25519Sign, .v6MLDSA65Sign,
                 .v6MLDSA87Sign, .v6RSA2048Sign, .v6RSA4096Sign, .v6Ed448Sign: return true
            case .cv25519Encrypt, .rsa2048Encrypt, .rsa4096Encrypt, .v6X25519Encrypt, .v6X448Encrypt,
                 .ed25519Auth, .rsa2048Auth, .rsa4096Auth, .v6Ed25519Auth,
                 .v6MLKEM768Encrypt, .v6MLKEM1024Encrypt, .v4MLKEM768Encrypt,
                 .v6RSA2048Encrypt, .v6RSA2048Auth, .v6RSA4096Encrypt, .v6RSA4096Auth: return false
            }
        }

        var isAuthenticate: Bool {
            switch self {
            case .ed25519Auth, .rsa2048Auth, .rsa4096Auth, .v6Ed25519Auth, .v6RSA2048Auth, .v6RSA4096Auth: return true
            default: return false
            }
        }

        /// OpenPGP key-flags octet (subpacket 27): 0x02 = sign, 0x0C = encrypt
        /// (communications + storage), 0x20 = authenticate.
        var keyFlags: UInt8 { isAuthenticate ? 0x20 : (isSign ? 0x02 : 0x0C) }

        var capabilities: SubkeyCapabilitySet {
            isAuthenticate ? [.authenticate] : (isSign ? [.sign] : [.encrypt])
        }

        /// The KeyAlgorithm the rebuilt PGPSubkeyModel will carry (matching how
        /// KeyAlgorithm.from maps the packet's algorithm octet).
        var modelAlgorithm: KeyAlgorithm {
            switch self {
            case .ed25519Sign, .cv25519Encrypt, .ed25519Auth: return .ed25519
            case .rsa2048Sign, .rsa2048Encrypt, .rsa2048Auth,
                 .v6RSA2048Sign, .v6RSA2048Encrypt, .v6RSA2048Auth: return .rsa2048
            case .rsa4096Sign, .rsa4096Encrypt, .rsa4096Auth,
                 .v6RSA4096Sign, .v6RSA4096Encrypt, .v6RSA4096Auth: return .rsa4096
            case .v6Ed25519Sign, .v6Ed25519Auth: return .v6Ed25519
            case .v6X25519Encrypt: return .v6X25519
            case .v6MLKEM768Encrypt: return .v6MLKEM768
            case .v6MLKEM1024Encrypt: return .v6MLKEM1024
            case .v6MLDSA65Sign: return .v6MLDSA65
            case .v6MLDSA87Sign: return .v6MLDSA87
            case .v4MLKEM768Encrypt: return .v4MLKEM768
            case .v6Ed448Sign: return .v6Ed448
            case .v6X448Encrypt: return .v6X448
            }
        }

        var rsaBits: Int? {
            switch self {
            case .rsa2048Sign, .rsa2048Encrypt, .rsa2048Auth,
                 .v6RSA2048Sign, .v6RSA2048Encrypt, .v6RSA2048Auth: return 2048
            case .rsa4096Sign, .rsa4096Encrypt, .rsa4096Auth,
                 .v6RSA4096Sign, .v6RSA4096Encrypt, .v6RSA4096Auth: return 4096
            case .ed25519Sign, .cv25519Encrypt, .ed25519Auth, .v6Ed25519Sign, .v6X25519Encrypt,
                 .v6MLKEM768Encrypt, .v6MLKEM1024Encrypt, .v6MLDSA65Sign, .v4MLKEM768Encrypt, .v6Ed25519Auth,
                 .v6MLDSA87Sign, .v6Ed448Sign, .v6X448Encrypt: return nil
            }
        }
    }

    struct Result {
        let publicKeyData: Data
        let secretKeyData: Data
        let armoredPublicKey: String
        let subkeyFingerprintHex: String
        let capabilities: SubkeyCapabilitySet
    }

    enum SubkeyError: LocalizedError {
        case unsupportedPrimary
        case noPrimaryKeyPacket
        case keyGenerationFailed(String)
        case underlying(Error)

        var errorDescription: String? {
            switch self {
            case .unsupportedPrimary:
                return String(localized: "Adding a subkey requires a v4 Ed25519 or RSA software key. Newer key formats and hardware keys aren't supported for this yet.")
            case .noPrimaryKeyPacket:
                return String(localized: "Could not locate the primary key packet in this key.")
            case .keyGenerationFailed(let r):
                return r
            case .underlying(let e):
                return (e as? LocalizedError)?.errorDescription ?? e.localizedDescription
            }
        }
    }

    // MARK: - Entry point (blob based, so tests need no Keychain)

    /// Generate `type` and bind it as a new subkey of the key in
    /// (`publicKeyData`, `secretKeyData`). Returns the updated blobs and the
    /// new subkey's fingerprint. `passphrase` unlocks the primary to sign the
    /// binding and, when non-empty, also protects the new subkey's secret with
    /// the same S2K scheme the rest of the key uses.
    static func addSubkey(
        publicKeyData: Data,
        secretKeyData: Data,
        type: SubkeyType,
        expirationInterval: TimeInterval?,
        passphrase: String?
    ) throws -> Result {
        // 8.4.0 build 10 (plan 5m): a LibrePGP v5 Ed448 primary has its own path.
        if let v5Primary = try librePGPv5Ed448Primary(publicKeyData: publicKeyData) {
            return try addSubkeyUnderV5Ed448(primaryBody: v5Primary, publicKeyData: publicKeyData,
                                             secretKeyData: secretKeyData, type: type,
                                             expirationInterval: expirationInterval, passphrase: passphrase)
        }
        let (primaryBody, primaryPubAlgo) = try primaryPublicBody(publicKeyData: publicKeyData)

        // The primary signs the 0x18 binding. Build the signer from the
        // primary's secret, matching its algorithm: Ed25519 via CryptoKit, RSA
        // via the Security framework. Both extractors are blob-based and throw
        // passphraseRequired / invalidPassphrase, which the caller surfaces
        // unchanged.
        let primaryKeyID: [UInt8]
        let primarySign: (_ digest: [UInt8]) throws -> [[UInt8]]
        if primaryPubAlgo == 22 {
            let ed = try PGPService.shared.extractPrimaryCertificationKey(
                fromSecretKeyData: secretKeyData, passphrase: passphrase)
            primaryKeyID = Array(ed.fingerprint.suffix(8))
            primarySign = { digest in
                let sig = Array((try? ed.privateKey.signature(for: Data(digest))) ?? Data())
                guard sig.count == 64 else {
                    throw SubkeyError.keyGenerationFailed(String(localized: "Ed25519 primary signature failed"))
                }
                return [canonicalMPI(Array(sig[0..<32])), canonicalMPI(Array(sig[32..<64]))]
            }
        } else {
            let rsa = try PGPService.shared.extractPrimaryRSACertificationKey(
                fromSecretKeyData: secretKeyData, passphrase: passphrase)
            primaryKeyID = Array(rsa.fingerprint.suffix(8))
            primarySign = { digest in
                var err: Unmanaged<CFError>?
                guard let sig = SecKeyCreateSignature(
                    rsa.privateKey, .rsaSignatureDigestPKCS1v15SHA256, Data(digest) as CFData, &err) as Data? else {
                    let msg = (err?.takeRetainedValue()).map { CFErrorCopyDescription($0) as String } ?? String(localized: "RSA primary signature failed")
                    throw SubkeyError.keyGenerationFailed(msg)
                }
                return [canonicalMPI([UInt8](sig))]
            }
        }
        let creationTime = UInt32(Date().timeIntervalSince1970)

        // Build the new subkey's public body, secret body, and (for a sign
        // subkey) a signer closure that makes the 0x19 back-signature.
        let material = try generateSubkey(
            type: type, creationTime: creationTime,
            protectPassphrase: (passphrase?.isEmpty == false) ? passphrase : nil)

        let subkeyFingerprint = Ed25519KeyGenerator.calculateV4Fingerprint(keyBody: material.publicBody)
        let subkeyKeyID = Array(subkeyFingerprint.suffix(8))

        // Embedded 0x19 back-signature, present only for a sign-capable subkey.
        var embeddedBackSig: [UInt8]? = nil
        if type.isSign {
            embeddedBackSig = try buildBackSignature(
                primaryBody: primaryBody,
                subkeyBody: material.publicBody,
                creationTime: creationTime,
                subkeyKeyID: subkeyKeyID,
                pubAlgo: material.pubAlgo,
                sign: material.sign
            )
        }

        // 0x18 subkey binding, signed by the primary (Ed25519 or RSA).
        let binding = try buildBindingSignature(
            primaryPubAlgo: primaryPubAlgo,
            primarySign: primarySign,
            primaryBody: primaryBody,
            subkeyBody: material.publicBody,
            creationTime: creationTime,
            keyFlags: type.keyFlags,
            expirationInterval: expirationInterval,
            primaryKeyID: primaryKeyID,
            embeddedBackSignature: embeddedBackSig
        )

        // Append-only: the new subkey packet + its binding go at the end of
        // each ring; existing bytes are untouched.
        var newPublic = publicKeyData
        newPublic.append(buildPacket(tag: 14, body: material.publicBody))
        newPublic.append(buildPacket(tag: 2, body: binding))

        var newSecret = secretKeyData
        newSecret.append(buildPacket(tag: 7, body: material.secretBody))
        newSecret.append(buildPacket(tag: 2, body: binding))

        return Result(
            publicKeyData: newPublic,
            secretKeyData: newSecret,
            armoredPublicKey: armorPublicKeyBlock(Array(newPublic)),
            subkeyFingerprintHex: subkeyFingerprint.map { String(format: "%02x", $0) }.joined(),
            capabilities: type.capabilities
        )
    }

    // MARK: - Under a LibrePGP v5 Ed448 primary (8.4.0 build 10, plan 5m)

    /// The subkey types this file adds under a LibrePGP v5 Ed448 primary:
    /// the v4 Ed25519 and Curve25519 ones gpg 2.4.4 adds there.
    static let librePGPv5Types: [SubkeyType] = [.ed25519Sign, .cv25519Encrypt, .ed25519Auth]

    /// The public primary body when it is a LibrePGP v5 Ed448 key, else nil.
    private static func librePGPv5Ed448Primary(publicKeyData: Data) throws -> [UInt8]? {
        let packets = try OpenPGPPacketParser.parsePackets(data: Array(publicKeyData))
        guard let primary = packets.first(where: { $0.tag == 6 }), primary.body.first == 5,
              let c = OpenPGP448.component(keyBody: primary.body), c.curve == .ed448, c.algorithm == 22 else {
            return nil
        }
        return primary.body
    }

    /// Add a v4 Ed25519 or Curve25519 subkey under a LibrePGP v5 Ed448
    /// primary, the way gpg 2.4.4 does: a v5 0x18 binding by the primary
    /// (SHA-512, issuer fingerprint version 5, no issuer key ID), a signing
    /// subkey's v4 0x19 back-signature in its unhashed area.
    private static func addSubkeyUnderV5Ed448(
        primaryBody: [UInt8],
        publicKeyData: Data,
        secretKeyData: Data,
        type: SubkeyType,
        expirationInterval: TimeInterval?,
        passphrase: String?
    ) throws -> Result {
        guard librePGPv5Types.contains(type) else { throw SubkeyError.unsupportedPrimary }
        guard let primary = try OpenPGP448.v5PrimaryCertificationKey(
                secretRing: Array(secretKeyData), passphrase: passphrase),
              primary.fingerprint == CertificateValidator.fingerprint(ofKeyBody: primaryBody) else {
            throw SubkeyError.unsupportedPrimary
        }
        let creationTime = UInt32(Date().timeIntervalSince1970)
        let material = try generateSubkey(
            type: type, creationTime: creationTime,
            protectPassphrase: (passphrase?.isEmpty == false) ? passphrase : nil)
        let subkeyFingerprint = Ed25519KeyGenerator.calculateV4Fingerprint(keyBody: material.publicBody)

        var unhashed: [UInt8] = []
        if type.isSign {
            // subkeyHashData frames the primary by its own version (0x9A here).
            let back = try buildBackSignature(
                primaryBody: primaryBody,
                subkeyBody: material.publicBody,
                creationTime: creationTime,
                subkeyKeyID: Array(subkeyFingerprint.suffix(8)),
                pubAlgo: material.pubAlgo,
                sign: material.sign
            )
            unhashed += buildSubpacket(type: 32, data: back)
        }
        var hashed: [UInt8] = []
        hashed += buildSubpacket(type: 2, data: u32be(creationTime))
        if let interval = expirationInterval {
            hashed += buildSubpacket(type: 9, data: u32be(UInt32(interval)))
        }
        hashed += buildSubpacket(type: 27, data: [type.keyFlags])
        hashed += buildSubpacket(type: 33, data: [5] + primary.fingerprint)
        let document = OpenPGP448.frameForKeySignature(primaryBody, signatureVersion: 5)
            + OpenPGP448.frameForKeySignature(material.publicBody, signatureVersion: 5)
        let binding = try OpenPGP448.keySignatureBody(key: primary, signatureType: 0x18, document: document,
                                                      hashedSubpackets: hashed, unhashedSubpackets: unhashed)

        var newPublic = publicKeyData
        newPublic.append(buildPacket(tag: 14, body: material.publicBody))
        newPublic.append(buildPacket(tag: 2, body: binding))
        var newSecret = secretKeyData
        newSecret.append(buildPacket(tag: 7, body: material.secretBody))
        newSecret.append(buildPacket(tag: 2, body: binding))
        return Result(
            publicKeyData: newPublic,
            secretKeyData: newSecret,
            armoredPublicKey: armorPublicKeyBlock(Array(newPublic)),
            subkeyFingerprintHex: subkeyFingerprint.map { String(format: "%02x", $0) }.joined(),
            capabilities: type.capabilities
        )
    }

    // MARK: - Primary inspection

    /// The primary's public body plus its public-key algorithm octet. v4 only;
    /// the algorithm must be one this path can sign a binding with: EdDSA (22)
    /// or sign-capable RSA (1 or 3). Anything else (v6, DSA, RSA-encrypt-only)
    /// is refused.
    private static func primaryPublicBody(publicKeyData: Data) throws -> (body: [UInt8], pubAlgo: UInt8) {
        let packets = try OpenPGPPacketParser.parsePackets(data: Array(publicKeyData))
        guard let primary = packets.first(where: { $0.tag == 6 }) else {
            throw SubkeyError.noPrimaryKeyPacket
        }
        guard primary.body.count > 5, primary.body[0] == 4 else {
            throw SubkeyError.unsupportedPrimary
        }
        let algo = primary.body[5]
        guard algo == 22 || algo == 1 || algo == 3 else {
            throw SubkeyError.unsupportedPrimary
        }
        return (primary.body, algo)
    }

    // MARK: - Subkey material

    private struct SubkeyMaterial {
        let publicBody: [UInt8]
        let secretBody: [UInt8]
        let pubAlgo: UInt8
        /// Signs a SHA-256 digest with the SUBKEY's own private key (used for
        /// the 0x19 back-signature). Returns the OpenPGP signature MPIs.
        let sign: (_ digest: [UInt8]) throws -> [[UInt8]]
    }

    private static func generateSubkey(
        type: SubkeyType,
        creationTime: UInt32,
        protectPassphrase: String?
    ) throws -> SubkeyMaterial {
        switch type {
        case .ed25519Sign, .ed25519Auth:
            let key = Curve25519.Signing.PrivateKey()
            let pub = Array(key.publicKey.rawRepresentation)
            let priv = Array(key.rawRepresentation)
            let pubBody = Ed25519KeyGenerator.buildEdDSAPublicKeyBody(creationTime: creationTime, publicKey: pub)
            let secBody = singleMPISecretBody(publicBody: pubBody, scalar: priv, passphrase: protectPassphrase)
            return SubkeyMaterial(publicBody: pubBody, secretBody: secBody, pubAlgo: 22, sign: { digest in
                let sig = Array(try key.signature(for: Data(digest)))
                return [canonicalMPI(Array(sig[0..<32])), canonicalMPI(Array(sig[32..<64]))]
            })

        case .cv25519Encrypt:
            let key = Curve25519.KeyAgreement.PrivateKey()
            let pub = Array(key.publicKey.rawRepresentation)
            // Match buildECDHSecretKeyBody: store the clamped big-endian scalar.
            let wire = Ed25519KeyGenerator.canonicalCv25519WireScalar(Array(key.rawRepresentation))
            let pubBody = Ed25519KeyGenerator.buildECDHPublicKeyBody(creationTime: creationTime, publicKey: pub)
            let secBody = singleMPISecretBody(publicBody: pubBody, scalar: wire, passphrase: protectPassphrase)
            // An encryption subkey never signs, so sign is never called.
            return SubkeyMaterial(publicBody: pubBody, secretBody: secBody, pubAlgo: 18, sign: { _ in [] })

        case .rsa2048Sign, .rsa2048Encrypt, .rsa4096Sign, .rsa4096Encrypt, .rsa2048Auth, .rsa4096Auth:
            guard let bits = type.rsaBits else { throw SubkeyError.keyGenerationFailed(String(localized: "Missing RSA size")) }
            let (secKey, comp) = try generateRSA(bits: bits)
            let pubBody = rsaPublicBody(creationTime: creationTime, n: comp.n, e: comp.e)
            let secBody = rsaSecretBody(publicBody: pubBody, d: comp.d, p: comp.p, q: comp.q, u: comp.u,
                                        passphrase: protectPassphrase)
            return SubkeyMaterial(publicBody: pubBody, secretBody: secBody, pubAlgo: 1, sign: { digest in
                var err: Unmanaged<CFError>?
                guard let sig = SecKeyCreateSignature(
                    secKey, .rsaSignatureDigestPKCS1v15SHA256, Data(digest) as CFData, &err) as Data? else {
                    let msg = (err?.takeRetainedValue()).map { CFErrorCopyDescription($0) as String } ?? String(localized: "RSA sign failed")
                    throw SubkeyError.keyGenerationFailed(msg)
                }
                return [canonicalMPI([UInt8](sig))]
            })
        case .v4MLKEM768Encrypt:
            // 8.3.0 (4.6 / 4.3): the RFC 9980 algorithm 35 subkey on a v4 key,
            // the same material Ed25519KeyGenerator grafts for the interop
            // shape. Its fingerprint is v4 SHA-1 like any other v4 subkey; the
            // v4 0x18 binding below covers it with 0x99 framing.
            let xKey = Curve25519.KeyAgreement.PrivateKey()
            let mlkemSeed = SecureRandom.bytesOrTrap(64)
            let (mlkemPub, _) = try MLKEMService.generateKeyPair(seed: Data(mlkemSeed), level: .mlkem768)
            let pubBody = Ed25519KeyGenerator.buildV4MLKEMPublicKeyBody(
                creationTime: creationTime,
                x25519Public: Array(xKey.publicKey.rawRepresentation),
                mlkemPublic: Array(mlkemPub))
            let secBody = Ed25519KeyGenerator.buildV4MLKEMSecretKeyBody(
                publicBody: pubBody,
                x25519Private: Array(xKey.rawRepresentation),
                mlkemSeed: mlkemSeed,
                passphrase: protectPassphrase)
            return SubkeyMaterial(publicBody: pubBody, secretBody: secBody, pubAlgo: 35, sign: { _ in [] })
        case .v6Ed25519Sign, .v6X25519Encrypt, .v6MLKEM768Encrypt, .v6MLKEM1024Encrypt, .v6MLDSA65Sign, .v6Ed25519Auth,
             .v6MLDSA87Sign, .v6RSA2048Sign, .v6RSA2048Encrypt, .v6RSA2048Auth,
             .v6RSA4096Sign, .v6RSA4096Encrypt, .v6RSA4096Auth, .v6Ed448Sign, .v6X448Encrypt:
            // v6 subkeys are generated by V6KeyGenerator (v6 packet + salted
            // binding). performAddSubkey routes them there, so this v4 path is
            // never called for them; the case exists only for switch exhaustiveness.
            throw SubkeyError.keyGenerationFailed(String(localized: "v6 subkeys are built by V6KeyGenerator, not the classical path"))
        }
    }

    /// 8.4.0 build 9 (plan 5l, Android 4.6.0 item 21): a fresh RSA key as
    /// OpenPGP key material for a v6 subkey: the public MPIs (n, e), the
    /// secret MPIs (d, p, q, u, with p < q as RFC 9580 orders them) and the
    /// private SecKey that makes a signing subkey's back-signature.
    static func rsaKeyMaterial(bits: Int) throws -> (privateKey: SecKey, publicMPIs: [UInt8], secretMPIs: [UInt8]) {
        let (key, c) = try generateRSA(bits: bits)
        return (key,
                canonicalMPI(c.n) + canonicalMPI(c.e),
                canonicalMPI(c.d) + canonicalMPI(c.p) + canonicalMPI(c.q) + canonicalMPI(c.u))
    }

    /// Secret body for a single-MPI (Ed25519 / Cv25519) subkey. Mirrors
    /// Ed25519KeyGenerator's buildEdDSA/ECDH secret bodies exactly: unprotected
    /// is usage-0 + canonicalMPI + two-octet checksum; protected reuses the
    /// generator's own S2K writer.
    private static func singleMPISecretBody(publicBody: [UInt8], scalar: [UInt8], passphrase: String?) -> [UInt8] {
        var body = publicBody
        if let passphrase, !passphrase.isEmpty {
            body.append(contentsOf: Ed25519KeyGenerator.buildS2KProtectedSecretMPI(
                privateKey: scalar, passphrase: passphrase))
        } else {
            body.append(0)
            let mpi = canonicalMPI(scalar)
            body.append(contentsOf: mpi)
            body.append(contentsOf: checksum(mpi))
        }
        return body
    }

    // MARK: - RSA

    private struct RSAComponents {
        let n: [UInt8]; let e: [UInt8]; let d: [UInt8]
        let p: [UInt8]; let q: [UInt8]; let u: [UInt8]   // OpenPGP: p<q, u = p^-1 mod q
    }

    /// Generate an RSA keypair and map its PKCS#1 external representation to
    /// OpenPGP's (n,e,d,p,q,u). No big-integer math: the Security framework's
    /// RSAPrivateKey gives (n,e,d,prime1,prime2,coefficient) where, by the
    /// PKCS#1 convention corecrypto follows, prime1 > prime2 and
    /// coefficient = prime2^-1 mod prime1. OpenPGP wants the smaller prime as p
    /// and u = p^-1 mod q, so p = prime2, q = prime1, u = coefficient falls out
    /// directly. The prime1 > prime2 assumption is enforced by a regenerate
    /// guard rather than assumed.
    private static func generateRSA(bits: Int) throws -> (SecKey, RSAComponents) {
        for _ in 0..<4 {
            let attrs: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits as String: bits
            ]
            var err: Unmanaged<CFError>?
            guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
                let msg = (err?.takeRetainedValue()).map { CFErrorCopyDescription($0) as String } ?? String(localized: "RSA key generation failed")
                throw SubkeyError.keyGenerationFailed(msg)
            }
            guard let der = SecKeyCopyExternalRepresentation(key, &err) as Data? else {
                let msg = (err?.takeRetainedValue()).map { CFErrorCopyDescription($0) as String } ?? String(localized: "RSA key export failed")
                throw SubkeyError.keyGenerationFailed(msg)
            }
            guard let ints = parseRSAPrivateKeyDER([UInt8](der)), ints.count >= 9 else {
                throw SubkeyError.keyGenerationFailed(String(localized: "Unexpected RSA key format"))
            }
            // RSAPrivateKey ::= { version, n, e, d, prime1, prime2, exp1, exp2, coefficient }
            let n = strip(ints[1]), e = strip(ints[2]), d = strip(ints[3])
            let prime1 = strip(ints[4]), prime2 = strip(ints[5]), coeff = strip(ints[8])
            guard magnitudeGreater(prime1, prime2) else { continue }   // need prime1 > prime2
            return (key, RSAComponents(n: n, e: e, d: d, p: prime2, q: prime1, u: coeff))
        }
        throw SubkeyError.keyGenerationFailed(String(localized: "RSA key generation did not converge on p<q ordering"))
    }

    private static func rsaPublicBody(creationTime: UInt32, n: [UInt8], e: [UInt8]) -> [UInt8] {
        var body: [UInt8] = [4]
        body.append(contentsOf: u32be(creationTime))
        body.append(1)   // algorithm 1 = RSA (Encrypt or Sign); capability set via key flags
        body.append(contentsOf: canonicalMPI(n))
        body.append(contentsOf: canonicalMPI(e))
        return body
    }

    /// RSA secret body: after the public body, either usage-0 + the four secret
    /// MPIs + two-octet checksum, or usage-254 S2K-CFB over (MPIs ‖ SHA-1).
    /// Byte layout is the exact inverse of PGPService.parseRSASecretPacket.
    private static func rsaSecretBody(publicBody: [UInt8], d: [UInt8], p: [UInt8], q: [UInt8], u: [UInt8],
                                      passphrase: String?) -> [UInt8] {
        var region: [UInt8] = []
        region += canonicalMPI(d); region += canonicalMPI(p)
        region += canonicalMPI(q); region += canonicalMPI(u)

        var body = publicBody
        guard let passphrase, !passphrase.isEmpty else {
            body.append(0)
            body.append(contentsOf: region)
            body.append(contentsOf: checksum(region))
            return body
        }
        // usage 254: AES-128, Iterated+Salted S2K (SHA-256), SHA-1 checksum,
        // the same scheme Ed25519KeyGenerator writes for a protected primary,
        // reusing its vetted key derivation and CFB so the bytes round-trip
        // through gpg and PGPony's own RSA parser.
        let salt = randomBytes(8)
        let iv = randomBytes(16)
        let key = Ed25519KeyGenerator.deriveS2KKey(passphrase: passphrase, salt: salt, codedCount: 0xFF, keySize: 16)
        var plaintext = region
        var sha1 = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CC_SHA1(region, CC_LONG(region.count), &sha1)
        plaintext.append(contentsOf: sha1)
        let ciphertext = Ed25519KeyGenerator.aesCFBEncrypt(plaintext: plaintext, key: key, iv: iv)

        body.append(254)   // S2K usage: SHA-1 checksum
        body.append(7)     // AES-128
        body.append(3)     // Iterated+Salted
        body.append(8)     // SHA-256
        body.append(contentsOf: salt)
        body.append(0xFF)  // coded count -> 65,011,712
        body.append(contentsOf: iv)
        body.append(contentsOf: ciphertext)
        return body
    }

    // MARK: - Signatures

    /// The 0x18 subkey binding, signed by the primary over
    /// (0x99‖primary) ‖ (0x99‖subkey) ‖ v4 trailer. The signer is supplied as a
    /// closure so the same assembly serves an Ed25519 primary (two 32-byte
    /// MPIs) and an RSA primary (one MPI); `primaryPubAlgo` is written into the
    /// signature and its trailer so the digest gpg recomputes matches.
    private static func buildBindingSignature(
        primaryPubAlgo: UInt8,
        primarySign: (_ digest: [UInt8]) throws -> [[UInt8]],
        primaryBody: [UInt8],
        subkeyBody: [UInt8],
        creationTime: UInt32,
        keyFlags: UInt8,
        expirationInterval: TimeInterval?,
        primaryKeyID: [UInt8],
        embeddedBackSignature: [UInt8]?
    ) throws -> [UInt8] {
        var hashed: [UInt8] = []
        hashed += buildSubpacket(type: 2, data: u32be(creationTime))
        if let interval = expirationInterval {
            hashed += buildSubpacket(type: 9, data: u32be(UInt32(interval)))
        }
        hashed += buildSubpacket(type: 27, data: [keyFlags])

        var unhashed: [UInt8] = []
        unhashed += buildSubpacket(type: 16, data: primaryKeyID)
        // Embedded Signature (type 32): the 0x19 back-sig for a signing
        // subkey. Placed in the unhashed area, matching what gpg 2.x writes
        // for a v4 subkey binding.
        if let back = embeddedBackSignature {
            unhashed += buildSubpacket(type: 32, data: back)
        }

        let hashData = subkeyHashData(primaryBody: primaryBody, subkeyBody: subkeyBody,
                                      sigType: 0x18, pubAlgo: primaryPubAlgo, hashedSubpackets: hashed)
        let digest = Array(SHA256.hash(data: Data(hashData)))
        let mpis = try primarySign(digest)

        return assembleSignature(sigType: 0x18, pubAlgo: primaryPubAlgo, hashed: hashed, unhashed: unhashed,
                                 digest: digest, sigMPIs: mpis)
    }

    /// The 0x19 primary-key-binding back-signature, signed BY the subkey over
    /// the same (primary ‖ subkey) content as the 0x18.
    private static func buildBackSignature(
        primaryBody: [UInt8],
        subkeyBody: [UInt8],
        creationTime: UInt32,
        subkeyKeyID: [UInt8],
        pubAlgo: UInt8,
        sign: (_ digest: [UInt8]) throws -> [[UInt8]]
    ) throws -> [UInt8] {
        var hashed: [UInt8] = []
        hashed += buildSubpacket(type: 2, data: u32be(creationTime))
        var unhashed: [UInt8] = []
        unhashed += buildSubpacket(type: 16, data: subkeyKeyID)

        let hashData = subkeyHashData(primaryBody: primaryBody, subkeyBody: subkeyBody,
                                      sigType: 0x19, pubAlgo: pubAlgo, hashedSubpackets: hashed)
        let digest = Array(SHA256.hash(data: Data(hashData)))
        let mpis = try sign(digest)
        return assembleSignature(sigType: 0x19, pubAlgo: pubAlgo, hashed: hashed, unhashed: unhashed,
                                 digest: digest, sigMPIs: mpis)
    }

    /// The signed content for a subkey binding / back-signature (RFC 4880
    /// §5.2.4): 0x99‖len2‖primary, then 0x99‖len2‖subkey, then the v4 trailer.
    /// 8.4.0 build 10 (plan 5m): the primary is framed by its own version, so
    /// a LibrePGP v5 primary enters as 0x9A | len4 (what gpg hashes for the
    /// v4 back-signature of a subkey under it); a v4 primary is unchanged.
    private static func subkeyHashData(primaryBody: [UInt8], subkeyBody: [UInt8],
                                       sigType: UInt8, pubAlgo: UInt8, hashedSubpackets: [UInt8]) -> [UInt8] {
        var data: [UInt8] = OpenPGP448.frameForKeySignature(primaryBody, signatureVersion: 4)
        data += [0x99]
        data += u16be(UInt16(subkeyBody.count)); data += subkeyBody
        data += signatureTrailer(sigType: sigType, pubAlgo: pubAlgo, hashedSubpackets: hashedSubpackets)
        return data
    }

    private static func signatureTrailer(sigType: UInt8, pubAlgo: UInt8, hashedSubpackets: [UInt8]) -> [UInt8] {
        var t: [UInt8] = [4, sigType, pubAlgo, 8]   // v4, type, pubAlgo, SHA-256
        t += u16be(UInt16(hashedSubpackets.count))
        t += hashedSubpackets
        t += [4, 0xFF]
        t += u32be(UInt32(6 + hashedSubpackets.count))
        return t
    }

    private static func assembleSignature(sigType: UInt8, pubAlgo: UInt8, hashed: [UInt8], unhashed: [UInt8],
                                          digest: [UInt8], sigMPIs: [[UInt8]]) -> [UInt8] {
        var body: [UInt8] = [4, sigType, pubAlgo, 8]
        body += u16be(UInt16(hashed.count)); body += hashed
        body += u16be(UInt16(unhashed.count)); body += unhashed
        body.append(digest[0]); body.append(digest[1])
        for mpi in sigMPIs { body += mpi }
        return body
    }

    // MARK: - Encoders / helpers

    /// Canonical OpenPGP MPI: strip leading zero octets, declare the exact bit
    /// length. Delegates to the generator's implementation so there is one
    /// source of truth for the encoding this whole class depends on.
    private static func canonicalMPI(_ bytes: [UInt8]) -> [UInt8] {
        Ed25519KeyGenerator.canonicalMPI(bytes)
    }

    private static func checksum(_ mpiBytes: [UInt8]) -> [UInt8] {
        let sum = mpiBytes.reduce(UInt16(0)) { $0 &+ UInt16($1) }
        return u16be(sum)
    }

    private static func buildPacket(tag: UInt8, body: [UInt8]) -> Data {
        var out = Data([0xC0 | (tag & 0x3F)])
        let n = body.count
        if n < 192 {
            out.append(UInt8(n))
        } else if n < 8384 {
            let adj = n - 192
            out.append(UInt8((adj >> 8) + 192)); out.append(UInt8(adj & 0xFF))
        } else {
            out.append(0xFF)
            out.append(UInt8((n >> 24) & 0xFF)); out.append(UInt8((n >> 16) & 0xFF))
            out.append(UInt8((n >> 8) & 0xFF));  out.append(UInt8(n & 0xFF))
        }
        out.append(contentsOf: body)
        return out
    }

    private static func buildSubpacket(type: UInt8, data: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        let total = data.count + 1
        if total < 192 {
            out.append(UInt8(total))
        } else if total < 16576 {
            let adj = total - 192
            out.append(UInt8((adj >> 8) + 192)); out.append(UInt8(adj & 0xFF))
        } else {
            out.append(0xFF)
            out.append(UInt8((total >> 24) & 0xFF)); out.append(UInt8((total >> 16) & 0xFF))
            out.append(UInt8((total >> 8) & 0xFF));  out.append(UInt8(total & 0xFF))
        }
        out.append(type)
        out.append(contentsOf: data)
        return out
    }

    /// Minimal DER reader for a PKCS#1 RSAPrivateKey: one SEQUENCE of INTEGERs.
    /// Returns each INTEGER's raw content octets (leading 0x00 sign byte, if
    /// any, still attached; callers strip).
    private static func parseRSAPrivateKeyDER(_ der: [UInt8]) -> [[UInt8]]? {
        var i = 0
        guard i < der.count, der[i] == 0x30 else { return nil }   // SEQUENCE
        i += 1
        guard let (seqLen, seqHdr) = readDERLength(der, i) else { return nil }
        i += seqHdr
        let end = min(der.count, i + seqLen)
        var ints: [[UInt8]] = []
        while i < end {
            guard der[i] == 0x02 else { return nil }              // INTEGER
            i += 1
            guard let (len, hdr) = readDERLength(der, i) else { return nil }
            i += hdr
            guard i + len <= der.count else { return nil }
            ints.append(Array(der[i..<(i + len)]))
            i += len
        }
        return ints
    }

    /// Read a DER length at `off`; returns (length, number-of-length-octets).
    private static func readDERLength(_ der: [UInt8], _ off: Int) -> (Int, Int)? {
        guard off < der.count else { return nil }
        let first = der[off]
        if first < 0x80 { return (Int(first), 1) }
        let count = Int(first & 0x7F)
        guard count >= 1, count <= 4, off + count < der.count else { return nil }
        var len = 0
        for k in 1...count { len = (len << 8) | Int(der[off + k]) }
        return (len, 1 + count)
    }

    private static func strip(_ bytes: [UInt8]) -> [UInt8] {
        var v = bytes
        while v.count > 1 && v.first == 0 { v.removeFirst() }
        return v
    }

    /// True when big-endian magnitude a > b (leading zeros already possible).
    private static func magnitudeGreater(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        let x = strip(a), y = strip(b)
        if x.count != y.count { return x.count > y.count }
        for (i, xb) in x.enumerated() {
            if xb != y[i] { return xb > y[i] }
        }
        return false   // equal
    }

    /// 8.3.0 (hardening): a random buffer or a trap, never zeros.
    private static func randomBytes(_ n: Int) -> [UInt8] {
        SecureRandom.bytesOrTrap(n)
    }

    private static func u16be(_ v: UInt16) -> [UInt8] { [UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)] }
    private static func u32be(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }

    private static func armorPublicKeyBlock(_ data: [UInt8]) -> String {
        let b64 = Data(data).base64EncodedString(options: .lineLength76Characters)
        let crc = Data(crc24(data)).base64EncodedString()
        return "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\(b64)\n=\(crc)\n-----END PGP PUBLIC KEY BLOCK-----\n"
    }

    private static func crc24(_ data: [UInt8]) -> [UInt8] {
        var crc: UInt32 = 0xB704CE
        for b in data {
            crc ^= UInt32(b) << 16
            for _ in 0..<8 {
                crc <<= 1
                if (crc & 0x1000000) != 0 { crc ^= 0x1864CFB }
            }
        }
        crc &= 0xFFFFFF
        return [UInt8((crc >> 16) & 0xFF), UInt8((crc >> 8) & 0xFF), UInt8(crc & 0xFF)]
    }
}
