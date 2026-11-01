// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// KeyExpirationEditor.swift
// PGPony
//
// v6.0 — Phase 7: software key-expiration editing (Feature 1).
//
// WHAT THIS DOES
// Re-dates a key's expiration by SUPERSEDING its self-signatures, exactly the
// way `gpg --edit-key … expire` does. It does NOT mutate the existing self-cert
// or binding in place — it generates a FRESH primary user-ID self-certification
// (sig type 0x13) over each user ID and a FRESH subkey-binding signature (sig
// type 0x18) over each encryption subkey, each carrying a current creation
// timestamp and the new Key Expiration Time, then splices those fresh signatures
// in where the old ones sat. Editing expiration never changes the fingerprint:
// the fingerprint is computed over the key packet body, which we leave untouched.
//
// NAME NOTE: this is deliberately NOT "KeyExpirationService" — that name is
// already taken by the notification scheduler. After a successful edit the caller
// (Phase 7c UI) should persist the result and then ask the existing scheduler to
// refresh its reminders against the new expiresAt.
//
// SCOPE (this core): v4 Ed25519 primary + Cv25519 encryption subkey only — the
// same scope `generateKeyRevocation` shipped with. RSA self-sigs go through
// ObjectivePGP and v6 hasn't cleared the Sequoia interop wall, so both are
// deferred to a later pass, consistent with how revocation was staged.
//
// KEY EXPIRATION TIME IS RELATIVE (RFC 4880 §5.2.3.6). The subpacket value is the
// number of seconds AFTER that key's own creation time — and the primary and the
// subkey have different creation times, so the relative value is computed PER KEY
// from the same absolute target date. "Never" means the subpacket is omitted.
//
// CAPABILITIES ARE PRESERVED. We copy every capability subpacket forward from the
// existing self-signature (key flags 27, preferred sym/hash/compression 11/21/22,
// features 30, key-server prefs 23, primary-UID 25, etc.), preserving each one's
// critical bit, and only swap in a fresh creation time (2), the new expiration (9),
// and a fresh issuer fingerprint (33). That way nothing about how the key is
// allowed to be used changes — only when it expires.
//
// VERIFICATION RECIPE (run on the armoredPublicKey this returns):
//   gpg --no-default-keyring --keyring /tmp/x.gpg --import edited-public.asc
//   gpg --no-default-keyring --keyring /tmp/x.gpg --check-sigs <FPR>
//   gpg --no-default-keyring --keyring /tmp/x.gpg --list-keys --with-colons <FPR> | grep -E '^(pub|sub):'
//   rm /tmp/x.gpg
// Field 7 of the pub/sub colon rows is the expiry Unix timestamp (empty = never).
// Target: good self-sigs (sig!), capabilities intact, fingerprint unchanged.

import Foundation
import CryptoKit

enum KeyExpirationEditor {

    // MARK: - Result

    /// The product of an expiration edit. Pure data — no persistence performed.
    /// Phase 7c is responsible for writing `secretKeyData` to the Keychain (id
    /// `pgpony_key_<fingerprint>_private`), assigning `armoredPublicKey` back onto
    /// the model, setting `model.expiresAt = expiresAt`, then refreshing the
    /// notification scheduler.
    struct EditedKey {
        let secretKeyData: Data       // new secret keyring bytes (raw packets, unarmored)
        let armoredPublicKey: String  // new public keyring, ASCII-armored, header-free
        let expiresAt: Date?          // absolute expiry to stamp on the model (nil = never)
    }

    enum EditError: LocalizedError {
        case notAKeyPair
        case unsupportedAlgorithm
        case missingArmoredPublicKey
        case noPrimaryKeyPacket
        case expiryBeforeCreation
        case noLiveUserID
        // 8.4.0 build 11 (plan 5n, Android 4.7.0 item 53): one subkey's expiry.
        case subkeyNotFound
        case subkeyRevoked
        case noSubkeyBinding
        case signingSubkeyNotHere
        case cardSigningSubkey
        case underlying(Error)

        var errorDescription: String? {
            switch self {
            case .notAKeyPair:
                return String(localized: "Editing expiration requires the private key; this is a public-only key.")
            case .unsupportedAlgorithm:
                return String(localized: "Expiration editing supports Ed25519 keys and RSA or Ed25519 hardware keys. For a software RSA or v6 key, use GnuPG.")
            case .missingArmoredPublicKey:
                return String(localized: "The cached public key is missing, so the key material needed for re-signing can't be read.")
            case .noPrimaryKeyPacket:
                return String(localized: "Could not locate the primary public-key packet in this key.")
            case .expiryBeforeCreation:
                return String(localized: "The chosen expiration date is before the key was created.")
            case .noLiveUserID:
                return String(localized: "Every User ID on this key is revoked, so there is no identity to carry a new expiration date.")
            case .subkeyNotFound:
                return String(localized: "That subkey is not on this key.")
            case .subkeyRevoked:
                return String(localized: "This subkey is revoked, so its expiration can't be changed.")
            case .noSubkeyBinding:
                return String(localized: "This subkey has no binding signature from the primary key that could be checked, so nothing was changed.")
            case .signingSubkeyNotHere:
                return String(localized: "This signing subkey's secret is not on this device. A signing subkey signs its new binding too, so its expiration can't be changed here.")
            case .cardSigningSubkey:
                return String(localized: "A signing subkey's expiration can't be changed with the hardware key.")
            case .underlying(let e):
                return e.localizedDescription
            }
        }
    }

    // MARK: - Entry point (pure crypto, no side effects)

    /// Build a re-dated copy of a v4 Ed25519 key's material.
    ///
    /// CORE SEAM: in the app, a thin wrapper feeds this from the SwiftData model
    /// (`PGPService.extractEd25519SigningKey` for the signing material, plus the
    /// Keychain-loaded secret ring), and routes v6 keys to `buildEditedV6Key`
    /// off the model's algorithm. The core takes the extracted materials
    /// directly, so it performs no storage access of its own.
    ///
    /// - Parameters:
    ///   - armoredPublic: the key's ASCII-armored public keyring.
    ///   - signingInfo: the extracted Ed25519 signing key (see `Ed25519SigningInfo`).
    ///   - secretRing: raw secret keyring bytes to re-splice, or nil to skip.
    ///   - expiresAt: the new absolute expiry, or nil for "never".
    ///   - passphrase: the secret ring's passphrase. Needed only when
    ///     `subkeyFingerprint` names a signing subkey, whose new binding
    ///     carries a back-signature made with that subkey's own secret.
    ///   - includeCurrentSubkeys: re-sign the bindings of the subkeys that are
    ///     still valid now. Expired and revoked subkeys keep their old binding.
    ///   - subkeyFingerprint: 8.4.0: set to change that one subkey's expiry and
    ///     nothing else (the primary, its User IDs and the other subkeys keep
    ///     their signatures byte for byte). `expiresAt` is then the subkey's
    ///     new date, and so is the result's `expiresAt`; the key's own expiry
    ///     does not change. An expired subkey can be given a new date.
    /// - Returns: fresh secret keyring bytes + armored public key + the expiry.
    static func buildEditedKey(
        armoredPublic: String,
        signingInfo: Ed25519SigningInfo,
        secretRing: Data?,
        expiresAt: Date?,
        passphrase: String? = nil,
        includeCurrentSubkeys: Bool = true,
        subkeyFingerprint: String? = nil
    ) async throws -> EditedKey {
        let primaryFP20 = signingInfo.fingerprint.count >= 20
            ? Array(signingInfo.fingerprint.suffix(20))
            : signingInfo.fingerprint

        // 8.4.0 build 11 (plan 5n): a signing subkey's back-signature is made
        // with its own secret, read from the same secret ring.
        let target = subkeyFingerprint.map {
            SubkeyTarget(fingerprintHex: $0, secretRing: secretRing, passphrase: passphrase)
        }

        return try await buildEditedKeyCore(
            armoredPublic: armoredPublic,
            expiresAt: expiresAt,
            primaryFP20: primaryFP20,
            issuerKeyID: signingInfo.keyID,
            secretRing: secretRing,
            algorithm: .eddsa,
            includeCurrentSubkeys: includeCurrentSubkeys,
            subkeyTarget: target,
            sign: { digest in Array(try signingInfo.privateKey.signature(for: Data(digest))) }
        )
    }

    /// v8.2.0 issue #4 — software expiration edit for a v6 key. Extracts the
    /// primary certification key (signs the direct-key sig and each binding) and
    /// the signing subkey (signs its own 0x19 back-signature), then re-dates the
    /// whole ring via V6KeyGenerator's v6 signature builders. The primary is
    /// extracted first so a wrong passphrase surfaces here; the signing subkey is
    /// optional (an encryption-only v6 key has none).
    ///
    /// CORE SEAM: in the app this takes the SwiftData model and extracts the two
    /// signing keys itself (`PGPService.extractEd25519SigningKey`, once with
    /// `preferSigningSubkey: false` and once with `true`, off the main thread)
    /// plus the Keychain secret ring; the core takes the already-extracted
    /// materials. `signingSubkey` is nil for an encryption-only v6 key (no
    /// Sign-capable subkey). `passphrase` is needed only for a one-subkey edit
    /// (`subkeyFingerprint`) of a signing subkey.
    static func buildEditedV6Key(
        armoredPublic: String,
        secretRing: Data,
        primary: Ed25519SigningInfo,
        signingSubkey: Ed25519SigningInfo?,
        expiresAt: Date?,
        passphrase: String? = nil,
        includeCurrentSubkeys: Bool = true,
        subkeyFingerprint: String? = nil
    ) async throws -> EditedKey {
        let pubData = Data(try dearmor(armoredPublic))
        // 8.4.0: one subkey's binding and nothing else.
        if let subkeyFingerprint {
            let result = try await editV6SubkeyExpiration(
                publicKeyData: pubData,
                secretKeyData: secretRing,
                primarySigner: V6SignatureKey(primary),
                primaryFingerprint: Array(primary.fingerprint.suffix(32)),
                subkeyFingerprintHex: subkeyFingerprint,
                expiresAt: expiresAt,
                passphrase: passphrase
            )
            return EditedKey(
                secretKeyData: result.secretKeyData,
                armoredPublicKey: armorPublicKeyBlock(Array(result.publicKeyData)),
                expiresAt: expiresAt
            )
        }
        let signSub = signingSubkey

        do {
            let result = try V6KeyGenerator.editV6Expiration(
                publicKeyData: pubData,
                secretKeyData: secretRing,
                primarySigner: V6SignatureKey(primary),
                primaryFingerprint: Array(primary.fingerprint.suffix(32)),
                signingSubkey: signSub?.privateKey,
                signingSubkeyFingerprint: signSub.map { Array($0.fingerprint.suffix(32)) },
                expiresAt: expiresAt,
                includeCurrentSubkeys: includeCurrentSubkeys
            )
            return EditedKey(
                secretKeyData: result.secretKeyData,
                armoredPublicKey: armorPublicKeyBlock(Array(result.publicKeyData)),
                expiresAt: expiresAt
            )
        } catch {
            throw EditError.underlying(error)
        }
    }

    /// 8.4.0: Change Expiration for a key pair whose primary is Ed448
    /// (LibrePGP v5 or RFC 9580 v6), through Ed448KeyEditor off the main
    /// thread. Passphrase errors surface the way the other paths wrap them.
    ///
    /// CORE SEAM: in the app this takes the SwiftData model and loads the
    /// secret ring from the Keychain; the core takes the armored public
    /// keyring and the secret ring.
    static func buildEditedEd448Key(
        armoredPublic: String,
        secretRing: Data,
        expiresAt: Date?,
        passphrase: String?,
        includeCurrentSubkeys: Bool = true,
        subkeyFingerprint: String? = nil
    ) async throws -> EditedKey {
        let pubData = Data(try dearmor(armoredPublic))
        let secretData = secretRing
        // 8.4.0 build 11 (plan 5n): one subkey's binding and nothing else.
        if let subkeyFingerprint {
            let result = try await runOffMainThread {
                try editEd448SubkeyExpiration(publicKeyData: pubData, secretKeyData: secretData, passphrase: passphrase,
                                              subkeyFingerprintHex: subkeyFingerprint, expiresAt: expiresAt)
            }
            return EditedKey(
                secretKeyData: result.secretKeyData,
                armoredPublicKey: armorPublicKeyBlock(Array(result.publicKeyData)),
                expiresAt: expiresAt
            )
        }
        do {
            let result = try await runOffMainThread {
                try Ed448KeyEditor.resign(publicKeyData: pubData, secretKeyData: secretData, passphrase: passphrase,
                                          expiry: .set(expiresAt), includeCurrentSubkeys: includeCurrentSubkeys)
            }
            return EditedKey(
                secretKeyData: result.secretKeyData,
                armoredPublicKey: armorPublicKeyBlock(Array(result.publicKeyData)),
                expiresAt: expiresAt
            )
        } catch let e as Ed448KeyEditor.EditError {
            switch e {
            case .expiryBeforeCreation: throw EditError.expiryBeforeCreation
            case .noLiveUserID: throw EditError.noLiveUserID
            case .noPrimaryKeyPacket: throw EditError.noPrimaryKeyPacket
            default: throw EditError.underlying(e)
            }
        } catch {
            throw EditError.underlying(error)
        }
    }

    /// Card-backed expiration edit. Re-signs the user-ID self-cert and each subkey
    /// binding on the card (PSO:CDS) under the already-open `service` session. PW1
    /// is re-verified before each signature, so it works on cards whose PW1 is valid
    /// for a single CDS. A card key has no local secret, so only the public ring is
    /// rebuilt and `secretKeyData` comes back empty.
    /// CORE SEAM: in the app this takes the SwiftData model; the core takes the
    /// armored public keyring + primary fingerprint (hex) directly.
    static func buildEditedKeyOnCard(
        armoredPublic: String,
        fingerprintHex: String,
        expiresAt: Date?,
        service: OpenPGPCardService,
        pin: String,
        includeCurrentSubkeys: Bool = true,
        subkeyFingerprint: String? = nil
    ) async throws -> EditedKey {
        guard let fp = bytesFromHex(fingerprintHex), fp.count == 20 else {
            throw EditError.noPrimaryKeyPacket
        }
        // The card's signing-key algorithm drives the binding-signature framing
        // (EdDSA = two MPIs over a bare digest; RSA = one MPI over a PKCS#1
        // DigestInfo). Anything the card doesn't report as EdDSA or RSA is refused.
        let cardInfo = try await service.readCardInfo()
        guard let algorithm = cardInfo.signatureAlgorithm else { throw EditError.unsupportedAlgorithm }
        return try await buildEditedKeyCore(
            armoredPublic: armoredPublic,
            expiresAt: expiresAt,
            primaryFP20: fp,
            issuerKeyID: Array(fp.suffix(8)),
            secretRing: nil,
            algorithm: algorithm,
            includeCurrentSubkeys: includeCurrentSubkeys,
            // 8.4.0 build 11 (plan 5n): no secret ring, so a signing subkey
            // (which would sign its own back-signature) is refused.
            subkeyTarget: subkeyFingerprint.map { SubkeyTarget(fingerprintHex: $0, secretRing: nil, passphrase: nil) },
            sign: { digest in
                try await service.verify(pin: pin, mode: .signing)
                // 8.4.0 build 10 (plan 5m): EdDSA, RSA and ECDSA through one helper.
                return try await service.signDigest(digest, algorithm: algorithm)
            }
        )
    }

    /// Shared core: pre-scan the public ring, regenerate the self-cert(s) and subkey
    /// binding(s) via `sign`, splice into the public ring (and the secret ring when
    /// `secretRing` is provided), and return the result.
    private static func buildEditedKeyCore(
        armoredPublic: String,
        expiresAt: Date?,
        primaryFP20: [UInt8],
        issuerKeyID: [UInt8],
        secretRing: Data?,
        algorithm: CardSignatureAlgorithm,
        includeCurrentSubkeys: Bool = true,
        subkeyTarget: SubkeyTarget? = nil,
        sign: (_ digest: [UInt8]) async throws -> [UInt8]
    ) async throws -> EditedKey {
        let pubBytes = try dearmor(armoredPublic)
        let pubPackets = try OpenPGPPacketParser.parsePackets(data: pubBytes)

        // 3. Pre-scan: primary body + ordered user IDs and subkeys, each paired
        //    with the hashed subpackets of its existing self-signature so we can
        //    copy capabilities forward.
        var primaryBody: [UInt8]?
        var primaryCreation: UInt32 = 0
        var uids: [UidEntry] = []
        var subs: [SubEntry] = []
        var ctx = Context.none

        for pkt in pubPackets {
            switch pkt.tag {
            case 6:
                primaryBody = pkt.body
                primaryCreation = try OpenPGPPacketParser.parsePublicKeyFields(body: pkt.body).creationTime
            case 13:
                uids.append(UidEntry(body: pkt.body, certSubpackets: []))
                ctx = .uid
            case 14:
                let info = try OpenPGPPacketParser.parsePublicKeyFields(body: pkt.body)
                subs.append(SubEntry(body: pkt.body, creation: info.creationTime, bindingSubpackets: [], isSign: false,
                                     fingerprint: CertificateValidator.fingerprint(ofKeyBody: pkt.body)))
                ctx = .subkey
            case 2:
                let sig = try OpenPGPPacketParser.parseSignaturePacket(body: pkt.body)
                // Only treat as a self-sig if the issuer is the primary key.
                guard isSelfIssued(sig, primaryFP20: primaryFP20) else { break }
                if sig.signatureType == 0x13, ctx == .uid, let i = uids.indices.last {
                    // 8.4.0 (plan 5d): the newest cert's subpackets are the ones carried.
                    let t = sig.creationTime ?? .distantPast
                    if uids[i].latestCert.map({ t >= $0 }) ?? true {
                        uids[i].latestCert = t
                        uids[i].certSubpackets = sig.hashedSubpackets
                    }
                } else if sig.signatureType == 0x30, ctx == .uid, let i = uids.indices.last {
                    let t = sig.creationTime ?? .distantPast
                    if uids[i].latestRevocation.map({ t >= $0 }) ?? true { uids[i].latestRevocation = t }
                } else if sig.signatureType == 0x18, ctx == .subkey, let j = subs.indices.last {
                    // 8.4.0 (plan 5d): the newest binding decides the subkey's
                    // current expiry and is the one carried forward.
                    let t = sig.creationTime ?? .distantPast
                    guard subs[j].latestBinding.map({ t >= $0 }) ?? true else { break }
                    subs[j].latestBinding = t
                    subs[j].bindingSubpackets = sig.hashedSubpackets
                    if let kf = sig.hashedSubpackets.first(where: { $0.type == 27 })?.data,
                       let firstFlag = kf.first, (firstFlag & 0x02) != 0 {
                        // 0x02 = "this key may be used to sign data". Such a subkey
                        // needs a 0x19 primary-key back-signature we don't generate,
                        // so we leave its binding untouched. PGPony keys have no
                        // signing subkey; this guard is for imported keys.
                        subs[j].isSign = true
                    }
                } else if sig.signatureType == 0x28, ctx == .subkey, let j = subs.indices.last {
                    // 8.3.0 (4.6): a revoked subkey keeps its old binding. A
                    // fresh, newer binding would read as a re-certification to
                    // a verifier that lets a newer self-signature override a
                    // soft revocation (Sequoia does), resurrecting the subkey.
                    subs[j].isRevoked = true
                }
            default:
                break
            }
        }
        guard let primaryBody else { throw EditError.noPrimaryKeyPacket }

        let nowBytes = u32be(UInt32(Date().timeIntervalSince1970))
        let issuerFPData: [UInt8] = [4] + primaryFP20          // type-33 v4 form

        // 8.4.0 build 11 (plan 5n, Android 4.7.0 item 53): one subkey's
        // binding, signed again with its new date; the User IDs and every
        // other subkey keep their signatures. An expired subkey may take a
        // new date here (that is what this target is for); a revoked one
        // never does. A signing subkey's binding embeds a fresh 0x19 made by
        // the subkey, so its secret has to be in `secretRing`.
        if let target = subkeyTarget {
            let wanted = bytesFromHex(target.fingerprintHex.lowercased()) ?? []
            guard let j = subs.firstIndex(where: { $0.fingerprint == wanted }) else { throw EditError.subkeyNotFound }
            let s = subs[j]
            guard !s.isRevoked else { throw EditError.subkeyRevoked }
            guard let latest = s.latestBinding else { throw EditError.noSubkeyBinding }
            // Newer than the binding it replaces, so every reader picks it.
            let sigTime = max(UInt32(Date().timeIntervalSince1970), epochSeconds(latest) &+ 1)
            let doc2 = [0x99] + u16be(UInt16(s.body.count)) + s.body
            var embedded: [UInt8]? = nil
            if s.isSign {
                guard let ring = target.secretRing else { throw EditError.cardSigningSubkey }
                embedded = try await v4BackSignature(primaryBody: primaryBody, subkeyBody: s.body, secretRing: ring,
                                                     passphrase: target.passphrase, sigTime: sigTime)
            }
            let hashed = bindingSubpackets(
                creationBytes: u32be(sigTime),
                expiryBytes: try relativeExpiry(expiresAt: expiresAt, creation: s.creation),
                preserved: s.bindingSubpackets,
                issuerFPData: issuerFPData,
                embeddedBackSignature: embedded
            )
            let packet = try await signKeyTargeted(
                primaryBody: primaryBody, document2: doc2, sigType: 0x18,
                algorithm: algorithm,
                hashedSubpackets: hashed,
                unhashedSubpackets: buildSubpacket(type: 16, data: issuerKeyID),
                sign: sign
            )
            let newPublicRing = spliceRing(packets: pubPackets, newCerts: [:], newBindings: [j: packet],
                                           primaryFP20: primaryFP20)
            var secretOut = Data()
            if let secretRing {
                let secretData = secretRing
                let secretPackets = try OpenPGPPacketParser.parsePackets(data: Array(secretData))
                secretOut = Data(spliceRing(packets: secretPackets, newCerts: [:], newBindings: [j: packet],
                                            primaryFP20: primaryFP20))
            }
            return EditedKey(secretKeyData: secretOut, armoredPublicKey: armorPublicKeyBlock(newPublicRing),
                             expiresAt: expiresAt)
        }

        // 4. Generate one fresh 0x13 cert per live user ID (relative to PRIMARY
        //    creation). Revoked user IDs keep their old cert and revocation.
        //    With none live there is nowhere to carry the primary's expiration.
        guard uids.isEmpty || uids.contains(where: { !$0.isRevoked }) else {
            throw EditError.noLiveUserID
        }
        var newCerts: [Int: [UInt8]] = [:]
        for (i, u) in uids.enumerated() where !u.isRevoked {
            let expiryBytes = try relativeExpiry(expiresAt: expiresAt, creation: primaryCreation)
            let hashed = certSubpackets(
                creationBytes: nowBytes,
                expiryBytes: expiryBytes,
                preserved: u.certSubpackets,
                issuerFPData: issuerFPData
            )
            let doc2 = [0xB4] + u32be(UInt32(u.body.count)) + u.body   // 0xB4 || 4-byte len || UID
            let packet = try await signKeyTargeted(
                primaryBody: primaryBody, document2: doc2, sigType: 0x13,
                algorithm: algorithm,
                hashedSubpackets: hashed,
                unhashedSubpackets: buildSubpacket(type: 16, data: issuerKeyID),
                sign: sign
            )
            newCerts[i] = packet
        }

        // 5. Generate one fresh 0x18 binding per (non-signing) subkey, relative to
        //    that SUBKEY's own creation time. Signing subkeys and revoked subkeys
        //    are skipped (left as-is).
        //    8.4.0 (plan 5d, Android 4.7.0 item 53): only when the caller asks
        //    for it, and only for subkeys still valid now. Before 8.4.0 every
        //    subkey got the primary's new date, which brought expired subkeys
        //    back; an expired subkey now keeps its old binding.
        let now = Date()
        var newBindings: [Int: [UInt8]] = [:]
        for (j, s) in subs.enumerated() where includeCurrentSubkeys && !s.isSign && !s.isRevoked && !s.isExpired(at: now) {
            let expiryBytes = try relativeExpiry(expiresAt: expiresAt, creation: s.creation)
            let hashed = bindingSubpackets(
                creationBytes: nowBytes,
                expiryBytes: expiryBytes,
                preserved: s.bindingSubpackets,
                issuerFPData: issuerFPData
            )
            let doc2 = [0x99] + u16be(UInt16(s.body.count)) + s.body  // 0x99 || 2-byte len || subkey body
            let packet = try await signKeyTargeted(
                primaryBody: primaryBody, document2: doc2, sigType: 0x18,
                algorithm: algorithm,
                hashedSubpackets: hashed,
                unhashedSubpackets: buildSubpacket(type: 16, data: issuerKeyID),
                sign: sign
            )
            newBindings[j] = packet
        }

        // 6. Splice the fresh signatures into both rings. The public ring gives us
        //    the new armored public key; the secret ring (loaded from the Keychain)
        //    gives us the bytes to persist. Both rings share the same UID/subkey
        //    ordering, so positional indices line up.
        let newPublicRing = spliceRing(
            packets: pubPackets, newCerts: newCerts, newBindings: newBindings, primaryFP20: primaryFP20
        )

        var secretOut = Data()
        if let secretRing {
            // CORE SEAM: the app loads these bytes from its Keychain
            // (KeychainService.loadPrivateKey); the core receives them directly.
            let secretPackets = try OpenPGPPacketParser.parsePackets(data: Array(secretRing))
            secretOut = Data(spliceRing(
                packets: secretPackets, newCerts: newCerts, newBindings: newBindings, primaryFP20: primaryFP20
            ))
        }

        return EditedKey(
            secretKeyData: secretOut,
            armoredPublicKey: armorPublicKeyBlock(newPublicRing),
            expiresAt: expiresAt
        )
    }

    // MARK: - One subkey's expiry (8.4.0 build 11, plan 5n, Android 4.7.0 item 53)

    /// Which subkey a Change Expiration edits instead of the primary. The
    /// secret ring is where a signing subkey's own secret is read for its
    /// back-signature; nil on a hardware key, which cannot make one.
    struct SubkeyTarget {
        let fingerprintHex: String
        let secretRing: Data?
        let passphrase: String?
    }

    /// A v4 signing subkey's fresh 0x19 back-signature (the signature body,
    /// for the binding's embedded-signature subpacket), made by the subkey
    /// over primary || subkey. Only an Ed25519 subkey whose secret is in the
    /// ring signs here; the result must verify against the subkey.
    private static func v4BackSignature(primaryBody: [UInt8], subkeyBody: [UInt8], secretRing: Data,
                                        passphrase: String?, sigTime: UInt32) async throws -> [UInt8] {
        guard subkeyBody.count > 5, subkeyBody[0] == 4, subkeyBody[5] == 22 else { throw EditError.signingSubkeyNotHere }
        let info = try await unlockSigningSubkey(secretRing: secretRing, subkeyBody: subkeyBody, passphrase: passphrase)
        let subFP = CertificateValidator.fingerprint(ofKeyBody: subkeyBody)
        guard Array(info.fingerprint.suffix(20)) == subFP else { throw EditError.signingSubkeyNotHere }
        let key = info.privateKey
        var hashed = buildSubpacket(type: 2, data: u32be(sigTime))
        hashed += buildSubpacket(type: 33, data: [4] + subFP)
        let packet = try await signKeyTargeted(
            primaryBody: primaryBody,
            document2: [0x99] + u16be(UInt16(subkeyBody.count)) + subkeyBody,
            sigType: 0x19,
            algorithm: .eddsa,
            hashedSubpackets: hashed,
            unhashedSubpackets: buildSubpacket(type: 16, data: Array(subFP.suffix(8))),
            sign: { digest in Array(try key.signature(for: Data(digest))) }
        )
        guard let body = try? OpenPGPPacketParser.parsePackets(data: packet).first?.body else {
            throw EditError.signingSubkeyNotHere
        }
        try checkSignature(body, signerBody: subkeyBody, primaryBody: primaryBody, subkeyBody: subkeyBody)
        return body
    }

    /// Unlock one signing subkey's secret (v4 or v6 Ed25519) on its own,
    /// whatever its validity: framed as a ring of that one secret-subkey
    /// packet, the extractor has nothing else to choose. A GnuPG stub, or a
    /// subkey whose secret is not in the ring, is not here.
    private static func unlockSigningSubkey(secretRing: Data, subkeyBody: [UInt8],
                                            passphrase: String?) async throws -> Ed25519SigningInfo {
        let packets = try OpenPGPPacketParser.parsePackets(data: Array(secretRing))
        guard let secret = packets.first(where: {
            $0.tag == 7 && $0.body.count > subkeyBody.count && Array($0.body.prefix(subkeyBody.count)) == subkeyBody
        }), OpenPGPPacketParser.gnuStub(secretBody: secret.body) == nil else {
            throw EditError.signingSubkeyNotHere
        }
        let single = Data(OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 7, body: secret.body))
        do {
            return try await runOffMainThread {
                try PGPService.shared.extractEd25519SigningKey(fromSecretKeyData: single, passphrase: passphrase,
                                                               preferSigningSubkey: true)
            }
        } catch let e as PGPServiceError {
            switch e {
            case .passphraseRequired, .invalidPassphrase: throw EditError.underlying(e)
            default: throw EditError.signingSubkeyNotHere
            }
        }
    }

    /// Throws unless `body` (a signature) verifies by `signerBody` over the
    /// (primary, subkey) binding document.
    private static func checkSignature(_ body: [UInt8], signerBody: [UInt8], primaryBody: [UInt8],
                                       subkeyBody: [UInt8]) throws {
        guard let parsed = try? OpenPGPPacketParser.parseSignaturePacket(body: body) else {
            throw EditError.noSubkeyBinding
        }
        let documents = CertificateValidator.bindingDocuments(primaryBody: primaryBody, subkeyBody: subkeyBody,
                                                              signatureVersion: parsed.version)
        let verdicts = documents.map { CertificateValidator.verify(parsed, signerBody: signerBody, document: $0) }
        // .uncheckable (no verifier on this device) is not a failure.
        guard verdicts.contains(where: { $0 != .invalid }) else {
            throw parsed.signatureType == 0x19 ? EditError.signingSubkeyNotHere : EditError.noSubkeyBinding
        }
    }

    /// One subkey of a public ring, with its position among the subkeys and
    /// the signatures under it.
    struct LocatedSubkey {
        let order: Int
        let body: [UInt8]
        /// Signatures issued by the primary, parsed.
        let selfSignatures: [OpenPGPPacketParser.ParsedSignature]
        /// Every signature packet body under the subkey, as stored.
        let signatureBodies: [[UInt8]]

        var isRevoked: Bool { selfSignatures.contains { $0.signatureType == 0x28 } }

        /// The newest binding by the primary.
        var newestBinding: OpenPGPPacketParser.ParsedSignature? {
            selfSignatures.filter { $0.signatureType == 0x18 }
                .max { ($0.creationTime ?? .distantPast) < ($1.creationTime ?? .distantPast) }
        }

        /// True when the newest binding's Key Expiration Time has passed.
        func isExpired(at date: Date) -> Bool {
            guard body.count >= 5,
                  let d = newestBinding?.hashedSubpackets.first(where: { $0.type == 9 })?.data, d.count == 4 else { return false }
            let creation = UInt32(body[1]) << 24 | UInt32(body[2]) << 16 | UInt32(body[3]) << 8 | UInt32(body[4])
            let seconds = UInt32(d[0]) << 24 | UInt32(d[1]) << 16 | UInt32(d[2]) << 8 | UInt32(d[3])
            return seconds > 0 && Date(timeIntervalSince1970: TimeInterval(creation) + TimeInterval(seconds)) <= date
        }
    }

    /// The public subkey (tag 14) whose fingerprint is `fingerprint`.
    static func locateSubkey(_ packets: [ParsedPacket], primaryBody: [UInt8], fingerprint: [UInt8]) -> LocatedSubkey? {
        var order = -1
        var i = 0
        while i < packets.count {
            guard packets[i].tag == 14 else { i += 1; continue }
            order += 1
            var j = i + 1
            var parsed: [OpenPGPPacketParser.ParsedSignature] = []
            var raw: [[UInt8]] = []
            while j < packets.count, packets[j].tag == 2 || packets[j].tag == 12 {
                if packets[j].tag == 2 {
                    raw.append(packets[j].body)
                    if let sig = try? OpenPGPPacketParser.parseSignaturePacket(body: packets[j].body),
                       CertificateValidator.issuedBy(primaryBody: primaryBody, sig) {
                        parsed.append(sig)
                    }
                }
                j += 1
            }
            if CertificateValidator.fingerprint(ofKeyBody: packets[i].body) == fingerprint {
                return LocatedSubkey(order: order, body: packets[i].body, selfSignatures: parsed, signatureBodies: raw)
            }
            i = j
        }
        return nil
    }

    /// Re-emit a ring (public 6/14 or secret 5/7) with the subkey at
    /// `order` bound by `fresh` (a signature body): written once in place
    /// of its first binding by the primary, the older bindings dropped.
    /// Everything else, revocations and other subkeys included, is kept.
    static func replaceSubkeyBinding(_ packets: [ParsedPacket], order target: Int, with fresh: [UInt8],
                                     primaryBody: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        var order = -1
        var inTarget = false
        var wrote = false
        for pkt in packets {
            switch pkt.tag {
            case 14, 7:
                order += 1
                inTarget = order == target
                out += buildNewFormatPacket(tag: pkt.tag, body: pkt.body)
            case 2 where inTarget:
                if let sig = try? OpenPGPPacketParser.parseSignaturePacket(body: pkt.body),
                   sig.signatureType == 0x18, CertificateValidator.issuedBy(primaryBody: primaryBody, sig) {
                    if !wrote { out += buildNewFormatPacket(tag: 2, body: fresh) }
                    wrote = true
                } else {
                    out += buildNewFormatPacket(tag: pkt.tag, body: pkt.body)
                }
            case 2, 12:
                out += buildNewFormatPacket(tag: pkt.tag, body: pkt.body)
            default:
                inTarget = false
                out += buildNewFormatPacket(tag: pkt.tag, body: pkt.body)
            }
        }
        return out
    }

    /// A v6 key (Ed25519 or composite primary): one subkey's binding signed
    /// again with the new date, the way V6KeyGenerator.editV6Expiration signs
    /// it (every hashed subpacket of the old binding carried, a fresh 0x19
    /// for a signing subkey), and nothing else touched: the direct-key
    /// signature, the User IDs and the other subkeys stay byte for byte.
    static func editV6SubkeyExpiration(
        publicKeyData: Data,
        secretKeyData: Data,
        primarySigner: V6SignatureKey,
        primaryFingerprint: [UInt8],
        subkeyFingerprintHex: String,
        expiresAt: Date?,
        passphrase: String?,
        now: Date = Date()
    ) async throws -> (publicKeyData: Data, secretKeyData: Data) {
        let pubPackets = try OpenPGPPacketParser.parsePackets(data: Array(publicKeyData))
        guard let primaryBody = pubPackets.first(where: { $0.tag == 6 })?.body else { throw EditError.noPrimaryKeyPacket }
        let wanted = bytesFromHex(subkeyFingerprintHex.lowercased()) ?? []
        guard let sub = locateSubkey(pubPackets, primaryBody: primaryBody, fingerprint: wanted) else {
            throw EditError.subkeyNotFound
        }
        guard !sub.isRevoked else { throw EditError.subkeyRevoked }
        guard let old = sub.newestBinding else { throw EditError.noSubkeyBinding }
        let subCreation = try OpenPGPPacketParser.parsePublicKeyFields(body: sub.body).creationTime
        let expiry = try relativeExpiry(expiresAt: expiresAt, creation: subCreation)
        let sigTime = max(UInt32(now.timeIntervalSince1970), epochSeconds(old.creationTime ?? .distantPast) &+ 1)
        let document = CertificateValidator.frameKey(primaryBody, signatureVersion: 6)
            + CertificateValidator.frameKey(sub.body, signatureVersion: 6)

        var backSignature: [UInt8]? = nil
        let flags = old.hashedSubpackets.first(where: { $0.type == 27 })?.data.first ?? 0
        if flags & 0x02 != 0 {
            let info = try await unlockSigningSubkey(secretRing: secretKeyData, subkeyBody: sub.body, passphrase: passphrase)
            let subFP = CertificateValidator.fingerprint(ofKeyBody: sub.body)
            guard Array(info.fingerprint.suffix(32)) == subFP else { throw EditError.signingSubkeyNotHere }
            var backHashed = buildSubpacket(type: 2 | 0x80, data: u32be(sigTime))
            backHashed += buildSubpacket(type: 33, data: [6] + subFP)
            let back = try V6KeyGenerator.assembleV6Signature(
                signer: V6SignatureKey(info), sigType: 0x19, documentHashChunks: document,
                hashedSubpackets: backHashed, unhashedSubpackets: [])
            try checkSignature(back, signerBody: sub.body, primaryBody: primaryBody, subkeyBody: sub.body)
            backSignature = back
        }

        var hashed = buildSubpacket(type: 2 | 0x80, data: u32be(sigTime))
        if let expiry { hashed += buildSubpacket(type: 9 | 0x80, data: expiry) }
        for sp in old.hashedSubpackets where ![2, 9, 16, 32, 33].contains(sp.type) {
            hashed += buildSubpacket(type: sp.isCritical ? (sp.type | 0x80) : sp.type, data: sp.data)
        }
        if let backSignature { hashed += buildSubpacket(type: 32 | 0x80, data: backSignature) }
        hashed += buildSubpacket(type: 33, data: [6] + primaryFingerprint)
        let binding = try V6KeyGenerator.assembleV6Signature(
            signer: primarySigner, sigType: 0x18, documentHashChunks: document,
            hashedSubpackets: hashed, unhashedSubpackets: [])
        try checkSignature(binding, signerBody: primaryBody, primaryBody: primaryBody, subkeyBody: sub.body)

        let secretPackets = try OpenPGPPacketParser.parsePackets(data: Array(secretKeyData))
        return (Data(replaceSubkeyBinding(pubPackets, order: sub.order, with: binding, primaryBody: primaryBody)),
                Data(replaceSubkeyBinding(secretPackets, order: sub.order, with: binding, primaryBody: primaryBody)))
    }

    /// An Ed448 key (LibrePGP v5 or RFC 9580 v6): Ed448KeyEditor signs the
    /// new binding (its v5 or v6 shape, its back-signature for a signing
    /// subkey), and only that one binding is taken into the stored rings.
    /// The editor passes over an expired subkey, so for one it is run as of
    /// the subkey's creation, when it was not expired; it then dates its
    /// signatures one second after the newest self-signature, which still
    /// makes the new binding the newest. Synchronous, for runOffMainThread.
    static func editEd448SubkeyExpiration(
        publicKeyData: Data,
        secretKeyData: Data,
        passphrase: String?,
        subkeyFingerprintHex: String,
        expiresAt: Date?,
        now: Date = Date()
    ) throws -> (publicKeyData: Data, secretKeyData: Data) {
        let pubPackets = try OpenPGPPacketParser.parsePackets(data: Array(publicKeyData))
        guard let primaryBody = pubPackets.first(where: { $0.tag == 6 })?.body else { throw EditError.noPrimaryKeyPacket }
        let wanted = bytesFromHex(subkeyFingerprintHex.lowercased()) ?? []
        guard let sub = locateSubkey(pubPackets, primaryBody: primaryBody, fingerprint: wanted) else {
            throw EditError.subkeyNotFound
        }
        guard !sub.isRevoked else { throw EditError.subkeyRevoked }
        guard sub.newestBinding != nil, sub.body.count >= 5 else { throw EditError.noSubkeyBinding }
        let subCreation = UInt32(sub.body[1]) << 24 | UInt32(sub.body[2]) << 16 | UInt32(sub.body[3]) << 8 | UInt32(sub.body[4])
        _ = try relativeExpiry(expiresAt: expiresAt, creation: subCreation)
        let runAt = sub.isExpired(at: now) ? Date(timeIntervalSince1970: TimeInterval(subCreation)) : now

        let result: Ed448KeyEditor.Result
        do {
            result = try Ed448KeyEditor.resign(publicKeyData: publicKeyData, secretKeyData: secretKeyData,
                                               passphrase: passphrase, expiry: .set(expiresAt),
                                               includeCurrentSubkeys: true, now: runAt)
        } catch let e as Ed448KeyEditor.EditError {
            switch e {
            case .expiryBeforeCreation: throw EditError.expiryBeforeCreation
            case .noPrimaryKeyPacket: throw EditError.noPrimaryKeyPacket
            case .nothingToSign: throw EditError.noSubkeyBinding
            default: throw EditError.underlying(e)
            }
        }
        let outPackets = try OpenPGPPacketParser.parsePackets(data: Array(result.publicKeyData))
        guard let outSub = locateSubkey(outPackets, primaryBody: primaryBody, fingerprint: wanted),
              let fresh = outSub.signatureBodies.first(where: { body in
                  !sub.signatureBodies.contains(body)
                      && (try? OpenPGPPacketParser.parseSignaturePacket(body: body))?.signatureType == 0x18
              }) else {
            let hex = wanted.map { String(format: "%02x", $0) }.joined()
            throw result.passedOver.contains(hex) ? EditError.signingSubkeyNotHere : EditError.noSubkeyBinding
        }
        let secretPackets = try OpenPGPPacketParser.parsePackets(data: Array(secretKeyData))
        return (Data(replaceSubkeyBinding(pubPackets, order: sub.order, with: fresh, primaryBody: primaryBody)),
                Data(replaceSubkeyBinding(secretPackets, order: sub.order, with: fresh, primaryBody: primaryBody)))
    }

    private static func epochSeconds(_ date: Date) -> UInt32 {
        let t = date.timeIntervalSince1970
        return t <= 0 ? 0 : UInt32(min(t, Double(UInt32.max - 1)))
    }

    // MARK: - Pre-scan helpers

    private enum Context { case none, uid, subkey }

    private struct UidEntry {
        let body: [UInt8]
        var certSubpackets: [OpenPGPPacketParser.ParsedSubpacket]
        /// 8.3.0 build 4: newest self-issued 0x13 and 0x30 times. A UID whose
        /// newest self-revocation is at least as new as its newest self-cert is
        /// revoked, and keeps its old cert: a fresh 0x13 would be newer than
        /// the revocation and read as a re-certification (the same
        /// resurrection the subkey path already avoids for 0x28).
        var latestCert: Date? = nil
        var latestRevocation: Date? = nil
        var isRevoked: Bool {
            guard let latestRevocation else { return false }
            guard let latestCert else { return true }
            return latestRevocation >= latestCert
        }
    }

    private struct SubEntry {
        let body: [UInt8]
        let creation: UInt32
        var bindingSubpackets: [OpenPGPPacketParser.ParsedSubpacket]
        var isSign: Bool
        /// 8.3.0 (4.6): carries a self-issued 0x28; its binding is left as is.
        var isRevoked = false
        /// 8.4.0 (plan 5d): creation time of the newest self-issued binding.
        var latestBinding: Date? = nil
        /// 8.4.0 build 11 (plan 5n): the subkey's fingerprint, to find a target.
        var fingerprint: [UInt8] = []

        /// True when the newest binding's Key Expiration Time has passed.
        func isExpired(at date: Date) -> Bool {
            guard let d = bindingSubpackets.first(where: { $0.type == 9 })?.data, d.count == 4 else { return false }
            let seconds = UInt32(d[0]) << 24 | UInt32(d[1]) << 16 | UInt32(d[2]) << 8 | UInt32(d[3])
            return seconds > 0 && Date(timeIntervalSince1970: TimeInterval(creation) + TimeInterval(seconds)) <= date
        }
    }

    /// True if a signature's issuer is the primary key (so it's a self-signature
    /// and safe for us to supersede). Third-party certifications are left alone.
    private static func isSelfIssued(_ sig: OpenPGPPacketParser.ParsedSignature, primaryFP20: [UInt8]) -> Bool {
        if let fp = sig.issuerFingerprint {
            return Array(fp.suffix(20)) == primaryFP20
        }
        if let kid = sig.issuerKeyID {
            return kid == Array(primaryFP20.suffix(8))
        }
        // No issuer info: assume self (PGPony self-sigs always carry type 33).
        return true
    }

    // MARK: - Subpacket construction

    /// Capability subpackets to copy forward verbatim. We always regenerate
    /// creation time (2), expiration (9), and issuer info (16/33) ourselves.
    private static let regeneratedTypes: Set<UInt8> = [2, 9, 16, 33]

    private static func certSubpackets(
        creationBytes: [UInt8],
        expiryBytes: [UInt8]?,
        preserved: [OpenPGPPacketParser.ParsedSubpacket],
        issuerFPData: [UInt8]
    ) -> [UInt8] {
        var out: [UInt8] = []
        out += buildSubpacket(type: 2, data: creationBytes)
        for sp in preserved where !regeneratedTypes.contains(sp.type) {
            out += buildSubpacket(type: sp.isCritical ? (sp.type | 0x80) : sp.type, data: sp.data)
        }
        if let expiryBytes { out += buildSubpacket(type: 9, data: expiryBytes) }
        out += buildSubpacket(type: 33, data: issuerFPData)
        return out
    }

    private static func bindingSubpackets(
        creationBytes: [UInt8],
        expiryBytes: [UInt8]?,
        preserved: [OpenPGPPacketParser.ParsedSubpacket],
        issuerFPData: [UInt8],
        embeddedBackSignature: [UInt8]? = nil
    ) -> [UInt8] {
        // 8.4.0 build 11 (plan 5n): a signing subkey's binding carries its
        // fresh 0x19 (hashed, as GnuPG writes it) in place of the old one.
        if let back = embeddedBackSignature {
            var out: [UInt8] = []
            out += buildSubpacket(type: 2, data: creationBytes)
            for sp in preserved where !regeneratedTypes.contains(sp.type) && sp.type != 32 {
                out += buildSubpacket(type: sp.isCritical ? (sp.type | 0x80) : sp.type, data: sp.data)
            }
            if let expiryBytes { out += buildSubpacket(type: 9, data: expiryBytes) }
            out += buildSubpacket(type: 32, data: back)
            out += buildSubpacket(type: 33, data: issuerFPData)
            return out
        }
        // Identical shape to a cert's; in practice a binding usually only carries
        // a key-flags subpacket (type 27) to preserve.
        return certSubpackets(
            creationBytes: creationBytes,
            expiryBytes: expiryBytes,
            preserved: preserved,
            issuerFPData: issuerFPData
        )
    }

    /// Relative Key Expiration Time (seconds after `creation`), or nil for "never".
    private static func relativeExpiry(expiresAt: Date?, creation: UInt32) throws -> [UInt8]? {
        guard let expiresAt else { return nil }
        let expEpoch = expiresAt.timeIntervalSince1970
        guard expEpoch > Double(creation) else { throw EditError.expiryBeforeCreation }
        let rel = UInt32(expEpoch) - creation
        return u32be(rel)
    }

    // MARK: - Key-targeted signature (0x13 / 0x18), v4 EdDSA or RSA

    /// Build a complete tag-2 signature packet whose hash covers the primary key
    /// followed by `document2` (a 0xB4 user-ID block for 0x13, or a 0x99 subkey
    /// block for 0x18), per RFC 4880 §5.2.4. The public-key algorithm byte is part
    /// of the hashed trailer, so it must match the card's signing key: EdDSA (22)
    /// returns 64 bytes (R||S, two MPIs); RSA (1) returns one modulus-length value
    /// (a single MPI, leading zero bytes stripped for a canonical MPI). The `sign`
    /// closure receives the bare SHA-256 digest and is responsible for presenting it
    /// to the card the way that algorithm needs (bare digest for EdDSA, a PKCS#1
    /// DigestInfo for RSA).
    static func signKeyTargeted(
        primaryBody: [UInt8],
        document2: [UInt8],
        sigType: UInt8,
        algorithm: CardSignatureAlgorithm,
        hashedSubpackets: [UInt8],
        unhashedSubpackets: [UInt8],
        sign: (_ digest: [UInt8]) async throws -> [UInt8]
    ) async throws -> [UInt8] {
        let pubAlgo = algorithm.packetAlgorithmID
        // 8.4.0 build 10 (plan 5m): SHA-256 for EdDSA and RSA, the curve's
        // hash for a card ECDSA key.
        let hashID: UInt8 = algorithm.hashAlgorithmID

        // Hash input: 0x99 || len || primary body || document2 || trailer || final.
        var hashInput = Data()
        hashInput.append(0x99)
        hashInput.append(contentsOf: u16be(UInt16(primaryBody.count)))
        hashInput.append(contentsOf: primaryBody)
        hashInput.append(contentsOf: document2)

        var trailer: [UInt8] = [4, sigType, pubAlgo, hashID]
        trailer += u16be(UInt16(hashedSubpackets.count))
        trailer += hashedSubpackets
        hashInput.append(contentsOf: trailer)

        // v4 final trailer: 0x04 0xFF || 4-byte BE length of the trailer.
        hashInput.append(4)
        hashInput.append(0xFF)
        hashInput.append(contentsOf: u32be(UInt32(trailer.count)))

        let digest = algorithm.digest(hashInput)
        let sigBytes = try await sign(digest)

        // Algorithm-specific signature MPI list.
        let signatureMPIs: [[UInt8]]
        switch algorithm {
        case .eddsa:
            guard sigBytes.count == 64 else { throw EditError.underlying(NSError(
                domain: "PGPony.Expiration", code: 1,
                userInfo: [NSLocalizedDescriptionKey: String(localized: "Unexpected Ed25519 signature length \(sigBytes.count).")])) }
            signatureMPIs = [Array(sigBytes[0..<32]), Array(sigBytes[32..<64])]
        case .rsa:
            guard !sigBytes.isEmpty else { throw EditError.underlying(NSError(
                domain: "PGPony.Expiration", code: 2,
                userInfo: [NSLocalizedDescriptionKey: String(localized: "Empty RSA signature from card.")])) }
            var sig = sigBytes
            while sig.first == 0x00 && sig.count > 1 { sig.removeFirst() }
            signatureMPIs = [sig]
        case .ecdsa:
            // 8.4.0 build 10 (plan 5m): the card's r || s, two MPIs.
            signatureMPIs = try algorithm.signatureMPIs(fromCardOutput: sigBytes)
        }

        // Assemble the tag-2 body.
        var body: [UInt8] = [4, sigType, pubAlgo, hashID]
        body += u16be(UInt16(hashedSubpackets.count))
        body += hashedSubpackets
        body += u16be(UInt16(unhashedSubpackets.count))
        body += unhashedSubpackets
        body.append(digest[0])
        body.append(digest[1])
        for mpi in signatureMPIs { body += mpiEncode(mpi) }

        return buildNewFormatPacket(tag: 2, body: body)
    }

    // MARK: - Ring reassembly

    /// Re-emit every packet, replacing each self-cert / self-binding with its
    /// freshly generated counterpart (by positional index). Everything else —
    /// the key packets themselves, revocation signatures, skipped signing-subkey
    /// bindings — is preserved byte-for-byte in its body and re-framed new-format.
    private static func spliceRing(
        packets: [ParsedPacket],
        newCerts: [Int: [UInt8]],
        newBindings: [Int: [UInt8]],
        primaryFP20: [UInt8]
    ) -> [UInt8] {
        var out: [UInt8] = []
        var uidIdx = -1
        var subIdx = -1
        var ctx = Context.none
        var certEmittedFor = Set<Int>()
        var bindingEmittedFor = Set<Int>()

        for pkt in packets {
            switch pkt.tag {
            case 13:
                uidIdx += 1
                ctx = .uid
                out += buildNewFormatPacket(tag: pkt.tag, body: pkt.body)
            case 14, 7:
                subIdx += 1
                ctx = .subkey
                out += buildNewFormatPacket(tag: pkt.tag, body: pkt.body)
            case 2:
                guard let sig = try? OpenPGPPacketParser.parseSignaturePacket(body: pkt.body),
                      isSelfIssued(sig, primaryFP20: primaryFP20) else {
                    out += buildNewFormatPacket(tag: pkt.tag, body: pkt.body)
                    break
                }
                if sig.signatureType == 0x13, ctx == .uid, let replacement = newCerts[uidIdx] {
                    // Emit the regenerated cert once per UID and drop any superseded
                    // extras, so a source key carrying multiple self-certs doesn't
                    // produce a duplicate self-signature in the output. A revoked
                    // UID has no entry and falls through with its certs as they were.
                    if certEmittedFor.insert(uidIdx).inserted {
                        out += replacement
                    }
                } else if sig.signatureType == 0x18, ctx == .subkey, let replacement = newBindings[subIdx] {
                    if bindingEmittedFor.insert(subIdx).inserted {
                        out += replacement
                    }
                } else {
                    out += buildNewFormatPacket(tag: pkt.tag, body: pkt.body)
                }
            default:
                // Primary key packet (tag 5 or 6) and anything else: unchanged.
                out += buildNewFormatPacket(tag: pkt.tag, body: pkt.body)
            }
        }
        return out
    }

    // MARK: - Small encoders (kept local so this file has no private dependency
    // on SigningService; identical behavior to its versions).

    private static func buildSubpacket(type: UInt8, data: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
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
        out.append(type)
        out.append(contentsOf: data)
        return out
    }

    private static func mpiEncode(_ bytes: [UInt8]) -> [UInt8] {
        var leadingZeros = 0
        for b in bytes {
            if b == 0 { leadingZeros += 8; continue }
            var bb = b
            while (bb & 0x80) == 0 { leadingZeros += 1; bb <<= 1 }
            break
        }
        let bitLen = UInt16(bytes.count * 8 - leadingZeros)
        var out: [UInt8] = [UInt8((bitLen >> 8) & 0xFF), UInt8(bitLen & 0xFF)]
        // RFC 4880 3.2: the value carries no leading zero octets, so its byte
        // count matches ceil(bitLen / 8). Appending the full input here left
        // an Ed25519 R or S with a high zero octet self-inconsistent, and a
        // reader misaligned on the next MPI: roughly one v4 self-cert, UID
        // cert or expiration re-cert in 128 failed to verify (gpg included).
        // Same fix as SigningService.mpiEncode and CardSigner.mpiEncode.
        var value = bytes
        while value.first == 0 { value.removeFirst() }
        out.append(contentsOf: value)
        return out
    }

    private static func buildNewFormatPacket(tag: UInt8, body: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [0xC0 | (tag & 0x3F)]
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
        out.append(contentsOf: body)
        return out
    }

    private static func u16be(_ v: UInt16) -> [UInt8] { [UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)] }
    private static func u32be(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }

    /// 40-char hex fingerprint → 20 bytes. Returns nil on odd/invalid input.
    private static func bytesFromHex(_ hex: String) -> [UInt8]? {
        let chars = Array(hex)
        guard chars.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        var i = 0
        while i < chars.count {
            guard let b = UInt8(String(chars[i...i+1]), radix: 16) else { return nil }
            out.append(b); i += 2
        }
        return out
    }

    // Header-free PUBLIC KEY BLOCK armor (also avoids the ObjectivePGP header leak
    // tracked as a Phase 6 open item — edited keys come out clean).
    /// Lifted verbatim from the app's SigningService.dearmor so the core takes no
    /// SigningService dependency. Strips the armor BEGIN/END lines, headers and
    /// CRC24 line, then base64-decodes the body.
    private static func dearmor(_ armored: String) throws -> [UInt8] {
        let normalized = armored.replacingOccurrences(of: "\r\n", with: "\n")
        let lines = normalized.components(separatedBy: "\n")

        var inBody = false
        var headersDone = false
        var body = ""

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if !inBody {
                if trimmed.hasPrefix("-----BEGIN PGP") { inBody = true }
                continue
            }
            if trimmed.hasPrefix("-----END PGP") { break }
            if trimmed.hasPrefix("=") { continue }              // CRC24 line
            if trimmed.isEmpty {
                headersDone = true
                continue
            }
            if !headersDone, trimmed.contains(":") { continue } // armor header

            headersDone = true
            body.append(trimmed)
        }

        guard let data = Data(base64Encoded: body) else {
            throw NSError(
                domain: "PGPony.KeyExpirationEditor",
                code: 100,
                userInfo: [NSLocalizedDescriptionKey: "Base64 decode failed"]
            )
        }
        return Array(data)
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
