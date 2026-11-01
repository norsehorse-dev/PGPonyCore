// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CertificationService.swift
// PGPony
//
// 8.4.0 build 4 (Android 4.7.0 item 31): certify other people's User IDs with
// your own key, like gpg's --sign-key and --lsign-key, and read back who
// certified a key.
//
// A certification is a 0x10 to 0x13 signature by the certifier's primary over
// the target's primary key and one User ID (RFC 9580 5.2.1, 5.2.4), at the
// level gpg's --ask-cert-level offers: no claim (0x10, gpg's default),
// persona (0x11), casual (0x12), positive (0x13). Hashed: creation time,
// issuer fingerprint, an optional signature expiry (critical), and for a
// local-only certification Exportable Certification = false (critical).
// Revoking one you made is a 0x30 over the same User ID (reason: none).
//
// Framing follows the signature's version: a v4 signature hashes the target
// key as 0x99 | len2, a v6 one as 0x9B | len4 after its salt; the User ID is
// 0xB4 | len4 either way. Reading back, both the signature-version and the
// key-version framing are tried, as CertificateValidator does for bindings.
//
// Certifiers: a v4 Ed25519 (algorithm 22) or RSA primary, or a v6 Ed25519
// primary, whose secret is here; or a v4 Ed25519 or RSA primary in a
// hardware key's signature slot, signed on the card after the PIN
// (SHA-256, the hash the card path formats). Not offered, as on Android: a
// composite ML-DSA certifier or target, whose signatures Android's Bouncy
// Castle reader cannot load inside a classical certificate.
//
// 8.4.0 build 10 (plan 5m): a LibrePGP v5 Ed448 primary (GnuPG 2.4) certifies
// too, with a version 5 signature as gpg 2.4.4 makes one: SHA-512, issuer
// fingerprint version 5, no issuer key ID, and the target key framed by ITS
// version (0x99 | len2 for a v4 target, 0x9A | len4 for a v5 one). It
// certifies v4 and v5 targets; a v5 target takes only a v5 certifier, since
// how a v4 or v6 signature frames a v5 key differs between implementations.
//
// Exportable certifications go into the target's stored certificate, so
// sharing the key carries them. Local-only ones live in their own Keychain
// item per target (LocalCertificationStore, never synced), which no export,
// share, upload, QR code or backup reads.

import Foundation
import CryptoKit
import Security

enum CertificationService {

    // MARK: - Types

    /// gpg's --ask-cert-level choices, by signature type.
    enum Level: UInt8, CaseIterable, Identifiable {
        case noClaim = 0x10
        case persona = 0x11
        case casual = 0x12
        case positive = 0x13

        var id: UInt8 { rawValue }

        var displayName: String {
            switch self {
            case .noClaim: return String(localized: "No claim")
            case .persona: return String(localized: "Not checked")
            case .casual: return String(localized: "Casual check")
            case .positive: return String(localized: "Careful check")
            }
        }

        var explanation: String {
            switch self {
            case .noClaim: return String(localized: "Says nothing about how well you checked. GnuPG's default.")
            case .persona: return String(localized: "You did not check that this key belongs to this person.")
            case .casual: return String(localized: "You did a quick check, such as a call or a message you trust.")
            case .positive: return String(localized: "You checked carefully, such as in person with an ID.")
            }
        }
    }

    /// One certification made over `userId`: the complete tag-2 packet.
    struct Made: Codable, Equatable {
        let userId: String
        let packet: [UInt8]
    }

    /// How a certification checks out against its issuer.
    enum Status: Equatable {
        case verified
        case failed
        case signerUnknown
        case uncheckable
    }

    /// A third-party certification of one User ID, as Key Detail shows it.
    struct Certification: Identifiable, Equatable {
        let userId: String
        /// Uppercase hex; nil when the signature names only a key ID.
        let issuerFingerprint: String?
        /// Uppercase hex, 16 digits.
        let issuerKeyID: String
        let level: Level
        let created: Date
        let expires: Date?
        let exportable: Bool
        let isLocal: Bool
        let status: Status
        let revoked: Bool
        /// 8.4.0 build 6 (Android 4.7.0 item 59): a trust signature (gpg
        /// tsign, RFC 9580 5.2.3.21) also says the certifier trusts this key
        /// to introduce others: the depth and the amount (60 partial, 120
        /// full in gpg). Nil when the certification carries none.
        var trustDepth: Int? = nil
        var trustAmount: Int? = nil
        /// True when a Regular Expression subpacket limits that trust.
        var trustLimited = false

        var id: String { userId + "|" + (issuerFingerprint ?? issuerKeyID) + (isLocal ? "|local" : "") }

        func isExpired(at date: Date = Date()) -> Bool {
            expires.map { date >= $0 } ?? false
        }
    }

    enum CertifyError: LocalizedError, Equatable {
        case selfCertification
        case noUserIds
        case cannotCertify
        case unsupportedTarget
        case cardMismatch
        case unreadableKey

        var errorDescription: String? {
            switch self {
            case .selfCertification: return String(localized: "A key cannot certify itself.")
            case .noUserIds: return String(localized: "Pick at least one User ID of this key to certify.")
            case .cannotCertify: return String(localized: "This key cannot certify other keys.")
            case .unsupportedTarget: return String(localized: "PGPony cannot certify this kind of key yet.")
            case .cardMismatch: return String(localized: "This hardware key does not hold the key chosen to certify with.")
            case .unreadableKey: return String(localized: "Could not read this key.")
            }
        }
    }

    // MARK: - Who may certify

    /// The primary key packet body of a public (tag 6) or secret (tag 5) ring.
    static func primaryBody(_ data: Data) -> [UInt8]? {
        guard let packets = try? OpenPGPPacketParser.parsePackets(data: Array(data)) else { return nil }
        guard let primary = packets.first(where: { $0.tag == 6 || $0.tag == 5 }), primary.body.count > 5 else { return nil }
        if primary.tag == 6 { return primary.body }
        return publicPrefix(ofSecretBody: primary.body)
    }

    /// True when a certifier with this public primary can sign in software here.
    static func softwareAlgorithmSupported(primaryBody body: [UInt8]) -> Bool {
        guard body.count > 5 else { return false }
        switch (body[0], body[5]) {
        case (4, 22): return isLegacyEd25519(body)
        case (4, 1), (4, 3): return true
        case (6, 27): return true
        // 8.4.0 build 9 (plan 5l): an RFC 9580 Ed448 primary, v6 certifications.
        case (6, 28): return true
        // 8.4.0 build 10 (plan 5m): a LibrePGP v5 Ed448 primary, v5 certifications.
        case (5, 22): return OpenPGP448.isEd448(keyBody: body)
        default: return false
        }
    }

    /// True when a card whose signature slot holds this primary can certify.
    static func cardAlgorithmSupported(primaryBody body: [UInt8]) -> Bool {
        guard body.count > 5, body[0] == 4 else { return false }
        switch body[5] {
        case 22: return isLegacyEd25519(body)
        case 1, 3: return true
        default: return false
        }
    }

    /// False when the newest self-signature that carries key flags says the
    /// primary may not certify. A primary without key flags certifies, as
    /// OpenPGP has always assumed.
    static func primaryMayCertify(publicKeyData data: Data) -> Bool {
        guard let packets = try? OpenPGPPacketParser.parsePackets(data: Array(data)),
              let primary = packets.first(where: { $0.tag == 6 })?.body else { return false }
        var newest: (time: Date, flags: UInt8)?
        var inSubkey = false
        for packet in packets {
            switch packet.tag {
            case 14: inSubkey = true
            case 13, 17: inSubkey = false
            case 2 where !inSubkey:
                guard let sig = try? OpenPGPPacketParser.parseSignaturePacket(body: packet.body),
                      [0x10, 0x11, 0x12, 0x13, 0x1F].contains(sig.signatureType),
                      CertificateValidator.issuedBy(primaryBody: primary, sig),
                      let flags = sig.hashedSubpackets.first(where: { $0.type == 27 })?.data.first else { continue }
                let time = sig.creationTime ?? .distantPast
                if newest == nil || time >= newest!.time { newest = (time, flags) }
            default:
                break
            }
        }
        return newest.map { $0.flags & 0x01 != 0 } ?? true
    }

    /// True when `body` is a key PGPony may certify: v4 or v6, not composite,
    /// or (8.4.0 build 10, plan 5m) a LibrePGP v5 Ed448 key.
    static func targetSupported(primaryBody body: [UInt8]) -> Bool {
        guard body.count > 5 else { return false }
        if body[0] == 5 { return OpenPGP448.isEd448(keyBody: body) }
        guard body[0] == 4 || body[0] == 6 else { return false }
        return body[5] != 30 && body[5] != 31
    }

    /// 8.4.0 build 10 (plan 5m): whether this certifier may sign over this
    /// target. A v5 certifier certifies v4 and v5 keys (gpg 2.4.4 reads
    /// both); a v5 target takes only a v5 certifier.
    static func pairSupported(certifierBody: [UInt8], targetBody: [UInt8]) -> Bool {
        guard let c = certifierBody.first, let t = targetBody.first else { return false }
        if c == 5 { return t == 4 || t == 5 }
        return t != 5
    }

    // MARK: - Certify

    /// Certify `userIds` on `targetPublic` with the software key pair whose
    /// rings are `certifierSecret` and `certifierPublic`. One signature per
    /// User ID. Passphrase errors surface as PGPServiceError.
    static func certify(
        certifierSecret: Data,
        certifierPublic: Data,
        passphrase: String?,
        targetPublic: Data,
        userIds: [String],
        level: Level,
        expiresIn: TimeInterval?,
        exportable: Bool,
        now: Date = Date()
    ) async throws -> [Made] {
        let (certifierBody, target, uids) = try prepare(certifierPublic: certifierPublic, targetPublic: targetPublic, userIds: userIds)
        guard softwareAlgorithmSupported(primaryBody: certifierBody), primaryMayCertify(publicKeyData: certifierPublic) else {
            throw CertifyError.cannotCertify
        }
        let signer = try unlock(certifierSecret: certifierSecret, certifierBody: certifierBody, passphrase: passphrase)
        var out: [Made] = []
        for (raw, bytes) in uids {
            let hashed = certificationSubpackets(certifierBody: certifierBody, now: now, expiresIn: expiresIn, exportable: exportable)
            let packet = try await sign(signer: signer, certifierBody: certifierBody, targetBody: target,
                                        uid: bytes, sigType: level.rawValue, hashed: hashed)
            out.append(Made(userId: raw, packet: packet))
        }
        return out
    }

    /// Certify on the hardware key in `service` (connected, PIN not yet
    /// sent). Its signature slot must hold `certifierPublic`'s primary; that
    /// is checked before the PIN goes to the card.
    static func certifyOnCard(
        service: OpenPGPCardService,
        pin: String,
        certifierPublic: Data,
        targetPublic: Data,
        userIds: [String],
        level: Level,
        expiresIn: TimeInterval?,
        exportable: Bool,
        now: Date = Date()
    ) async throws -> [Made] {
        let (certifierBody, target, uids) = try prepare(certifierPublic: certifierPublic, targetPublic: targetPublic, userIds: userIds)
        guard cardAlgorithmSupported(primaryBody: certifierBody), primaryMayCertify(publicKeyData: certifierPublic) else {
            throw CertifyError.cannotCertify
        }
        let algorithm = try await requireCardHolds(service: service, certifierBody: certifierBody)
        var out: [Made] = []
        for (raw, bytes) in uids {
            let hashed = certificationSubpackets(certifierBody: certifierBody, now: now, expiresIn: expiresIn, exportable: exportable)
            let packet = try await signOnCard(service: service, pin: pin, algorithm: algorithm, certifierBody: certifierBody,
                                              targetBody: target, uid: bytes, sigType: level.rawValue, hashed: hashed)
            out.append(Made(userId: raw, packet: packet))
        }
        return out
    }

    // MARK: - Revoke

    /// A 0x30 revoking the software certifier's certification of `userId`.
    static func revoke(
        certifierSecret: Data,
        certifierPublic: Data,
        passphrase: String?,
        targetPublic: Data,
        userId: String,
        now: Date = Date()
    ) async throws -> Made {
        let (certifierBody, target, uids) = try prepare(certifierPublic: certifierPublic, targetPublic: targetPublic, userIds: [userId])
        guard softwareAlgorithmSupported(primaryBody: certifierBody) else { throw CertifyError.cannotCertify }
        let signer = try unlock(certifierSecret: certifierSecret, certifierBody: certifierBody, passphrase: passphrase)
        let packet = try await sign(signer: signer, certifierBody: certifierBody, targetBody: target,
                                    uid: uids[0].bytes, sigType: 0x30,
                                    hashed: revocationSubpackets(certifierBody: certifierBody, now: now))
        return Made(userId: userId, packet: packet)
    }

    /// `revoke`, signed on the hardware key in `service`.
    static func revokeOnCard(
        service: OpenPGPCardService,
        pin: String,
        certifierPublic: Data,
        targetPublic: Data,
        userId: String,
        now: Date = Date()
    ) async throws -> Made {
        let (certifierBody, target, uids) = try prepare(certifierPublic: certifierPublic, targetPublic: targetPublic, userIds: [userId])
        guard cardAlgorithmSupported(primaryBody: certifierBody) else { throw CertifyError.cannotCertify }
        let algorithm = try await requireCardHolds(service: service, certifierBody: certifierBody)
        let packet = try await signOnCard(service: service, pin: pin, algorithm: algorithm, certifierBody: certifierBody,
                                          targetBody: target, uid: uids[0].bytes, sigType: 0x30,
                                          hashed: revocationSubpackets(certifierBody: certifierBody, now: now))
        return Made(userId: userId, packet: packet)
    }

    // MARK: - Into the certificate

    /// `targetPublic` with each signature in `made` placed after its User
    /// ID's signatures. Every other packet keeps its body.
    static func adding(_ made: [Made], to targetPublic: Data) throws -> Data {
        let packets = try OpenPGPPacketParser.parsePackets(data: Array(targetPublic))
        var byUid: [String: [[UInt8]]] = [:]
        for m in made { byUid[m.userId, default: []].append(m.packet) }
        var out: [UInt8] = []
        var pending: [[UInt8]] = []
        func flush() {
            for p in pending { out += p }
            pending = []
        }
        for packet in packets {
            if packet.tag != 2 { flush() }
            out += newFormatPacket(tag: packet.tag, body: packet.body)
            if packet.tag == 13 {
                let raw = String(decoding: packet.body, as: UTF8.self)
                if let sigs = byUid.removeValue(forKey: raw) { pending = sigs }
            }
        }
        flush()
        guard byUid.isEmpty else { throw CertifyError.noUserIds }
        return Data(out)
    }

    /// True when the signature packet carries Exportable Certification = false.
    static func isLocalOnly(_ sig: OpenPGPPacketParser.ParsedSignature) -> Bool {
        sig.hashedSubpackets.first(where: { $0.type == 4 })?.data.first == 0
    }

    // MARK: - Reading back

    /// Every third-party certification of `targetPublic`'s User IDs, from the
    /// certificate and from `local` (local-only ones), newest per issuer and
    /// User ID. `issuer` returns the public ring of the key with that
    /// fingerprint (uppercase hex) or long key ID (16 hex digits), or nil when
    /// it is not in the keyring.
    static func certifications(
        targetPublic: Data,
        local: [Made],
        issuer: (_ fingerprint: String?, _ keyID: String) -> Data?
    ) -> [Certification] {
        guard let packets = try? OpenPGPPacketParser.parsePackets(data: Array(targetPublic)),
              let primary = packets.first(where: { $0.tag == 6 })?.body else { return [] }

        struct Entry { let sig: OpenPGPPacketParser.ParsedSignature; let isLocal: Bool }
        var order: [(raw: String, bytes: [UInt8])] = []
        var sigsByUid: [String: [Entry]] = [:]
        var current: String?
        for packet in packets {
            switch packet.tag {
            case 13:
                let raw = String(decoding: packet.body, as: UTF8.self)
                if sigsByUid[raw] == nil { order.append((raw, packet.body)); sigsByUid[raw] = [] }
                current = raw
            case 2:
                guard let uid = current, let sig = try? OpenPGPPacketParser.parseSignaturePacket(body: packet.body) else { break }
                sigsByUid[uid]?.append(Entry(sig: sig, isLocal: false))
            default:
                current = nil
            }
        }
        for m in local {
            guard sigsByUid[m.userId] != nil,
                  let parsed = try? OpenPGPPacketParser.parsePackets(data: m.packet).first,
                  parsed.tag == 2,
                  let sig = try? OpenPGPPacketParser.parseSignaturePacket(body: parsed.body) else { continue }
            sigsByUid[m.userId]?.append(Entry(sig: sig, isLocal: true))
        }

        var out: [Certification] = []
        for (raw, bytes) in order {
            let entries = (sigsByUid[raw] ?? []).filter {
                !CertificateValidator.issuedBy(primaryBody: primary, $0.sig)
                    && ($0.sig.issuerFingerprint != nil || $0.sig.issuerKeyID != nil)
            }
            var groups: [String: [Entry]] = [:]
            var groupOrder: [String] = []
            for e in entries {
                let k = groupKey(e.sig)
                if groups[k] == nil { groupOrder.append(k) }
                groups[k, default: []].append(e)
            }
            for k in groupOrder {
                let group = groups[k] ?? []
                guard let newest = group
                    .filter({ Level(rawValue: $0.sig.signatureType) != nil })
                    .max(by: { ($0.sig.creationTime ?? .distantPast) < ($1.sig.creationTime ?? .distantPast) }) else { continue }
                let cert = newest.sig
                let fp = cert.issuerFingerprint.map(hex)
                let keyID = cert.issuerKeyID.map(hex) ?? ""
                let signerBody = issuer(fp, keyID).flatMap(primaryBody)
                let status: Status
                if let signerBody {
                    switch verdict(cert, signerBody: signerBody, targetBody: primary, uid: bytes) {
                    case .valid: status = .verified
                    case .invalid: status = .failed
                    case .uncheckable: status = .uncheckable
                    }
                } else {
                    status = .signerUnknown
                }
                let created = cert.creationTime ?? .distantPast
                let trustData: [UInt8] = cert.hashedSubpackets.first(where: { $0.type == 5 })?.data ?? []
                let trust: [UInt8]? = trustData.count >= 2 ? Array(trustData.prefix(2)) : nil
                let revoked = signerBody.map { body in
                    group.contains { e in
                        e.sig.signatureType == 0x30
                            && (e.sig.creationTime ?? .distantPast) >= created
                            && verdict(e.sig, signerBody: body, targetBody: primary, uid: bytes) == .valid
                    }
                } ?? false
                out.append(Certification(
                    userId: raw,
                    issuerFingerprint: fp,
                    issuerKeyID: keyID,
                    level: Level(rawValue: cert.signatureType) ?? .noClaim,
                    created: created,
                    expires: expirySeconds(cert).map { created.addingTimeInterval(TimeInterval($0)) },
                    exportable: !isLocalOnly(cert),
                    isLocal: newest.isLocal,
                    status: status,
                    revoked: revoked,
                    trustDepth: trust.map { Int($0[0]) },
                    trustAmount: trust.map { Int($0[1]) },
                    trustLimited: trust != nil && cert.hashedSubpackets.contains { $0.type == 6 }
                ))
            }
        }
        return out
    }

    // MARK: - Internals

    private enum Signer {
        case ed25519(Ed25519SigningInfo)
        case rsa(RSASigningInfo)
        /// 8.4.0 build 10 (plan 5m): a LibrePGP v5 Ed448 primary.
        case ed448(Ed448SigningKey)
    }

    private static func prepare(certifierPublic: Data, targetPublic: Data, userIds: [String])
        throws -> (certifier: [UInt8], target: [UInt8], uids: [(raw: String, bytes: [UInt8])]) {
        guard let certifier = primaryBody(certifierPublic) else { throw CertifyError.cannotCertify }
        guard let packets = try? OpenPGPPacketParser.parsePackets(data: Array(targetPublic)),
              let target = packets.first(where: { $0.tag == 6 })?.body else { throw CertifyError.unreadableKey }
        guard targetSupported(primaryBody: target),
              pairSupported(certifierBody: certifier, targetBody: target) else { throw CertifyError.unsupportedTarget }
        if CertificateValidator.fingerprint(ofKeyBody: certifier) == CertificateValidator.fingerprint(ofKeyBody: target) {
            throw CertifyError.selfCertification
        }
        let available = packets.filter { $0.tag == 13 }.map { (raw: String(decoding: $0.body, as: UTF8.self), bytes: $0.body) }
        var picked: [(raw: String, bytes: [UInt8])] = []
        for id in userIds {
            guard let match = available.first(where: { $0.raw == id }) else { throw CertifyError.noUserIds }
            if !picked.contains(where: { $0.raw == id }) { picked.append(match) }
        }
        guard !picked.isEmpty else { throw CertifyError.noUserIds }
        return (certifier, target, picked)
    }

    private static func unlock(certifierSecret: Data, certifierBody: [UInt8], passphrase: String?) throws -> Signer {
        do {
            // 8.4.0 build 10 (plan 5m): a LibrePGP v5 Ed448 primary unlocks
            // through OpenPGP448; the v4 extractor keeps refusing it.
            if certifierBody[0] == 5 {
                guard let ed = try OpenPGP448.v5PrimaryCertificationKey(
                        secretRing: Array(certifierSecret), passphrase: passphrase),
                      ed.fingerprint == CertificateValidator.fingerprint(ofKeyBody: certifierBody) else {
                    throw CertifyError.cannotCertify
                }
                return .ed448(ed)
            }
            if certifierBody[0] == 4, certifierBody[5] == 1 || certifierBody[5] == 3 {
                return .rsa(try PGPService.shared.extractPrimaryRSACertificationKey(fromSecretKeyData: certifierSecret, passphrase: passphrase))
            }
            let info = try PGPService.shared.extractPrimaryCertificationKey(fromSecretKeyData: certifierSecret, passphrase: passphrase)
            guard info.composite == nil else { throw CertifyError.cannotCertify }
            return .ed25519(info)
        } catch let e as PGPServiceError {
            switch e {
            case .passphraseRequired, .invalidPassphrase: throw e
            default: throw CertifyError.cannotCertify
            }
        }
    }

    private static func fingerprintSubpacket(_ certifierBody: [UInt8]) -> [UInt8] {
        buildSubpacket(type: 33, data: [certifierBody[0]] + CertificateValidator.fingerprint(ofKeyBody: certifierBody))
    }

    private static func creationSubpacket(_ certifierBody: [UInt8], _ now: Date) -> [UInt8] {
        buildSubpacket(type: certifierBody[0] == 6 ? (2 | 0x80) : 2, data: u32be(UInt32(now.timeIntervalSince1970)))
    }

    static func certificationSubpackets(certifierBody: [UInt8], now: Date, expiresIn: TimeInterval?, exportable: Bool) -> [UInt8] {
        var out = creationSubpacket(certifierBody, now) + fingerprintSubpacket(certifierBody)
        if let expiresIn, expiresIn >= 1 {
            out += buildSubpacket(type: 3 | 0x80, data: u32be(UInt32(min(expiresIn, Double(UInt32.max)))))
        }
        if !exportable {
            out += buildSubpacket(type: 4 | 0x80, data: [0])
        }
        return out
    }

    private static func revocationSubpackets(certifierBody: [UInt8], now: Date) -> [UInt8] {
        creationSubpacket(certifierBody, now) + fingerprintSubpacket(certifierBody) + buildSubpacket(type: 29, data: [0x00])
    }

    private static func unhashed(_ certifierBody: [UInt8]) -> [UInt8] {
        guard certifierBody[0] == 4 else { return [] }
        return buildSubpacket(type: 16, data: Array(CertificateValidator.fingerprint(ofKeyBody: certifierBody).suffix(8)))
    }

    private static func sign(
        signer: Signer,
        certifierBody: [UInt8],
        targetBody: [UInt8],
        uid: [UInt8],
        sigType: UInt8,
        hashed: [UInt8]
    ) async throws -> [UInt8] {
        let identity = CertificateValidator.frameIdentity(0xB4, uid)
        // 8.4.0 build 10 (plan 5m): a v5 certification, the target framed by
        // its own version, as gpg 2.4.4 hashes it.
        if certifierBody[0] == 5 {
            guard case .ed448(let key) = signer else { throw CertifyError.cannotCertify }
            let body = try OpenPGP448.keySignatureBody(
                key: key, signatureType: sigType,
                document: OpenPGP448.frameForKeySignature(targetBody, signatureVersion: 5) + identity,
                hashedSubpackets: hashed)
            return newFormatPacket(tag: 2, body: body)
        }
        if certifierBody[0] == 6 {
            guard case .ed25519(let info) = signer else { throw CertifyError.cannotCertify }
            let body = try V6KeyGenerator.assembleV6Signature(
                signer: V6SignatureKey(info),
                sigType: sigType,
                documentHashChunks: CertificateValidator.frameKey(targetBody, signatureVersion: 6) + identity,
                hashedSubpackets: hashed,
                unhashedSubpackets: []
            )
            return newFormatPacket(tag: 2, body: body)
        }
        switch signer {
        case .ed25519(let info):
            let key = info.privateKey
            return try await KeyExpirationEditor.signKeyTargeted(
                primaryBody: targetBody, document2: identity, sigType: sigType, algorithm: .eddsa,
                hashedSubpackets: hashed, unhashedSubpackets: unhashed(certifierBody),
                sign: { digest in Array(try key.signature(for: Data(digest))) })
        case .rsa(let rsa):
            let key = rsa.privateKey
            return try await KeyExpirationEditor.signKeyTargeted(
                primaryBody: targetBody, document2: identity, sigType: sigType, algorithm: .rsa,
                hashedSubpackets: hashed, unhashedSubpackets: unhashed(certifierBody),
                sign: { digest in
                    var err: Unmanaged<CFError>?
                    guard let sig = SecKeyCreateSignature(key, .rsaSignatureDigestPKCS1v15SHA256, Data(digest) as CFData, &err) as Data? else {
                        throw CertifyError.cannotCertify
                    }
                    return Array(sig)
                })
        case .ed448:
            // A v5 certifier returned above; it never reaches the v4 builder.
            throw CertifyError.cannotCertify
        }
    }

    private static func requireCardHolds(service: OpenPGPCardService, certifierBody: [UInt8]) async throws -> CardSignatureAlgorithm {
        let info = try await service.readCardInfo()
        let want = hex(CertificateValidator.fingerprint(ofKeyBody: certifierBody))
        let got = info.signFingerprint.map { KeyringDeduplicationService.normalize($0).uppercased() }
        guard got == want, let algorithm = info.signatureAlgorithm else { throw CertifyError.cardMismatch }
        return algorithm
    }

    private static func signOnCard(
        service: OpenPGPCardService,
        pin: String,
        algorithm: CardSignatureAlgorithm,
        certifierBody: [UInt8],
        targetBody: [UInt8],
        uid: [UInt8],
        sigType: UInt8,
        hashed: [UInt8]
    ) async throws -> [UInt8] {
        try await KeyExpirationEditor.signKeyTargeted(
            primaryBody: targetBody,
            document2: CertificateValidator.frameIdentity(0xB4, uid),
            sigType: sigType,
            algorithm: algorithm,
            hashedSubpackets: hashed,
            unhashedSubpackets: unhashed(certifierBody),
            sign: { digest in
                try await service.verify(pin: pin, mode: .signing)
                // 8.4.0 build 10 (plan 5m): EdDSA, RSA and ECDSA through one helper.
                return try await service.signDigest(digest, algorithm: algorithm)
            })
    }

    /// The signature over (target, uid) by the key whose body is `signerBody`,
    /// framed by the signature's version and, failing that, by the key's.
    private static func verdict(
        _ sig: OpenPGPPacketParser.ParsedSignature,
        signerBody: [UInt8],
        targetBody: [UInt8],
        uid: [UInt8]
    ) -> CertificateValidator.Verdict {
        let identity = CertificateValidator.frameIdentity(0xB4, uid)
        let bySignature = CertificateValidator.frameKey(targetBody, signatureVersion: sig.version) + identity
        let first = CertificateValidator.verify(sig, signerBody: signerBody, document: bySignature)
        guard first == .invalid, let keyVersion = targetBody.first, keyVersion != sig.version else { return first }
        let byKey = CertificateValidator.frameKey(targetBody, signatureVersion: keyVersion) + identity
        return CertificateValidator.verify(sig, signerBody: signerBody, document: byKey)
    }

    private static func groupKey(_ sig: OpenPGPPacketParser.ParsedSignature) -> String {
        if let fp = sig.issuerFingerprint { return hex(fp) }
        return hex(sig.issuerKeyID ?? [])
    }

    private static func expirySeconds(_ sig: OpenPGPPacketParser.ParsedSignature) -> UInt32? {
        guard let d = sig.hashedSubpackets.first(where: { $0.type == 3 })?.data, d.count == 4 else { return nil }
        let v = UInt32(d[0]) << 24 | UInt32(d[1]) << 16 | UInt32(d[2]) << 8 | UInt32(d[3])
        return v == 0 ? nil : v
    }

    private static func isLegacyEd25519(_ body: [UInt8]) -> Bool {
        let oid: [UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]
        guard body.count > 6 + oid.count, Int(body[6]) == oid.count else { return false }
        return Array(body[7..<(7 + oid.count)]) == oid
    }

    /// The public part of a secret key body: version, creation time,
    /// algorithm and public material (v6 carries its length; v4 is read by
    /// the shared parser).
    private static func publicPrefix(ofSecretBody body: [UInt8]) -> [UInt8]? {
        if body.first == 6 {
            guard body.count >= 10 else { return nil }
            let n = Int(body[6]) << 24 | Int(body[7]) << 16 | Int(body[8]) << 8 | Int(body[9])
            guard 10 + n <= body.count else { return nil }
            return Array(body[0..<(10 + n)])
        }
        return OpenPGPPacketParser.v4PublicPrefix(secretBody: body)
    }

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }

    private static func u32be(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }

    private static func lengthOctets(_ n: Int) -> [UInt8] {
        if n < 192 { return [UInt8(n)] }
        if n < 8384 {
            let m = n - 192
            return [UInt8((m >> 8) + 192), UInt8(m & 0xFF)]
        }
        return [0xFF] + u32be(UInt32(n))
    }

    static func buildSubpacket(type: UInt8, data: [UInt8]) -> [UInt8] {
        lengthOctets(data.count + 1) + [type] + data
    }

    static func newFormatPacket(tag: UInt8, body: [UInt8]) -> [UInt8] {
        [0xC0 | tag] + lengthOctets(body.count) + body
    }
}

// MARK: - Local-only certifications

// CORE NOTE: the app also defines LocalCertificationStore here, which keeps
// local (non-exportable) certifications in the Keychain. Storage is
// application logic, so it stays in the app.
