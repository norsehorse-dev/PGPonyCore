// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// SelfSignatureRefresh.swift
// PGPony
//
// 8.4.0 build 7 (Android 4.7.0 items 51 and 66): Refresh Self-Signatures.
//
// Signs a key pair's User ID certifications and subkey bindings again with
// SHA-256, each keeping the expiry it has (the Key Expiration Time subpacket
// is relative to the key's own creation, so carrying it forward keeps the
// date). Nothing expires or comes back to life: an expired subkey stays
// expired, a revoked User ID or subkey keeps its old signatures.
//
// What gets signed again:
//   - every User ID that is not revoked and whose newest self-certification
//     verifies (or verifies apart from a SHA-1 hash, see below);
//   - every subkey that is not revoked and whose newest binding by the
//     primary verifies the same way. A signing subkey also needs a fresh
//     back-signature (0x19) made by the subkey itself, so its secret has to be
//     on this device; one whose secret is not here (a GnuPG stub, or missing)
//     is passed over and keeps its old binding;
//   - a subkey whose binding used SHA-1, which this device does not accept for
//     EdDSA, comes back only when its secret is on this device. The SHA-1
//     risk is a binding forged over a subkey someone else controls, and that
//     subkey's secret would not be in the owner's key pair;
//   - a subkey the stored certificate lacks but the stored secret ring still
//     carries (real secret material, a binding by the primary that verifies
//     apart from its hash, not revoked) is put back into the certificate, at
//     the position it has in the secret ring so both rings keep one order.
// A signature that does not verify at all is never signed again: that would
// turn a grafted User ID or subkey into a real one.
//
// Scope: v4 software key pairs with an Ed25519 or RSA primary, the shapes
// UserIdService and ClassicalSubkeyGen sign with. 8.4.0 build 10 (plan 5m):
// and key pairs with an Ed448 primary, LibrePGP v5 or RFC 9580 v6, which
// Ed448KeyEditor signs again (SHA-512, v5 or v6 signatures, every expiry
// kept, a direct key signature included). The secret ring must hold
// the primary's secret (not an offline stub). Everything here is synchronous
// so the caller can run it through runOffMainThread.

import Foundation
import CryptoKit
import Security

enum SelfSignatureRefresh {

    struct Result {
        let publicKeyData: Data
        let secretKeyData: Data
        let armoredPublicKey: String
        /// User ID certifications signed again.
        let userIDsResigned: Int
        /// Subkey bindings signed again, the restored ones included.
        let subkeysResigned: Int
        /// Lowercase hex fingerprints of subkeys that were out of use and are
        /// back: put back from the secret ring, or bound only with SHA-1.
        let restoredSubkeys: [String]
        /// Lowercase hex fingerprints of signing subkeys passed over because
        /// no back-signature could be made on this device.
        let passedOver: [String]
    }

    enum RefreshError: LocalizedError, Equatable {
        case unsupportedKey
        case primaryNotOnDevice
        case noPrimaryKeyPacket
        case nothingToSign
        case signatureFailed

        var errorDescription: String? {
            switch self {
            case .unsupportedKey:
                return String(localized: "Refresh Self-Signatures works on v4 Ed25519 and RSA key pairs.")
            case .primaryNotOnDevice:
                return String(localized: "The primary key's secret is not on this device, so its self-signatures can't be signed again.")
            case .noPrimaryKeyPacket:
                return String(localized: "Could not locate the primary key packet in this key.")
            case .nothingToSign:
                return String(localized: "No User ID or subkey on this key has a self-signature that could be checked, so nothing was signed again.")
            case .signatureFailed:
                return String(localized: "A signature could not be made.")
            }
        }
    }

    // MARK: - Entry points

    /// Whether `publicKeyData` (binary) has a primary this refresh can sign
    /// with: v4 Ed25519 (EdDSA legacy) or RSA. For gating the menu item.
    static func supportsPrimary(publicKeyData: Data) -> Bool {
        guard let packets = try? OpenPGPPacketParser.parsePackets(data: Array(publicKeyData)),
              let primary = packets.first(where: { $0.tag == 6 }) else { return false }
        // 8.4.0 build 10 (plan 5m): an Ed448 primary, v5 or v6.
        return supports(primaryBody: primary.body) || Ed448KeyEditor.supports(primaryBody: primary.body)
    }

    /// Re-sign the self-signatures of the key pair in (`publicKeyData`,
    /// `secretKeyData`), both binary. `passphrase` unlocks the primary and any
    /// signing subkey whose back-signature is made again. Throws the
    /// passphrase errors of PGPService unchanged.
    static func refresh(
        publicKeyData: Data,
        secretKeyData: Data,
        passphrase: String?,
        now: Date = Date()
    ) throws -> Result {
        let pubPackets = try OpenPGPPacketParser.parsePackets(data: Array(publicKeyData))
        let secPackets = try OpenPGPPacketParser.parsePackets(data: Array(secretKeyData))
        guard let primaryBody = pubPackets.first(where: { $0.tag == 6 })?.body else {
            throw RefreshError.noPrimaryKeyPacket
        }
        // 8.4.0 build 10 (plan 5m): an Ed448 primary (v5 or v6) is signed
        // again by Ed448KeyEditor, every expiry kept.
        if Ed448KeyEditor.supports(primaryBody: primaryBody) {
            return try refreshEd448(publicKeyData: publicKeyData, secretKeyData: secretKeyData,
                                    passphrase: passphrase, now: now)
        }
        guard supports(primaryBody: primaryBody) else { throw RefreshError.unsupportedKey }
        guard let primarySecret = secPackets.first(where: { $0.tag == 5 }) else {
            throw RefreshError.noPrimaryKeyPacket
        }
        if OpenPGPPacketParser.gnuStub(secretBody: primarySecret.body) != nil {
            throw RefreshError.primaryNotOnDevice
        }
        let primaryFP = OpenPGPPacketParser.computeV4Fingerprint(packetBody: primaryBody)
        let primaryKeyID = Array(primaryFP.suffix(8))
        let primarySigner = try signer(secretRing: secretKeyData, algorithm: primaryBody[5], passphrase: passphrase)
        let primaryFrame = CertificateValidator.frameKey(primaryBody, signatureVersion: 4)

        var pubBlocks = blocks(pubPackets)
        let secBlocks = blocks(secPackets)

        // Every new signature is newer than every self-signature already on
        // the key, so a verifier that picks the newest picks it.
        var newest: UInt32 = 0
        for packet in pubPackets where packet.tag == 2 {
            guard let sig = try? OpenPGPPacketParser.parseSignaturePacket(body: packet.body),
                  CertificateValidator.issuedBy(primaryBody: primaryBody, sig) else { continue }
            newest = max(newest, seconds(sig.creationTime))
        }
        let sigTime = max(UInt32(now.timeIntervalSince1970), newest &+ 1)

        // 1. User IDs.
        var newCerts: [[UInt8]: [UInt8]] = [:]
        for block in pubBlocks where block.key.tag == 13 {
            let sigs = selfSignatures(block, primaryBody: primaryBody)
            let certs = sigs.filter { (0x10...0x13).contains($0.signatureType) }
            let latestCert = certs.map { seconds($0.creationTime) }.max()
            let latestRevocation = sigs.filter { $0.signatureType == 0x30 }.map { seconds($0.creationTime) }.max()
            if let latestRevocation, latestRevocation >= (latestCert ?? 0) { continue }
            let document = primaryFrame + CertificateValidator.frameIdentity(0xB4, block.key.body)
            let ordered = certs.sorted { seconds($0.creationTime) > seconds($1.creationTime) }
            guard let base = ordered.first(where: { check($0, signerBody: primaryBody, document: document) != .invalid }) else {
                continue
            }
            var hashed = subpacket(2, u32be(sigTime))
            hashed += preserved(base.hashedSubpackets)
            hashed += subpacket(33, [4] + primaryFP)
            let body = try makeSignature(sigType: 0x13, signer: primarySigner, document: document,
                                         hashed: hashed, unhashed: subpacket(16, primaryKeyID))
            newCerts[block.key.body] = OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 2, body: body)
        }

        // 2. What the secret ring holds, by subkey fingerprint.
        struct HeldSecret {
            let publicBody: [UInt8]
            let secretBody: [UInt8]
            let isStub: Bool
            let signatures: [ParsedPacket]
        }
        var held: [String: HeldSecret] = [:]
        var secretOrder: [String] = []
        for block in secBlocks where block.key.tag == 7 {
            guard let prefix = OpenPGPPacketParser.v4PublicPrefix(secretBody: block.key.body) else { continue }
            let fp = hex(OpenPGPPacketParser.computeV4Fingerprint(packetBody: prefix))
            held[fp] = HeldSecret(publicBody: prefix, secretBody: block.key.body,
                                  isStub: OpenPGPPacketParser.gnuStub(secretBody: block.key.body) != nil,
                                  signatures: block.rest.filter { $0.tag == 2 })
            secretOrder.append(fp)
        }

        // 3. Put back subkeys the certificate lacks but the secret ring holds.
        var restored: [String] = []
        var publicFPs = pubBlocks.filter { $0.key.tag == 14 && $0.key.body.first == 4 }
            .map { hex(OpenPGPPacketParser.computeV4Fingerprint(packetBody: $0.key.body)) }
        for (index, fp) in secretOrder.enumerated() where !publicFPs.contains(fp) {
            guard let secret = held[fp], !secret.isStub else { continue }
            let candidate = Block(key: ParsedPacket(tag: 14, body: secret.publicBody), rest: secret.signatures)
            let sigs = selfSignatures(candidate, primaryBody: primaryBody)
            if sigs.contains(where: { $0.signatureType == 0x28 }) { continue }
            let document = primaryFrame + CertificateValidator.frameKey(secret.publicBody, signatureVersion: 4)
            guard sigs.contains(where: { $0.signatureType == 0x18 && check($0, signerBody: primaryBody, document: document) != .invalid }) else {
                continue
            }
            // Before the next subkey that both rings carry, else at the end.
            let following = secretOrder[(index + 1)...].first { publicFPs.contains($0) }
            if let following,
               let at = pubBlocks.firstIndex(where: { $0.key.tag == 14 && $0.key.body.first == 4
                   && hex(OpenPGPPacketParser.computeV4Fingerprint(packetBody: $0.key.body)) == following }) {
                pubBlocks.insert(candidate, at: at)
            } else {
                pubBlocks.append(candidate)
            }
            publicFPs.append(fp)
            restored.append(fp)
        }

        // 4. Subkey bindings.
        var newBindings: [String: [UInt8]] = [:]
        var passedOver: [String] = []
        for block in pubBlocks where block.key.tag == 14 && block.key.body.first == 4 {
            let subBody = block.key.body
            let fp = hex(OpenPGPPacketParser.computeV4Fingerprint(packetBody: subBody))
            let sigs = selfSignatures(block, primaryBody: primaryBody)
            if sigs.contains(where: { $0.signatureType == 0x28 }) { continue }
            let document = primaryFrame + CertificateValidator.frameKey(subBody, signatureVersion: 4)
            let ordered = sigs.filter { $0.signatureType == 0x18 }
                .sorted { seconds($0.creationTime) > seconds($1.creationTime) }
            let verdicts = ordered.map { ($0, check($0, signerBody: primaryBody, document: document)) }
            guard let picked = verdicts.first(where: { $0.1 == .valid })
                    ?? verdicts.first(where: { $0.1 == .weakHash }) else { continue }
            let base = picked.0
            let verdict = picked.1
            let secret = held[fp].flatMap { $0.isStub ? nil : $0 }
            // A subkey usable today only through a SHA-1 binding comes back
            // only when its secret is here.
            if verdict == .weakHash && secret == nil { continue }

            let flags = base.hashedSubpackets.first(where: { $0.type == 27 })?.data.first ?? 0
            var embedded: [UInt8]? = nil
            if flags & 0x02 != 0 {
                guard let secret,
                      let back = try? backSignature(secretBody: secret.secretBody, subkeyBody: subBody,
                                                    document: document, passphrase: passphrase, sigTime: sigTime) else {
                    passedOver.append(fp)
                    continue
                }
                embedded = back
            }
            var hashed = subpacket(2, u32be(sigTime))
            hashed += preserved(base.hashedSubpackets)
            hashed += subpacket(33, [4] + primaryFP)
            var unhashed = subpacket(16, primaryKeyID)
            if let embedded { unhashed += subpacket(32, embedded) }
            let body = try makeSignature(sigType: 0x18, signer: primarySigner, document: document,
                                         hashed: hashed, unhashed: unhashed)
            newBindings[fp] = OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 2, body: body)
            if verdict == .weakHash && !restored.contains(fp) { restored.append(fp) }
        }
        // A subkey put back whose binding could not be made again (a signing
        // subkey whose secret did not unlock) does not go back in.
        let unbound = restored.filter { newBindings[$0] == nil }
        if !unbound.isEmpty {
            pubBlocks.removeAll { block in
                block.key.tag == 14 && block.key.body.first == 4
                    && unbound.contains(hex(OpenPGPPacketParser.computeV4Fingerprint(packetBody: block.key.body)))
            }
            restored.removeAll { unbound.contains($0) }
            passedOver.removeAll { unbound.contains($0) }
        }

        guard !newCerts.isEmpty || !newBindings.isEmpty else { throw RefreshError.nothingToSign }

        let newPublic = splice(pubBlocks, subkeyTag: 14, primaryBody: primaryBody,
                               newCerts: newCerts, newBindings: newBindings)
        let newSecret = splice(secBlocks, subkeyTag: 7, primaryBody: primaryBody,
                               newCerts: newCerts, newBindings: newBindings)
        return Result(
            publicKeyData: Data(newPublic),
            secretKeyData: Data(newSecret),
            armoredPublicKey: PublicKeyBundle.armorPublicKeyBlock(newPublic),
            userIDsResigned: newCerts.count,
            subkeysResigned: newBindings.count,
            restoredSubkeys: restored,
            passedOver: passedOver
        )
    }

    /// 8.4.0 build 10 (plan 5m): Refresh Self-Signatures for an Ed448
    /// primary, its errors read as this file's.
    private static func refreshEd448(publicKeyData: Data, secretKeyData: Data, passphrase: String?,
                                     now: Date) throws -> Result {
        let result: Ed448KeyEditor.Result
        do {
            result = try Ed448KeyEditor.resign(publicKeyData: publicKeyData, secretKeyData: secretKeyData,
                                               passphrase: passphrase, expiry: .keep, now: now)
        } catch let e as Ed448KeyEditor.EditError {
            switch e {
            case .unsupportedKey: throw RefreshError.unsupportedKey
            case .noPrimaryKeyPacket: throw RefreshError.noPrimaryKeyPacket
            case .primaryNotOnDevice: throw RefreshError.primaryNotOnDevice
            case .nothingToSign, .noLiveUserID, .expiryBeforeCreation: throw RefreshError.nothingToSign
            }
        }
        return Result(
            publicKeyData: result.publicKeyData,
            secretKeyData: result.secretKeyData,
            armoredPublicKey: PublicKeyBundle.armorPublicKeyBlock(Array(result.publicKeyData)),
            userIDsResigned: result.userIDsResigned,
            subkeysResigned: result.subkeysResigned,
            restoredSubkeys: [],
            passedOver: result.passedOver
        )
    }

    // MARK: - Ring blocks

    /// A key or User ID packet and the packets that follow it up to the next
    /// one. Packets before the first key packet (none in a well-formed ring)
    /// ride in a block whose key is the first of them.
    private struct Block {
        let key: ParsedPacket
        var rest: [ParsedPacket]
    }

    private static let blockTags: Set<UInt8> = [5, 6, 7, 13, 14, 17]

    private static func blocks(_ packets: [ParsedPacket]) -> [Block] {
        var out: [Block] = []
        for packet in packets {
            if blockTags.contains(packet.tag) || out.isEmpty {
                out.append(Block(key: packet, rest: []))
            } else {
                out[out.count - 1].rest.append(packet)
            }
        }
        return out
    }

    private static func selfSignatures(_ block: Block, primaryBody: [UInt8]) -> [OpenPGPPacketParser.ParsedSignature] {
        block.rest.compactMap { packet in
            guard packet.tag == 2, let sig = try? OpenPGPPacketParser.parseSignaturePacket(body: packet.body),
                  CertificateValidator.issuedBy(primaryBody: primaryBody, sig) else { return nil }
            return sig
        }
    }

    /// Re-emit `blocks`, each User ID's self-certifications (0x10 to 0x13)
    /// and each subkey's bindings (0x18) replaced by the new one, in the
    /// place of the first one. Everything else passes through.
    private static func splice(
        _ blocks: [Block],
        subkeyTag: UInt8,
        primaryBody: [UInt8],
        newCerts: [[UInt8]: [UInt8]],
        newBindings: [String: [UInt8]]
    ) -> [UInt8] {
        var out: [UInt8] = []
        for block in blocks {
            out += OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: block.key.tag, body: block.key.body)
            var replacement: [UInt8]? = nil
            var replacedTypes: ClosedRange<UInt8>? = nil
            if block.key.tag == 13, let cert = newCerts[block.key.body] {
                replacement = cert
                replacedTypes = 0x10...0x13
            } else if block.key.tag == subkeyTag, block.key.body.first == 4 {
                let publicBody = subkeyTag == 7 ? OpenPGPPacketParser.v4PublicPrefix(secretBody: block.key.body) : block.key.body
                if let publicBody,
                   let binding = newBindings[hex(OpenPGPPacketParser.computeV4Fingerprint(packetBody: publicBody))] {
                    replacement = binding
                    replacedTypes = 0x18...0x18
                }
            }
            var emitted = false
            for packet in block.rest {
                if let replacement, let replacedTypes, packet.tag == 2,
                   let sig = try? OpenPGPPacketParser.parseSignaturePacket(body: packet.body),
                   replacedTypes.contains(sig.signatureType),
                   CertificateValidator.issuedBy(primaryBody: primaryBody, sig) {
                    if !emitted {
                        out += replacement
                        emitted = true
                    }
                    continue
                }
                out += OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: packet.tag, body: packet.body)
            }
            if let replacement, !emitted { out += replacement }
        }
        return out
    }

    // MARK: - Checking the old signatures

    private enum Check { case valid, weakHash, invalid }

    /// `.valid` when the signature verifies here; `.weakHash` when it is an
    /// EdDSA signature over SHA-1 (which this device refuses for use) that
    /// verifies apart from that; `.invalid` otherwise.
    private static func check(_ sig: OpenPGPPacketParser.ParsedSignature, signerBody: [UInt8], document: [UInt8]) -> Check {
        if CertificateValidator.verify(sig, signerBody: signerBody, document: document) == .valid { return .valid }
        return verifiesEd25519OverSHA1(sig, signerBody: signerBody, document: document) ? .weakHash : .invalid
    }

    private static let ed25519LegacyOID: [UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]

    private static func verifiesEd25519OverSHA1(_ sig: OpenPGPPacketParser.ParsedSignature,
                                                signerBody: [UInt8], document: [UInt8]) -> Bool {
        guard sig.version == 4, sig.hashAlgorithm == 2, sig.publicKeyAlgorithm == 22,
              signerBody.count > 7, signerBody[0] == 4, signerBody[5] == 22 else { return false }
        let oidLength = Int(signerBody[6])
        guard 7 + oidLength + 2 <= signerBody.count,
              Array(signerBody[7..<(7 + oidLength)]) == ed25519LegacyOID else { return false }
        let pointStart = 7 + oidLength + 2
        guard pointStart + 33 <= signerBody.count, signerBody[pointStart] == 0x40,
              let publicKey = try? Curve25519.Signing.PublicKey(
                rawRepresentation: Data(signerBody[(pointStart + 1)..<(pointStart + 33)])) else { return false }
        var input = Data(document)
        input.append(contentsOf: sig.rawHashedPortion)
        input.append(contentsOf: [4, 0xFF] + u32be(UInt32(sig.rawHashedPortion.count)))
        let digest = Array(Insecure.SHA1.hash(data: input))
        guard Array(digest.prefix(2)) == sig.hashPrefix,
              let pair = try? OpenPGPPacketParser.extractMPIPair(from: sig.signatureData),
              pair.r.count <= 32, pair.s.count <= 32 else { return false }
        let raw = [UInt8](repeating: 0, count: 32 - pair.r.count) + pair.r
            + [UInt8](repeating: 0, count: 32 - pair.s.count) + pair.s
        return publicKey.isValidSignature(Data(raw), for: Data(digest))
    }

    // MARK: - Signing

    private struct Signer {
        let algorithm: UInt8
        let sign: (_ digest: [UInt8]) throws -> [[UInt8]]
    }

    private static func supports(primaryBody: [UInt8]) -> Bool {
        guard primaryBody.count > 7, primaryBody[0] == 4 else { return false }
        switch primaryBody[5] {
        case 1, 3:
            return true
        case 22:
            let oidLength = Int(primaryBody[6])
            return 7 + oidLength <= primaryBody.count && Array(primaryBody[7..<(7 + oidLength)]) == ed25519LegacyOID
        default:
            return false
        }
    }

    /// The signer for the first secret key packet (tag 5) of `secretRing`,
    /// unlocked with `passphrase`. Ed25519 through CryptoKit, RSA (PKCS #1
    /// v1.5 over SHA-256) through the Security framework.
    private static func signer(secretRing: Data, algorithm: UInt8, passphrase: String?) throws -> Signer {
        if algorithm == 22 {
            let info = try PGPService.shared.extractPrimaryCertificationKey(fromSecretKeyData: secretRing, passphrase: passphrase)
            let privateKey = info.privateKey
            return Signer(algorithm: 22) { digest in
                let sig = Array(try privateKey.signature(for: Data(digest)))
                guard sig.count == 64 else { throw RefreshError.signatureFailed }
                return [Array(sig[0..<32]), Array(sig[32..<64])]
            }
        }
        let rsa = try PGPService.shared.extractPrimaryRSACertificationKey(fromSecretKeyData: secretRing, passphrase: passphrase)
        let privateKey = rsa.privateKey
        return Signer(algorithm: 1) { digest in
            var error: Unmanaged<CFError>?
            guard let sig = SecKeyCreateSignature(privateKey, .rsaSignatureDigestPKCS1v15SHA256,
                                                  Data(digest) as CFData, &error) as Data? else {
                throw RefreshError.signatureFailed
            }
            return [Array(sig)]
        }
    }

    /// A signing subkey's new 0x19 back-signature, made by the subkey. Its
    /// secret packet is unlocked on its own (framed as a primary so the
    /// PGPService extractors read it), and the result must verify against
    /// the subkey's public part, which proves the secret is this subkey's.
    private static func backSignature(secretBody: [UInt8], subkeyBody: [UInt8], document: [UInt8],
                                      passphrase: String?, sigTime: UInt32) throws -> [UInt8]? {
        guard subkeyBody.count > 5, [1, 3, 22].contains(subkeyBody[5]) else { return nil }
        let single = Data(OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 5, body: secretBody))
        let subSigner = try signer(secretRing: single, algorithm: subkeyBody[5], passphrase: passphrase)
        let subFP = OpenPGPPacketParser.computeV4Fingerprint(packetBody: subkeyBody)
        var hashed = subpacket(2, u32be(sigTime))
        hashed += subpacket(33, [4] + subFP)
        let body = try makeSignature(sigType: 0x19, signer: subSigner, document: document,
                                     hashed: hashed, unhashed: subpacket(16, Array(subFP.suffix(8))))
        guard let parsed = try? OpenPGPPacketParser.parseSignaturePacket(body: body),
              CertificateValidator.verify(parsed, signerBody: subkeyBody, document: document) == .valid else {
            return nil
        }
        return body
    }

    /// A complete v4 signature body (not framed) over `document` with SHA-256.
    private static func makeSignature(sigType: UInt8, signer: Signer, document: [UInt8],
                                      hashed: [UInt8], unhashed: [UInt8]) throws -> [UInt8] {
        let trailer: [UInt8] = [4, sigType, signer.algorithm, 8] + u16be(UInt16(hashed.count)) + hashed
        var input = Data(document)
        input.append(contentsOf: trailer)
        input.append(contentsOf: [4, 0xFF] + u32be(UInt32(trailer.count)))
        let digest = Array(SHA256.hash(data: input))
        let mpis = try signer.sign(digest)
        var body = trailer
        body += u16be(UInt16(unhashed.count)) + unhashed
        body += [digest[0], digest[1]]
        for value in mpis { body += mpi(value) }
        return body
    }

    // MARK: - Subpackets

    /// Hashed subpackets carried forward: everything but creation time (2),
    /// issuer key ID (16), issuer fingerprint (33) and an embedded signature
    /// (32), which are made again. Key flags, expiry, preferences, features,
    /// key server preferences and the primary User ID flag stay as they were.
    private static let regenerated: Set<UInt8> = [2, 16, 32, 33]

    private static func preserved(_ subpackets: [OpenPGPPacketParser.ParsedSubpacket]) -> [UInt8] {
        var out: [UInt8] = []
        for sp in subpackets where !regenerated.contains(sp.type) {
            out += subpacket(sp.isCritical ? (sp.type | 0x80) : sp.type, sp.data)
        }
        return out
    }

    private static func subpacket(_ type: UInt8, _ data: [UInt8]) -> [UInt8] {
        let total = data.count + 1
        var out: [UInt8]
        if total < 192 {
            out = [UInt8(total)]
        } else if total < 8384 {
            let adjusted = total - 192
            out = [UInt8((adjusted >> 8) + 192), UInt8(adjusted & 0xFF)]
        } else {
            out = [0xFF] + u32be(UInt32(total))
        }
        return out + [type] + data
    }

    // MARK: - Small encoders

    private static func mpi(_ bytes: [UInt8]) -> [UInt8] {
        var value = bytes
        while value.first == 0 { value.removeFirst() }
        guard let first = value.first else { return [0, 0] }
        let bits = (value.count - 1) * 8 + (8 - first.leadingZeroBitCount)
        return u16be(UInt16(bits)) + value
    }

    private static func seconds(_ date: Date?) -> UInt32 {
        guard let date else { return 0 }
        let t = date.timeIntervalSince1970
        return t <= 0 ? 0 : UInt32(min(t, Double(UInt32.max)))
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func u16be(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xFF)] }
    private static func u32be(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }
}
