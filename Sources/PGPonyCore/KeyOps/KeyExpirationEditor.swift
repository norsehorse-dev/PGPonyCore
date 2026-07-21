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
        case underlying(Error)

        var errorDescription: String? {
            switch self {
            case .notAKeyPair:
                return "Editing expiration requires the private key — this is a public-only key."
            case .unsupportedAlgorithm:
                return "Expiration editing supports Ed25519 keys and RSA or Ed25519 hardware keys. For a software RSA or v6 key, use GnuPG."
            case .missingArmoredPublicKey:
                return "The cached public key is missing, so the key material needed for re-signing can't be read."
            case .noPrimaryKeyPacket:
                return "Could not locate the primary public-key packet in this key."
            case .expiryBeforeCreation:
                return "The chosen expiration date is before the key was created."
            case .underlying(let e):
                return e.localizedDescription
            }
        }
    }

    // MARK: - Entry point (pure crypto, no side effects)

    /// Build a re-dated copy of a key's material.
    ///
    /// CORE SEAM: in the app, a thin wrapper feeds this from the SwiftData model
    /// (`PGPService.extractEd25519SigningKey` for the signing material, plus the
    /// Keychain-loaded secret ring). The core takes the extracted materials
    /// directly, so it performs no storage access of its own.
    ///
    /// - Parameters:
    ///   - armoredPublic: the key's ASCII-armored public keyring.
    ///   - signingInfo: the extracted Ed25519 signing key (see `Ed25519SigningInfo`).
    ///   - secretRing: raw secret keyring bytes to re-splice, or nil to skip.
    ///   - expiresAt: the new absolute expiry, or nil for "never".
    /// - Returns: fresh secret keyring bytes + armored public key + the expiry.
    static func buildEditedKey(
        armoredPublic: String,
        signingInfo: Ed25519SigningInfo,
        secretRing: Data?,
        expiresAt: Date?
    ) async throws -> EditedKey {
        let primaryFP20 = signingInfo.fingerprint.count >= 20
            ? Array(signingInfo.fingerprint.suffix(20))
            : signingInfo.fingerprint

        return try await buildEditedKeyCore(
            armoredPublic: armoredPublic,
            expiresAt: expiresAt,
            primaryFP20: primaryFP20,
            issuerKeyID: signingInfo.keyID,
            secretRing: secretRing,
            algorithm: .eddsa,
            sign: { digest in Array(try signingInfo.privateKey.signature(for: Data(digest))) }
        )
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
        pin: String
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
            sign: { digest in
                try await service.verify(pin: pin, mode: .signing)
                switch algorithm {
                case .eddsa:
                    return try await service.sign(digest: digest)
                case .rsa:
                    return try await service.signRSA(digestInfo: CardSigner.sha256DigestInfo(digest))
                }
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
                subs.append(SubEntry(body: pkt.body, creation: info.creationTime, bindingSubpackets: [], isSign: false))
                ctx = .subkey
            case 2:
                let sig = try OpenPGPPacketParser.parseSignaturePacket(body: pkt.body)
                // Only treat as a self-sig if the issuer is the primary key.
                guard isSelfIssued(sig, primaryFP20: primaryFP20) else { break }
                if sig.signatureType == 0x13, ctx == .uid, let i = uids.indices.last {
                    uids[i].certSubpackets = sig.hashedSubpackets
                } else if sig.signatureType == 0x18, ctx == .subkey, let j = subs.indices.last {
                    subs[j].bindingSubpackets = sig.hashedSubpackets
                    if let kf = sig.hashedSubpackets.first(where: { $0.type == 27 })?.data,
                       let firstFlag = kf.first, (firstFlag & 0x02) != 0 {
                        // 0x02 = "this key may be used to sign data". Such a subkey
                        // needs a 0x19 primary-key back-signature we don't generate,
                        // so we leave its binding untouched. PGPony keys have no
                        // signing subkey; this guard is for imported keys.
                        subs[j].isSign = true
                    }
                }
            default:
                break
            }
        }
        guard let primaryBody else { throw EditError.noPrimaryKeyPacket }

        let nowBytes = u32be(UInt32(Date().timeIntervalSince1970))
        let issuerFPData: [UInt8] = [4] + primaryFP20          // type-33 v4 form

        // 4. Generate one fresh 0x13 cert per user ID (relative to PRIMARY creation).
        var newCerts: [[UInt8]] = []
        for u in uids {
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
            newCerts.append(packet)
        }

        // 5. Generate one fresh 0x18 binding per (non-signing) subkey, relative to
        //    that SUBKEY's own creation time. Signing subkeys are skipped (left as-is).
        var newBindings: [Int: [UInt8]] = [:]
        for (j, s) in subs.enumerated() where !s.isSign {
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
        //    the new armored public key; the secret ring (supplied by the caller)
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

    // MARK: - Pre-scan helpers

    private enum Context { case none, uid, subkey }

    private struct UidEntry {
        let body: [UInt8]
        var certSubpackets: [OpenPGPPacketParser.ParsedSubpacket]
    }

    private struct SubEntry {
        let body: [UInt8]
        let creation: UInt32
        var bindingSubpackets: [OpenPGPPacketParser.ParsedSubpacket]
        var isSign: Bool
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
        issuerFPData: [UInt8]
    ) -> [UInt8] {
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
        let hashSHA256: UInt8 = 8

        // Hash input: 0x99 || len || primary body || document2 || trailer || final.
        var hashInput = Data()
        hashInput.append(0x99)
        hashInput.append(contentsOf: u16be(UInt16(primaryBody.count)))
        hashInput.append(contentsOf: primaryBody)
        hashInput.append(contentsOf: document2)

        var trailer: [UInt8] = [4, sigType, pubAlgo, hashSHA256]
        trailer += u16be(UInt16(hashedSubpackets.count))
        trailer += hashedSubpackets
        hashInput.append(contentsOf: trailer)

        // v4 final trailer: 0x04 0xFF || 4-byte BE length of the trailer.
        hashInput.append(4)
        hashInput.append(0xFF)
        hashInput.append(contentsOf: u32be(UInt32(trailer.count)))

        let digest = Array(SHA256.hash(data: hashInput))
        let sigBytes = try await sign(digest)

        // Algorithm-specific signature MPI list.
        let signatureMPIs: [[UInt8]]
        switch algorithm {
        case .eddsa:
            guard sigBytes.count == 64 else { throw EditError.underlying(NSError(
                domain: "PGPony.Expiration", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Unexpected Ed25519 signature length \(sigBytes.count)."])) }
            signatureMPIs = [Array(sigBytes[0..<32]), Array(sigBytes[32..<64])]
        case .rsa:
            guard !sigBytes.isEmpty else { throw EditError.underlying(NSError(
                domain: "PGPony.Expiration", code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Empty RSA signature from card."])) }
            var sig = sigBytes
            while sig.first == 0x00 && sig.count > 1 { sig.removeFirst() }
            signatureMPIs = [sig]
        }

        // Assemble the tag-2 body.
        var body: [UInt8] = [4, sigType, pubAlgo, hashSHA256]
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
        newCerts: [[UInt8]],
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
                if sig.signatureType == 0x13, ctx == .uid, uidIdx >= 0, uidIdx < newCerts.count {
                    // Emit the regenerated cert once per UID and drop any superseded
                    // extras, so a source key carrying multiple self-certs doesn't
                    // produce a duplicate self-signature in the output.
                    if certEmittedFor.insert(uidIdx).inserted {
                        out += newCerts[uidIdx]
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
        out.append(contentsOf: bytes)
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
