// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CertificateValidator.swift
// PGPonyCore
//
// Only components a certificate's primary key actually bound are part of it,
// following RFC 9580 as GnuPG and Sequoia apply it:
//   - a subkey belongs to the certificate only when a subkey binding
//     signature (0x18) made by the primary over (primary, subkey) verifies;
//   - a subkey that may sign (key flag 0x02) must also carry a primary key
//     binding signature (0x19) made by the subkey itself, in the binding's
//     embedded-signature subpacket (32);
//   - encryption picks among bound subkeys whose newest binding grants
//     encryption (0x04 or 0x08) and has not expired.
//
// `boundComponents` returns the ring with every other subkey removed; callers
// that pick recipients or attribute signatures read that view.
//
// Bindings this code cannot check: an ML-DSA-65 + Ed25519 primary where
// ML-DSA is unavailable is checked on its Ed25519 half. An Ed448 primary
// (RFC 9980 algorithm 31), a DSA primary, a LibrePGP v5 key, an ECDSA key on
// a curve other than P-256/384/521 and a v4 key with algorithm 27 have no
// verifier here: such a binding counts for encryption and signing only for a
// subkey the caller lists in `pinnedSubkeys` (one the user accepted), and
// `newestVerifiedBinding`, what a merge should add subkeys on, never returns
// it. Whether a binding is uncheckable depends only on the signer's key; a
// signature naming a hash or version this code cannot handle is invalid.

import Foundation
import CryptoKit
import CommonCrypto
import Security

enum CertificateValidator {

    enum Purpose {
        /// Every bound subkey (display, signer lookup by issuer).
        case any
        /// Bound, grants encryption when the binding carries key flags, not expired.
        case encrypt
        /// Bound, grants signing, back-signed, not expired.
        case sign
    }

    enum Verdict: Equatable {
        case valid
        case invalid
        /// No verifier for this algorithm on this device.
        case uncheckable
    }

    // MARK: - Errors and pins

    /// The stored ring did not parse, so which of its subkeys the primary
    /// bound cannot be decided. Encrypt paths refuse the key.
    struct UnreadableKey: LocalizedError {
        var errorDescription: String? { "This key could not be read." }
    }

    /// Subkeys the user accepted whose binding cannot be checked here (a DSA,
    /// Ed448, brainpool or LibrePGP v5 primary), by the primary's
    /// fingerprint. They qualify for `.encrypt` and `.sign` like verified
    /// ones; nothing else with an uncheckable binding does. Empty by default;
    /// an app sets this from its own record of what the user accepted, and
    /// should never add to it from a merge or refresh.
    static var pinnedSubkeys: (_ primaryFingerprint: [UInt8]) -> Set<[UInt8]> = { _ in [] }

    /// Fingerprint of a primary or subkey packet body: v4 SHA-1, v6 SHA-256
    /// (0x9B framing), LibrePGP v5 SHA-256 (0x9A framing).
    static func fingerprint(ofKeyBody body: [UInt8]) -> [UInt8] {
        switch body.first {
        case 6: return OpenPGPPacketParser.computeV6Fingerprint(packetBody: body)
        case 5: return Array(SHA256.hash(data: Data(frameKey(body, signatureVersion: 5))))
        default: return OpenPGPPacketParser.computeV4Fingerprint(packetBody: body)
        }
    }

    /// Armored input as binary; binary input as given.
    private static func binary(_ data: Data) -> Data {
        guard data.starts(with: Array("-----BEGIN".utf8)),
              let text = String(data: data, encoding: .utf8),
              let raw = try? OpenPGPPacketParser.dearmor(text) else { return data }
        return raw
    }

    // MARK: - Ring filtering

    /// `data` (a transferable PUBLIC key, binary) with every subkey that does
    /// not qualify for `purpose` removed, with the signatures under it. The
    /// primary, its User IDs and their signatures pass through untouched.
    /// Throws `UnreadableKey` when the ring does not parse: an unfiltered ring
    /// must never reach a recipient picker. A secret ring (no tag 6 primary)
    /// comes back as given; encrypt paths only ever pass public data.
    static func boundComponents(_ data: Data, purpose: Purpose = .any, at date: Date = Date()) throws -> Data {
        let data = binary(data)
        guard let packets = try? OpenPGPPacketParser.parsePackets(data: Array(data)) else {
            throw UnreadableKey()
        }
        guard let primaryIndex = packets.firstIndex(where: { $0.tag == 6 }) else { return data }
        let primaryBody = packets[primaryIndex].body
        let pinned = pinnedSubkeys(fingerprint(ofKeyBody: primaryBody))
        var out: [UInt8] = []
        var index = 0
        var changed = false
        while index < packets.count {
            let packet = packets[index]
            guard packet.tag == 14 else {
                out += OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: packet.tag, body: packet.body)
                index += 1
                continue
            }
            // The subkey and the signatures that follow it.
            var end = index + 1
            while end < packets.count, packets[end].tag == 2 || packets[end].tag == 12 { end += 1 }
            let signatures = packets[(index + 1)..<end].filter { $0.tag == 2 }.map(\.body)
            if qualifies(subkeyBody: packet.body, signatures: signatures, primaryBody: primaryBody,
                         purpose: purpose, at: date, pinned: pinned) {
                for p in packets[index..<end] {
                    out += OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: p.tag, body: p.body)
                }
            } else {
                changed = true
            }
            index = end
        }
        return changed ? Data(out) : data
    }

    /// Fingerprints of the subkeys in a public ring whose newest binding is
    /// uncheckable on this device (no binding that verifies, and none that
    /// fails). Empty for a ring that does not parse or has no such subkey.
    static func uncheckableSubkeys(in data: Data) -> (primary: [UInt8], subkeys: [[UInt8]]) {
        guard let packets = try? OpenPGPPacketParser.parsePackets(data: Array(binary(data))),
              let primaryIndex = packets.firstIndex(where: { $0.tag == 6 }) else { return ([], []) }
        let primaryBody = packets[primaryIndex].body
        var found: [[UInt8]] = []
        var index = 0
        while index < packets.count {
            guard packets[index].tag == 14 else { index += 1; continue }
            var end = index + 1
            while end < packets.count, packets[end].tag == 2 || packets[end].tag == 12 { end += 1 }
            let signatures = packets[(index + 1)..<end].filter { $0.tag == 2 }.map(\.body)
            if newestBinding(subkeyBody: packets[index].body, signatures: signatures,
                             primaryBody: primaryBody)?.1 == .uncheckable {
                found.append(fingerprint(ofKeyBody: packets[index].body))
            }
            index = end
        }
        return (fingerprint(ofKeyBody: primaryBody), found)
    }

    /// True when the subkey qualifies for `purpose`. `.any` (display) takes a
    /// verified or an uncheckable binding. `.encrypt` and `.sign` take a
    /// verified binding, or an uncheckable one only for a subkey in `pinned`;
    /// `.sign` also needs a back-signature that verifies.
    static func qualifies(subkeyBody: [UInt8], signatures: [[UInt8]], primaryBody: [UInt8],
                          purpose: Purpose, at date: Date = Date(), pinned: Set<[UInt8]> = []) -> Bool {
        guard let found = newestBinding(subkeyBody: subkeyBody, signatures: signatures,
                                       primaryBody: primaryBody) else { return false }
        let (binding, verdict) = found
        let trusted = verdict == .valid || pinned.contains(fingerprint(ofKeyBody: subkeyBody))
        let flags = binding.hashedSubpackets.first(where: { $0.type == 27 })?.data.first
        switch purpose {
        case .any:
            return true
        case .encrypt:
            guard trusted else { return false }
            if let flags, flags & 0x0C == 0 { return false }
            return !isExpired(binding, subkeyBody: subkeyBody, at: date)
        case .sign:
            guard trusted, let flags, flags & 0x02 != 0 else { return false }
            guard !isExpired(binding, subkeyBody: subkeyBody, at: date) else { return false }
            return backSignatureVerifies(in: binding, subkeyBody: subkeyBody, primaryBody: primaryBody)
        }
    }

    /// Signer attribution: a trusted binding (as `qualifies`) and a verified
    /// back-signature, without the expiry check (a signature is judged by
    /// when it was made, elsewhere).
    static func isBoundSigningSubkey(subkeyBody: [UInt8], signatures: [[UInt8]], primaryBody: [UInt8],
                                     pinned: Set<[UInt8]>) -> Bool {
        guard let found = newestBinding(subkeyBody: subkeyBody, signatures: signatures,
                                       primaryBody: primaryBody) else { return false }
        let (binding, verdict) = found
        guard verdict == .valid || pinned.contains(fingerprint(ofKeyBody: subkeyBody)) else { return false }
        return backSignatureVerifies(in: binding, subkeyBody: subkeyBody, primaryBody: primaryBody)
    }

    /// The newest 0x18 over (primary, subkey) made by the primary, with the
    /// verdict it rests on: the newest one that verifies when any does,
    /// otherwise the newest one this device cannot check. Bindings that fail
    /// are ignored. Nil when there is neither.
    static func newestBinding(subkeyBody: [UInt8], signatures: [[UInt8]],
                              primaryBody: [UInt8]) -> (OpenPGPPacketParser.ParsedSignature, Verdict)? {
        var bestValid: OpenPGPPacketParser.ParsedSignature?
        var bestUncheckable: OpenPGPPacketParser.ParsedSignature?
        for body in signatures {
            guard let sig = try? OpenPGPPacketParser.parseSignaturePacket(body: body),
                  sig.signatureType == 0x18, issuedBy(primaryBody: primaryBody, sig) else { continue }
            let verdicts = bindingDocuments(primaryBody: primaryBody, subkeyBody: subkeyBody,
                                            signatureVersion: sig.version).map {
                verify(sig, signerBody: primaryBody, document: $0)
            }
            let t = sig.creationTime ?? .distantPast
            if verdicts.contains(.valid) {
                if bestValid == nil || t >= (bestValid?.creationTime ?? .distantPast) { bestValid = sig }
            } else if verdicts.contains(.uncheckable) {
                if bestUncheckable == nil || t >= (bestUncheckable?.creationTime ?? .distantPast) { bestUncheckable = sig }
            }
        }
        if let bestValid { return (bestValid, .valid) }
        if let bestUncheckable { return (bestUncheckable, .uncheckable) }
        return nil
    }

    /// The newest 0x18 that VERIFIES. What a merge or refresh may add a
    /// subkey on: an uncheckable binding never adds one.
    static func newestVerifiedBinding(subkeyBody: [UInt8], signatures: [[UInt8]],
                                      primaryBody: [UInt8]) -> OpenPGPPacketParser.ParsedSignature? {
        guard let found = newestBinding(subkeyBody: subkeyBody, signatures: signatures,
                                       primaryBody: primaryBody), found.1 == .valid else { return nil }
        return found.0
    }

    /// A signing subkey's 0x19, carried in the binding's embedded-signature
    /// subpacket (hashed or unhashed), made by the subkey over (primary, subkey).
    /// Only a back-signature that verifies counts: the subkey made it, so an
    /// uncheckable one proves nothing.
    static func backSignatureVerifies(in binding: OpenPGPPacketParser.ParsedSignature,
                                      subkeyBody: [UInt8], primaryBody: [UInt8]) -> Bool {
        let embedded = (binding.hashedSubpackets + binding.unhashedSubpackets).filter { $0.type == 32 }
        for sp in embedded {
            guard let back = try? OpenPGPPacketParser.parseSignaturePacket(body: sp.data),
                  back.signatureType == 0x19 else { continue }
            let verified = bindingDocuments(primaryBody: primaryBody, subkeyBody: subkeyBody,
                                            signatureVersion: back.version).contains {
                verify(back, signerBody: subkeyBody, document: $0) == .valid
            }
            if verified { return true }
        }
        return false
    }

    private static func isExpired(_ binding: OpenPGPPacketParser.ParsedSignature,
                                  subkeyBody: [UInt8], at date: Date) -> Bool {
        guard let sp = binding.hashedSubpackets.first(where: { $0.type == 9 }), sp.data.count == 4,
              subkeyBody.count >= 5 else { return false }
        let seconds = UInt32(sp.data[0]) << 24 | UInt32(sp.data[1]) << 16 | UInt32(sp.data[2]) << 8 | UInt32(sp.data[3])
        guard seconds > 0 else { return false }
        let created = UInt32(subkeyBody[1]) << 24 | UInt32(subkeyBody[2]) << 16 | UInt32(subkeyBody[3]) << 8 | UInt32(subkeyBody[4])
        return date.timeIntervalSince1970 >= Double(created) + Double(seconds)
    }

    // MARK: - Issuer and framing

    /// Whether `sig` names the key with public body `primaryBody` as its issuer
    /// (issuer fingerprint, else issuer key ID). A signature naming neither is
    /// taken as the primary's, which is how old GnuPG self-signatures look.
    static func issuedBy(primaryBody: [UInt8], _ sig: OpenPGPPacketParser.ParsedSignature) -> Bool {
        guard let version = primaryBody.first else { return false }
        let fp = version == 6 ? OpenPGPPacketParser.computeV6Fingerprint(packetBody: primaryBody)
                              : OpenPGPPacketParser.computeV4Fingerprint(packetBody: primaryBody)
        if let issuer = sig.issuerFingerprint {
            return version == 6 ? (issuer.count >= 32 && Array(issuer.prefix(32)) == fp)
                                : (issuer.count >= 20 && Array(issuer.suffix(20)) == fp)
        }
        if let keyID = sig.issuerKeyID {
            return keyID == (version == 6 ? Array(fp.prefix(8)) : Array(fp.suffix(8)))
        }
        return true
    }

    /// The (primary, subkey) documents a binding may have been hashed over.
    /// RFC 9580 5.2.4 frames keys by the SIGNATURE's version (a v4 RSA
    /// subkey under a v6 primary is 0x9B-framed); GnuPG frames a LibrePGP v5
    /// key by the KEY's version even inside a v4 signature. keys.pgpony.app
    /// holds v4 keys with v5 Kyber subkeys bound each way. Each candidate
    /// still needs the signer's signature over that exact subkey, so
    /// accepting both lets nothing else through.
    static func bindingDocuments(primaryBody: [UInt8], subkeyBody: [UInt8], signatureVersion: UInt8) -> [[UInt8]] {
        let bySignature = frameKey(primaryBody, signatureVersion: signatureVersion)
            + frameKey(subkeyBody, signatureVersion: signatureVersion)
        let byKey = frameKey(primaryBody, signatureVersion: primaryBody.first ?? 4)
            + frameKey(subkeyBody, signatureVersion: subkeyBody.first ?? 4)
        return bySignature == byKey ? [bySignature] : [bySignature, byKey]
    }

    /// A key packet as it enters a signature hash: 0x99 | len2 for version 4
    /// (and older), 0x9A | len4 for 5, 0x9B | len4 for 6, then the public body.
    /// Which version applies is the caller's choice; see `bindingDocuments`.
    static func frameKey(_ body: [UInt8], signatureVersion: UInt8) -> [UInt8] {
        let n = body.count
        if signatureVersion == 6 || signatureVersion == 5 {
            let prefix: UInt8 = signatureVersion == 6 ? 0x9B : 0x9A
            return [prefix, UInt8((n >> 24) & 0xFF), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)] + body
        }
        return [0x99, UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)] + body
    }

    /// A User ID (0xB4) or attribute (0xD1) as it enters a certification hash.
    static func frameIdentity(_ prefix: UInt8, _ body: [UInt8]) -> [UInt8] {
        let n = body.count
        return [prefix, UInt8((n >> 24) & 0xFF), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)] + body
    }

    // MARK: - Verification by key algorithm

    /// Verify `sig` over `document` with the key whose public body is
    /// `signerBody` (a primary or a subkey). Ed25519 (v4 22, v6 27), ECDSA on
    /// the NIST curves (19), RSA (1, 3), composite ML-DSA-65 + Ed25519 (30).
    static func verify(_ sig: OpenPGPPacketParser.ParsedSignature, signerBody: [UInt8], document: [UInt8]) -> Verdict {
        guard let version = signerBody.first, signerBody.count > 5 else { return .invalid }
        if version == 5 { return .uncheckable }
        guard version == 4 || version == 6 else { return .invalid }
        guard sig.version == version else { return .invalid }
        let algorithm = signerBody[5]
        guard sig.publicKeyAlgorithm == algorithm
                || (algorithm == 3 && sig.publicKeyAlgorithm == 1) || (algorithm == 1 && sig.publicKeyAlgorithm == 3) else {
            return .invalid
        }
        switch algorithm {
        case 1, 3:
            return verifyRSA(sig, document: document, keyBody: signerBody) ? .valid : .invalid
        case 27:
            if version == 4 { return .uncheckable }
            guard signerBody.count >= 42 else { return .invalid }
            return bool(try? OpenPGPPacketParser.verifyEd25519Signature(
                signature: sig, document: document, publicKey: Array(signerBody[10..<42])))
        case 30:
            guard let material = CompositeSignSuite.publicMaterial(fromKeyPacketBody: signerBody)?.material else { return .invalid }
            return bool(try? OpenPGPPacketParser.verifyEd25519Signature(
                signature: sig, document: document, publicKey: material,
                compositeClassicalHalfWhenUnavailable: true))
        case 31:
            return .uncheckable
        case 22, 19:
            guard version == 4, signerBody.count > 7 else { return .invalid }
            let oidLength = Int(signerBody[6])
            guard 7 + oidLength <= signerBody.count else { return .invalid }
            let oid = Array(signerBody[7..<(7 + oidLength)])
            if algorithm == 19, ![NISTCurve.p256, .p384, .p521].contains(where: { $0.oid == oid }) {
                return .uncheckable
            }
            if algorithm == 22, oid != Self.ed25519LegacyOID { return .uncheckable }
            var offset = 7 + oidLength
            guard var point = readMPI(signerBody, &offset) else { return .invalid }
            if algorithm == 22 {
                guard point.count == 33, point.first == 0x40 else { return .invalid }
                point.removeFirst()
            }
            return bool(try? OpenPGPPacketParser.verifyEd25519Signature(
                signature: sig, document: document, publicKey: point))
        default:
            return .uncheckable
        }
    }

    /// 1.3.6.1.4.1.11591.15.1, the legacy EdDSA curve OID for Ed25519.
    private static let ed25519LegacyOID: [UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]

    private static func bool(_ result: Bool?) -> Verdict {
        result == true ? .valid : .invalid
    }

    private static func verifyRSA(_ sig: OpenPGPPacketParser.ParsedSignature, document: [UInt8], keyBody: [UInt8]) -> Bool {
        var offset = keyBody.first == 6 ? 10 : 6
        guard let n = readMPI(keyBody, &offset), let e = readMPI(keyBody, &offset) else { return false }
        var sigOffset = 0
        guard var value = readMPI(sig.signatureData, &sigOffset) else { return false }

        var input = Data(document)
        if sig.version == 6 { input = Data(sig.salt) + input }
        input.append(contentsOf: sig.rawHashedPortion)
        let count = UInt32(sig.rawHashedPortion.count)
        input.append(contentsOf: [sig.version, 0xFF, UInt8((count >> 24) & 0xFF), UInt8((count >> 16) & 0xFF),
                                  UInt8((count >> 8) & 0xFF), UInt8(count & 0xFF)])
        let digest: [UInt8]
        let algorithm: SecKeyAlgorithm
        switch sig.hashAlgorithm {
        case 2:
            digest = Array(Insecure.SHA1.hash(data: input)); algorithm = .rsaSignatureDigestPKCS1v15SHA1
        case 8:
            digest = Array(SHA256.hash(data: input)); algorithm = .rsaSignatureDigestPKCS1v15SHA256
        case 9:
            digest = Array(SHA384.hash(data: input)); algorithm = .rsaSignatureDigestPKCS1v15SHA384
        case 10:
            digest = Array(SHA512.hash(data: input)); algorithm = .rsaSignatureDigestPKCS1v15SHA512
        case 11:
            var out = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
            input.withUnsafeBytes { _ = CC_SHA224($0.baseAddress, CC_LONG(input.count), &out) }
            digest = out; algorithm = .rsaSignatureDigestPKCS1v15SHA224
        default:
            return false
        }
        guard Array(digest.prefix(2)) == sig.hashPrefix else { return false }

        var modulus = n
        while modulus.first == 0 { modulus.removeFirst() }
        while value.count < modulus.count { value.insert(0, at: 0) }
        func derLength(_ length: Int) -> [UInt8] {
            if length < 0x80 { return [UInt8(length)] }
            var bytes: [UInt8] = []; var x = length
            while x > 0 { bytes.insert(UInt8(x & 0xFF), at: 0); x >>= 8 }
            return [UInt8(0x80 | bytes.count)] + bytes
        }
        func derInteger(_ bytes: [UInt8]) -> [UInt8] {
            var v = bytes
            while v.count > 1 && v.first == 0 { v.removeFirst() }
            if let first = v.first, first & 0x80 != 0 { v.insert(0, at: 0) }
            return [0x02] + derLength(v.count) + v
        }
        let sequence = derInteger(n) + derInteger(e)
        let der = [0x30] + derLength(sequence.count) + sequence
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        guard let key = SecKeyCreateWithData(Data(der) as CFData, attributes as CFDictionary, nil) else { return false }
        return SecKeyVerifySignature(key, algorithm, Data(digest) as CFData, Data(value) as CFData, nil)
    }

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
