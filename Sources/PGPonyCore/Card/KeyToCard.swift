// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// KeyToCard.swift
// PGPony
//
// 8.4.0 build 6 (Android 4.7.0 items 13, 54, 55), 26 October 2026: the pure
// half of Move to Hardware Key, gpg's keytocard. Which keys of a key pair may
// go to which card slot, the algorithm attributes a slot needs for them, the
// private key import data (OpenPGP card 3.4, 4.4.3.12: PUT DATA with odd INS
// 0xDB, P1P2 3FFF, an Extended Header List 0x4D), and the divert-to-card stub
// gpg writes for a key whose secret now lives on a card. No card I/O and no
// Keychain access here (KeyToCardService runs the session and the finish);
// unit-tested in KeyToCardTests. Port of Android crypto/card/KeyToCard.kt.
//
// Supported, as on Android RC4: v4 keys, RSA 2048, 3072 and 4096 (any slot by
// its usage), Ed25519 (EdDSA, algorithm 22: Signature and Authentication
// slots) and Cv25519 (ECDH, algorithm 18: Decryption slot). These are the
// types PGPony can also use on a card afterwards. NIST and brainpool curves,
// RFC 9580 Ed25519/X25519/Ed448/X448 (algorithms 25 to 28), v6 keys and
// composite or post-quantum keys are refused with the reason.
//
// The import data holds private key bytes. Every builder here returns arrays
// the caller wipes (wipe(_:)) once the APDUs are sent. Swift arrays are
// values, so a copy made along the way (the APDU's Data, a CoW split) cannot
// be reached from here; the wipes are best effort, as on Android, where the
// BigInteger values cannot be wiped at all.

import Foundation
import CryptoKit

enum KeyToCard {

    // MARK: - Slots

    /// The three key slots of an OpenPGP card, in the order the sheet shows them.
    enum Slot: Int, CaseIterable, Identifiable, Hashable {
        case signature
        case decryption
        case authentication

        var id: Int { rawValue }

        /// The card layer's own slot type (CRT, attribute and fingerprint DOs).
        var cardSlot: OpenPGPCardService.CardKeySlot {
            switch self {
            case .signature:      return .signature
            case .decryption:     return .decryption
            case .authentication: return .authentication
            }
        }

        /// Control Reference Template naming the slot in the Extended Header
        /// List: B6 signature, B8 decryption, A4 authentication.
        var crt: UInt8 { cardSlot.crt }

        /// Generation time DO (4 octets, big-endian Unix seconds): CE / CF / D0.
        var generationTimeTag: UInt16 {
            switch self {
            case .signature:      return 0x00CE
            case .decryption:     return 0x00CF
            case .authentication: return 0x00D0
            }
        }
    }

    // MARK: - What a key is

    /// The kinds of key this can move.
    enum Kind: Equatable {
        case rsa
        case ed25519
        case cv25519
    }

    /// Why a key cannot go to a card, shown to the user.
    enum Refusal: Equatable {
        /// A v6 (RFC 9580) key.
        case v6
        /// RSA other than 2048, 3072 or 4096 bits.
        case rsaSize
        /// ECDSA or ECDH on NIST or brainpool curves, or another curve.
        case curve
        /// RFC 9580 Ed25519, X25519, Ed448 or X448 (algorithms 25 to 28) on a v4 key.
        case rfc9580
        /// Composite or post-quantum (RFC 9980 algorithms, LibrePGP v5 keys).
        case postQuantum
        /// Anything else (DSA, ElGamal, unknown).
        case algorithm
    }

    enum Eligibility: Equatable {
        case movable(Kind, rsaBits: Int)
        case refused(Refusal)

        var kind: Kind? {
            if case .movable(let kind, _) = self { return kind }
            return nil
        }
    }

    // Curve OIDs as they appear in a key packet and in the card's algorithm
    // attributes (no 0x06 tag, no length).
    static let ed25519OID: [UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]
    static let cv25519OID: [UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]

    private static let curveNames: [([UInt8], String)] = [
        ([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], "NIST P-256"),
        ([0x2B, 0x81, 0x04, 0x00, 0x22], "NIST P-384"),
        ([0x2B, 0x81, 0x04, 0x00, 0x23], "NIST P-521"),
        ([0x2B, 0x81, 0x04, 0x00, 0x0A], "secp256k1"),
        ([0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07], "brainpoolP256r1"),
        ([0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B], "brainpoolP384r1"),
        ([0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D], "brainpoolP512r1"),
        ([0x2B, 0x65, 0x71], "Ed448"),
        ([0x2B, 0x65, 0x6F], "X448"),
    ]

    /// The public part of a key packet (tag 5, 6, 7 or 14), read without
    /// touching any secret material.
    struct KeyPacket: Equatable {
        let version: UInt8
        /// Creation time, Unix seconds, as in the packet.
        let created: UInt32
        let algorithm: UInt8
        /// The public key packet body (everything before the S2K usage octet
        /// of a secret packet); the fingerprint is computed over this.
        let publicBody: [UInt8]
        /// 20 octets for v4, 32 for v5 and v6.
        let fingerprint: [UInt8]
        let curveOID: [UInt8]?
        /// The EC point MPI value as stored (0x40 prefix included for the 25519 curves).
        let ecPoint: [UInt8]?
        let rsaModulus: [UInt8]?
        let rsaExponent: [UInt8]?

        var fingerprintHex: String { KeyToCard.hex(fingerprint) }

        /// 16 hex characters: the trailing 8 octets of a v4 fingerprint, the
        /// leading 8 of a v5 or v6 one.
        var keyIDHex: String {
            version == 4 ? KeyToCard.hex(Array(fingerprint.suffix(8))) : KeyToCard.hex(Array(fingerprint.prefix(8)))
        }

        var createdDate: Date { Date(timeIntervalSince1970: TimeInterval(created)) }

        /// RSA modulus length in bits, or 0.
        var rsaBits: Int { rsaModulus.map(KeyToCard.bitLength) ?? 0 }

        /// The raw 32-octet point of an Ed25519 or Cv25519 key (0x40 removed).
        var point25519: [UInt8]? {
            guard var p = ecPoint else { return nil }
            if p.count == 33, p.first == 0x40 { p.removeFirst() }
            return p.count == 32 ? p : nil
        }

        /// Whether this key can go to a card, and as what.
        var eligibility: Eligibility {
            switch version {
            case 4: break
            case 5: return .refused(.postQuantum)     // LibrePGP v5 keys come with Kyber here
            default: return .refused(.v6)
            }
            switch algorithm {
            case 1, 2, 3:
                let bits = rsaBits
                return [2048, 3072, 4096].contains(bits) ? .movable(.rsa, rsaBits: bits) : .refused(.rsaSize)
            case 22:
                return curveOID == KeyToCard.ed25519OID && point25519 != nil ? .movable(.ed25519, rsaBits: 0) : .refused(.curve)
            case 18:
                return curveOID == KeyToCard.cv25519OID && point25519 != nil ? .movable(.cv25519, rsaBits: 0) : .refused(.curve)
            case 19:
                return .refused(.curve)
            case 25, 26, 27, 28:
                return .refused(.rfc9580)
            case 29, 30, 31, 32, 33, 34, 35, 36:
                return .refused(.postQuantum)
            default:
                return .refused(.algorithm)
            }
        }

        /// A short technical label for the key's algorithm ("RSA 4096",
        /// "Ed25519", "NIST P-256"). Not localized: these are names.
        var algorithmLabel: String {
            switch algorithm {
            case 1, 2, 3: return "RSA \(rsaBits)"
            case 16: return "ElGamal"
            case 17: return "DSA"
            case 18, 19, 22:
                if let oid = curveOID {
                    if oid == KeyToCard.ed25519OID { return "Ed25519" }
                    if oid == KeyToCard.cv25519OID { return "Cv25519" }
                    if let named = KeyToCard.curveNames.first(where: { $0.0 == oid }) { return named.1 }
                }
                return algorithm == 18 ? "ECDH" : (algorithm == 19 ? "ECDSA" : "EdDSA")
            case 25: return "X25519"
            case 26: return "X448"
            case 27: return "Ed25519 (RFC 9580)"
            case 28: return "Ed448"
            case 30: return "ML-DSA-65 + Ed25519"
            case 31: return "ML-DSA-87 + Ed448"
            case 35: return "ML-KEM-768 + X25519"
            case 36: return "ML-KEM-1024 + X448"
            default: return "Algorithm \(algorithm)"
            }
        }
    }

    /// Read the public part of a key packet body (public or secret). Nil when
    /// the body is not a key packet this can walk.
    static func keyPacket(body: [UInt8]) -> KeyPacket? {
        guard body.count >= 6 else { return nil }
        let version = body[0]
        let created = UInt32(body[1]) << 24 | UInt32(body[2]) << 16 | UInt32(body[3]) << 8 | UInt32(body[4])
        let algorithm = body[5]

        switch version {
        case 4:
            var o = 6
            var curveOID: [UInt8]?
            var point: [UInt8]?
            var modulus: [UInt8]?
            var exponent: [UInt8]?
            switch algorithm {
            case 1, 2, 3:
                guard let n = readMPI(body, &o), let e = readMPI(body, &o) else { return nil }
                modulus = n; exponent = e
            case 16:
                for _ in 0..<3 { guard readMPI(body, &o) != nil else { return nil } }
            case 17:
                for _ in 0..<4 { guard readMPI(body, &o) != nil else { return nil } }
            case 19, 22:
                guard let oid = readLengthPrefixed(body, &o), let q = readMPI(body, &o) else { return nil }
                curveOID = oid; point = q
            case 18:
                guard let oid = readLengthPrefixed(body, &o), let q = readMPI(body, &o),
                      readLengthPrefixed(body, &o) != nil else { return nil }
                curveOID = oid; point = q
            case 25: o += 32
            case 26: o += 56
            case 27: o += 32
            case 28: o += 57
            case 35: o += 32 + 1184
            default: return nil
            }
            guard o <= body.count else { return nil }
            let publicBody = Array(body[0..<o])
            return KeyPacket(version: 4, created: created, algorithm: algorithm, publicBody: publicBody,
                             fingerprint: OpenPGPPacketParser.computeV4Fingerprint(packetBody: publicBody),
                             curveOID: curveOID, ecPoint: point, rsaModulus: modulus, rsaExponent: exponent)
        case 5, 6:
            // version(1) | created(4) | algo(1) | material length(4) | material
            guard body.count >= 10 else { return nil }
            let length = Int(body[6]) << 24 | Int(body[7]) << 16 | Int(body[8]) << 8 | Int(body[9])
            guard length >= 0, 10 + length <= body.count else { return nil }
            let publicBody = Array(body[0..<(10 + length)])
            let fingerprint: [UInt8]
            if version == 6 {
                fingerprint = OpenPGPPacketParser.computeV6Fingerprint(packetBody: publicBody)
            } else {
                let n = publicBody.count
                let prefix: [UInt8] = [0x9A, UInt8((n >> 24) & 0xFF), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)]
                fingerprint = Array(SHA256.hash(data: Data(prefix + publicBody)))
            }
            return KeyPacket(version: version, created: created, algorithm: algorithm, publicBody: publicBody,
                             fingerprint: fingerprint, curveOID: nil, ecPoint: nil, rsaModulus: nil, rsaExponent: nil)
        default:
            return nil
        }
    }

    // MARK: - Where a secret is

    /// What a secret key packet holds after its public part.
    enum SecretState: Equatable {
        /// S2K usage 0: the secret is here, unprotected.
        case clear
        /// Passphrase protected: the secret is here.
        case protected
        /// GnuPG stub, mode 1001: no secret anywhere on this device (offline primary).
        case gnuDummy
        /// GnuPG stub, mode 1002: the secret is on the card with this serial (AID).
        case divertToCard(serial: [UInt8])
    }

    /// The secret state of a v4 secret packet body. v5 and v6 bodies report
    /// clear or protected only; GnuPG never writes stubs for them.
    static func secretState(secretBody body: [UInt8]) -> SecretState? {
        guard let key = keyPacket(body: body) else { return nil }
        let i = key.publicBody.count
        guard i < body.count else { return nil }
        let usage = body[i]
        if usage == 0 { return .clear }
        guard key.version == 4, usage == 254 || usage == 255 else { return .protected }
        // usage | cipher | S2K type 101 | hash | "GNU" | mode | [serial length | serial]
        guard i + 7 < body.count, body[i + 2] == 101,
              body[i + 4] == 0x47, body[i + 5] == 0x4E, body[i + 6] == 0x55 else { return .protected }
        switch body[i + 7] {
        case 1: return .gnuDummy
        case 2:
            var serial: [UInt8] = []
            if i + 8 < body.count {
                let n = Int(body[i + 8])
                let start = i + 9
                if start + n <= body.count { serial = Array(body[start..<(start + n)]) }
            }
            return .divertToCard(serial: serial)
        default:
            return .protected
        }
    }

    static func hasSecretHere(_ state: SecretState?) -> Bool {
        state == .clear || state == .protected
    }

    // MARK: - Usage, from the self-signatures

    /// What the newest self-signature says about one key.
    struct Binding: Equatable {
        var flags: UInt8?
        var flagsTime: UInt32 = 0
        var revoked = false
        /// Seconds after the key's creation (subpacket 9) in the newest binding.
        var expirySeconds: UInt32?
    }

    /// Key flags, revocation and expiry for every key in `ring`, keyed by
    /// fingerprint hex. Only signatures issued by the primary count: user ID
    /// certifications (0x10 to 0x13) and direct key signatures (0x1F) for the
    /// primary, subkey bindings (0x18) for a subkey, 0x20 and 0x28 revocations.
    /// The newest one with key flags wins, as gpg reads it.
    static func bindings(ring: [UInt8]) -> [String: Binding] {
        guard let packets = try? OpenPGPPacketParser.parsePackets(data: ring) else { return [:] }
        var out: [String: Binding] = [:]
        var primary: KeyPacket?
        var current: KeyPacket?
        for packet in packets {
            switch packet.tag {
            case 5, 6:
                primary = keyPacket(body: packet.body)
                current = primary
            case 7, 14:
                current = keyPacket(body: packet.body)
            case 2:
                guard let primary, let current,
                      let sig = try? OpenPGPPacketParser.parseSignaturePacket(body: packet.body) else { continue }
                if let issuer = sig.issuerKeyID, issuer != Array(primary.fingerprint.suffix(8)),
                   issuer != Array(primary.fingerprint.prefix(8)) { continue }
                let isPrimary = current.fingerprint == primary.fingerprint
                let type = sig.signatureType
                var binding = out[current.fingerprintHex] ?? Binding()
                if (isPrimary && type == 0x20) || (!isPrimary && type == 0x28) {
                    binding.revoked = true
                    out[current.fingerprintHex] = binding
                    continue
                }
                let selfSig = isPrimary ? ((0x10...0x13).contains(type) || type == 0x1F) : type == 0x18
                guard selfSig else { continue }
                var time: UInt32 = 0
                var flags: UInt8?
                var expiry: UInt32?
                for sp in sig.hashedSubpackets {
                    if sp.type == 2, sp.data.count == 4 {
                        time = UInt32(sp.data[0]) << 24 | UInt32(sp.data[1]) << 16 | UInt32(sp.data[2]) << 8 | UInt32(sp.data[3])
                    } else if sp.type == 27, let first = sp.data.first {
                        flags = first
                    } else if sp.type == 9, sp.data.count == 4 {
                        expiry = UInt32(sp.data[0]) << 24 | UInt32(sp.data[1]) << 16 | UInt32(sp.data[2]) << 8 | UInt32(sp.data[3])
                    }
                }
                if let flags, binding.flags == nil || time >= binding.flagsTime {
                    binding.flags = flags
                    binding.flagsTime = time
                    binding.expirySeconds = (expiry == 0) ? nil : expiry
                }
                out[current.fingerprintHex] = binding
            default:
                continue
            }
        }
        return out
    }

    /// Usage when no self-signature carries key flags: PGPony's own layouts
    /// (SubkeyCapabilitySet.heuristic).
    static func heuristicFlags(algorithm: UInt8, isPrimary: Bool) -> UInt8 {
        switch algorithm {
        case 1, 2, 3: return isPrimary ? 0x0F : 0x0C
        case 18, 25, 26: return 0x0C
        default: return isPrimary ? 0x03 : 0x02
        }
    }

    // MARK: - Candidates

    /// One key of the key pair whose secret is on this device.
    struct Candidate: Identifiable, Equatable {
        let packet: KeyPacket
        let isPrimary: Bool
        let flags: UInt8
        let expires: Date?

        var id: String { packet.fingerprintHex }
        var eligibility: Eligibility { packet.eligibility }
        var kind: Kind? { eligibility.kind }
        var refusal: Refusal? {
            if case .refused(let reason) = eligibility { return reason }
            return nil
        }

        var canCertify: Bool { flags & 0x01 != 0 }
        var canSign: Bool { flags & 0x02 != 0 }
        var canEncrypt: Bool { flags & 0x0C != 0 }
        var canAuthenticate: Bool { flags & 0x20 != 0 }

        func isExpired(at now: Date = Date()) -> Bool {
            guard let expires else { return false }
            return expires <= now
        }

        /// Whether this key may go to `slot` (Android's fitsSlot).
        func fits(_ slot: Slot) -> Bool {
            guard let kind else { return false }
            return KeyToCard.fitsSlot(kind: kind, slot: slot, canSign: canSign, canEncrypt: canEncrypt,
                                      canAuthenticate: canAuthenticate, primaryCanCertify: isPrimary && canCertify)
        }
    }

    /// What the sheet offers: the keys with a secret here (revoked ones left
    /// out) and how many keys hold a secret on this device in all.
    struct Inventory: Equatable {
        let candidates: [Candidate]
        /// Every key whose secret is on this device, revoked or refused ones
        /// included. Remove is offered only when the move covers all of them.
        let secretCount: Int

        var hasMovable: Bool { candidates.contains { $0.kind != nil } }
        var refused: [Candidate] { candidates.filter { $0.refusal != nil } }

        func candidate(_ fingerprintHex: String) -> Candidate? {
            candidates.first { $0.id == fingerprintHex }
        }

        func options(for slot: Slot) -> [Candidate] {
            candidates.filter { $0.fits(slot) }
        }
    }

    /// Walk the secret ring for keys whose secret is here; usage, revocation
    /// and expiry come from the public ring's self-signatures, then the secret
    /// ring's, then PGPony's own defaults.
    static func inventory(secretRing: [UInt8], publicRing: [UInt8]?) throws -> Inventory {
        let packets = try OpenPGPPacketParser.parsePackets(data: secretRing)
        var bound = bindings(ring: secretRing)
        if let publicRing {
            for (fp, b) in bindings(ring: publicRing) { bound[fp] = b }
        }
        var candidates: [Candidate] = []
        var secretCount = 0
        for packet in packets where packet.tag == 5 || packet.tag == 7 {
            guard let key = keyPacket(body: packet.body),
                  hasSecretHere(secretState(secretBody: packet.body)) else { continue }
            secretCount += 1
            let isPrimary = packet.tag == 5
            let binding = bound[key.fingerprintHex]
            if binding?.revoked == true { continue }
            let flags = binding?.flags ?? heuristicFlags(algorithm: key.algorithm, isPrimary: isPrimary)
            let expires = binding?.expirySeconds.map { Date(timeIntervalSince1970: TimeInterval(key.created) + TimeInterval($0)) }
            candidates.append(Candidate(packet: key, isPrimary: isPrimary, flags: flags, expires: expires))
        }
        return Inventory(candidates: candidates, secretCount: secretCount)
    }

    /// Whether a key of `kind` may go to `slot` given what it is for. A
    /// certify-only primary may go to the Signature slot, as in gpg: the
    /// card's signature slot is what certifies on a card.
    static func fitsSlot(kind: Kind, slot: Slot, canSign: Bool, canEncrypt: Bool,
                         canAuthenticate: Bool, primaryCanCertify: Bool = false) -> Bool {
        switch slot {
        case .signature:      return (canSign || primaryCanCertify) && kind != .cv25519
        case .decryption:     return canEncrypt && (kind == .rsa || kind == .cv25519)
        case .authentication: return canAuthenticate && kind != .cv25519
        }
    }

    /// The key each slot starts with: the newest unexpired key that fits it, a
    /// subkey before the primary, and never one already given to an earlier
    /// slot. Authentication starts empty, as on Android: it is filled only
    /// when the owner picks a key for it.
    static func defaultChoices(_ inventory: Inventory, now: Date = Date()) -> [Slot: String] {
        var out: [Slot: String] = [:]
        for slot in [Slot.signature, .decryption] {
            let taken = Set(out.values)
            let pick = inventory.options(for: slot)
                .filter { !$0.isExpired(at: now) && !taken.contains($0.id) }
                .sorted { a, b in
                    if a.isPrimary != b.isPrimary { return !a.isPrimary }
                    return a.packet.created > b.packet.created
                }
                .first
            if let pick { out[slot] = pick.id }
        }
        return out
    }

    /// Every chosen key is a different key.
    static func choicesAreDistinct(_ choices: [Slot: String]) -> Bool {
        Set(choices.values).count == choices.count
    }

    /// Remove from this device is offered only when every key with a secret
    /// here moves (one per slot, no two slots sharing a key). A partial move
    /// keeps the full key pair on the device and the card holds copies.
    static func removeAllowed(_ choices: [Slot: String], secretCount: Int) -> Bool {
        !choices.isEmpty && choicesAreDistinct(choices) && choices.count == secretCount
    }

    // MARK: - Algorithm attributes (C1, C2, C3)

    /// RSA import format 00: standard (e, p, q).
    static let rsaFormatStandard: UInt8 = 0x00
    /// RSA import format 02: CRT (e, p, q, 1/q mod p, d mod (p-1), d mod (q-1)).
    static let rsaFormatCRT: UInt8 = 0x02

    /// The attributes a slot needs for a key of `kind`: RSA is
    /// 01 | n bits | e bits | import format, an EC key is its algorithm ID
    /// and curve OID. `rsaFormat` keeps the format the slot already uses.
    static func attributes(kind: Kind, rsaBits: Int = 0, eBits: Int = 0, rsaFormat: UInt8 = 0) -> [UInt8] {
        switch kind {
        case .rsa:
            return [0x01, UInt8((rsaBits >> 8) & 0xFF), UInt8(rsaBits & 0xFF),
                    UInt8((eBits >> 8) & 0xFF), UInt8(eBits & 0xFF), rsaFormat]
        case .ed25519:
            return [0x16] + ed25519OID
        case .cv25519:
            return [0x12] + cv25519OID
        }
    }

    /// The RSA public exponent length in bits of raw attributes, or nil when not RSA.
    static func rsaExponentBits(of attributes: [UInt8]?) -> Int? {
        guard let a = attributes, a.count >= 5, a[0] == 0x01 else { return nil }
        return Int(a[3]) << 8 | Int(a[4])
    }

    /// The RSA import format octet of raw attributes, or nil when not RSA.
    static func rsaFormat(of attributes: [UInt8]?) -> UInt8? {
        guard let a = attributes, a.count >= 6, a[0] == 0x01 else { return nil }
        return a[5]
    }

    /// Whether `current` (what the slot reports) already is `wanted`. An EC
    /// slot may report a trailing import-format octet after the OID, which is
    /// ignored here. Cards whose attributes cannot change refuse even an
    /// unchanged write, so the slot is only written when this is false.
    static func sameAttributes(current: [UInt8]?, wanted: [UInt8]) -> Bool {
        guard let current, !wanted.isEmpty else { return false }
        if current == wanted { return true }
        let isEC = wanted[0] != 0x01
        return isEC && current.count == wanted.count + 1 && Array(current.prefix(wanted.count)) == wanted
    }

    // MARK: - The import data

    /// One component of the private key template: its tag (0x91 to 0x99) and value.
    struct Part: Equatable {
        let tag: UInt8
        var value: [UInt8]
    }

    /// BER length octets: one, two or three. Nil past 0xFFFF, which no key
    /// this moves comes near.
    static func berLength(_ n: Int) -> [UInt8]? {
        if n < 0 { return nil }
        if n < 0x80 { return [UInt8(n)] }
        if n <= 0xFF { return [0x81, UInt8(n)] }
        if n <= 0xFFFF { return [0x82, UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)] }
        return nil
    }

    /// The Extended Header List for `slot`:
    /// 4D L { CRT 00, 7F48 L { tag len ... }, 5F48 L { values } }.
    /// Built in one exactly sized array, so no growing buffer leaves a copy
    /// of the key bytes behind.
    static func extendedHeaderList(slot: Slot, parts: [Part]) throws -> [UInt8] {
        var template: [UInt8] = []
        var dataLength = 0
        for part in parts {
            guard let len = berLength(part.value.count) else { throw KeyToCardError.unsupported }
            template.append(part.tag)
            template += len
            dataLength += part.value.count
        }
        guard let templateLen = berLength(template.count), let dataLen = berLength(dataLength) else {
            throw KeyToCardError.unsupported
        }
        let bodyLength = 2 + 2 + templateLen.count + template.count + 2 + dataLen.count + dataLength
        guard let bodyLen = berLength(bodyLength) else { throw KeyToCardError.unsupported }

        var out = [UInt8](repeating: 0, count: 1 + bodyLen.count + bodyLength)
        var i = 0
        func putByte(_ b: UInt8) { out[i] = b; i += 1 }
        func putBytes(_ bytes: [UInt8]) { for b in bytes { out[i] = b; i += 1 } }
        putByte(0x4D); putBytes(bodyLen)
        putByte(slot.crt); putByte(0x00)
        putByte(0x7F); putByte(0x48); putBytes(templateLen); putBytes(template)
        putByte(0x5F); putByte(0x48); putBytes(dataLen)
        for part in parts { putBytes(part.value) }
        guard i == out.count else { throw KeyToCardError.unsupported }
        return out
    }

    /// `value` (big-endian, leading zeros allowed) as exactly `length`
    /// octets, left-padded. Throws when it does not fit.
    static func fixed(_ value: [UInt8], _ length: Int) throws -> [UInt8] {
        let start = value.firstIndex { $0 != 0 } ?? value.count
        let significant = value.count - start
        guard significant <= length else { throw KeyToCardError.unsupported }
        var out = [UInt8](repeating: 0, count: length)
        for k in 0..<significant { out[length - significant + k] = value[start + k] }
        return out
    }

    /// The RSA parts for import format `format` (00/01 standard, 02/03 CRT;
    /// 01 and 03 add the modulus). `u` is OpenPGP's 1/p mod q; the card
    /// wants 1/q mod p, which is derived from it (and checked).
    static func rsaParts(e: [UInt8], p: [UInt8], q: [UInt8], d: [UInt8], u: [UInt8],
                         nBits: Int, eBits: Int, format: UInt8) throws -> [Part] {
        let eLength = (eBits + 7) / 8
        let half = nBits / 16
        let eValue = try fixed(e, eLength)
        let pValue = try fixed(p, half)
        let qValue = try fixed(q, half)
        var parts = [Part(tag: 0x91, value: eValue), Part(tag: 0x92, value: pValue), Part(tag: 0x93, value: qValue)]
        var bp = BigNum(bytes: p), bq = BigNum(bytes: q)
        defer { bp.wipe(); bq.wipe() }
        if format == rsaFormatCRT || format == 0x03 {
            var bd = BigNum(bytes: d), bu = BigNum(bytes: u)
            defer { bd.wipe(); bu.wipe() }
            guard var qInv = BigNum.inverseOfQModP(p: bp, q: bq, openPGPU: bu) else { throw KeyToCardError.unsupported }
            var dp = BigNum.divMod(bd, bp - BigNum(1)).remainder
            var dq = BigNum.divMod(bd, bq - BigNum(1)).remainder
            defer { qInv.wipe(); dp.wipe(); dq.wipe() }
            parts.append(Part(tag: 0x94, value: try fixed(qInv.bytes(), half)))
            parts.append(Part(tag: 0x95, value: try fixed(dp.bytes(), half)))
            parts.append(Part(tag: 0x96, value: try fixed(dq.bytes(), half)))
        }
        if format == 0x01 || format == 0x03 {
            parts.append(Part(tag: 0x97, value: try fixed((bp * bq).bytes(), nBits / 8)))
        }
        return parts
    }

    /// The parts for an EC key: 92 with the private scalar or seed.
    static func ecParts(_ secret: [UInt8]) -> [Part] {
        [Part(tag: 0x92, value: secret)]
    }

    // MARK: - Unlocked secrets

    /// One key's secret, read from an unprotected v4 secret packet. Held in a
    /// class so the bytes live in one place and wipe() reaches them.
    final class UnlockedKey {
        let packet: KeyPacket
        let kind: Kind
        let rsaBits: Int
        // RSA: OpenPGP's d, p, q, u (u = 1/p mod q).
        private(set) var rsaD: [UInt8] = []
        private(set) var rsaP: [UInt8] = []
        private(set) var rsaQ: [UInt8] = []
        private(set) var rsaU: [UInt8] = []
        /// Ed25519: the 32-octet seed.
        private(set) var seed: [UInt8] = []
        /// Cv25519: the clamped X25519 scalar in native (RFC 7748, little-endian) order.
        private(set) var x25519Native: [UInt8] = []

        init(packet: KeyPacket, kind: Kind, rsaBits: Int) {
            self.packet = packet
            self.kind = kind
            self.rsaBits = rsaBits
        }

        fileprivate func setRSA(d: [UInt8], p: [UInt8], q: [UInt8], u: [UInt8]) {
            rsaD = d; rsaP = p; rsaQ = q; rsaU = u
        }
        fileprivate func setSeed(_ s: [UInt8]) { seed = s }
        fileprivate func setX25519(_ s: [UInt8]) { x25519Native = s }

        /// Bit length of the public exponent.
        var rsaExponentBitLength: Int { packet.rsaExponent.map(KeyToCard.bitLength) ?? 0 }

        /// RSA import parts for a slot whose exponent field is `eBits` wide.
        func rsaParts(eBits: Int, format: UInt8) throws -> [Part] {
            guard kind == .rsa, let e = packet.rsaExponent else { throw KeyToCardError.unsupported }
            return try KeyToCard.rsaParts(e: e, p: rsaP, q: rsaQ, d: rsaD, u: rsaU,
                                          nBits: rsaBits, eBits: eBits, format: format)
        }

        /// A copy of the X25519 secret: native (RFC 7748) order, or the order
        /// OpenPGP stores it in (big-endian, what gpg and ykman send). Which
        /// one a card wants is settled by testing the slot after the import.
        func cv25519Secret(native: Bool) -> [UInt8] {
            native ? x25519Native : Array(x25519Native.reversed())
        }

        func wipe() {
            KeyToCard.wipe(&rsaD); KeyToCard.wipe(&rsaP); KeyToCard.wipe(&rsaQ); KeyToCard.wipe(&rsaU)
            KeyToCard.wipe(&seed); KeyToCard.wipe(&x25519Native)
        }
    }

    /// Read the secret of an UNPROTECTED v4 secret packet body (S2K usage 0,
    /// as ChangePassphraseService leaves it with no new passphrase). Each
    /// secret is checked against the packet's own public key: n = p * q for
    /// RSA, the derived public point for Ed25519 and Cv25519.
    static func unlockedKey(unprotectedSecretBody body: [UInt8]) throws -> UnlockedKey {
        guard let key = keyPacket(body: body), case .movable(let kind, let rsaBits) = key.eligibility else {
            throw KeyToCardError.unsupported
        }
        let usageIndex = key.publicBody.count
        guard usageIndex < body.count, body[usageIndex] == 0, body.count >= usageIndex + 3 else {
            throw KeyToCardError.secretUnreadable
        }
        var material = Array(body[(usageIndex + 1)..<(body.count - 2)])
        defer { wipe(&material) }
        let stored = UInt16(body[body.count - 2]) << 8 | UInt16(body[body.count - 1])
        let sum = material.reduce(UInt16(0)) { $0 &+ UInt16($1) }
        guard sum == stored else { throw KeyToCardError.secretUnreadable }

        let unlocked = UnlockedKey(packet: key, kind: kind, rsaBits: rsaBits)
        var o = 0
        switch kind {
        case .rsa:
            guard var d = readMPI(material, &o), var p = readMPI(material, &o),
                  var q = readMPI(material, &o), var u = readMPI(material, &o),
                  let n = key.rsaModulus else { throw KeyToCardError.secretUnreadable }
            var product = BigNum(bytes: p) * BigNum(bytes: q)
            let matches = product == BigNum(bytes: n)
            product.wipe()
            guard matches else {
                wipe(&d); wipe(&p); wipe(&q); wipe(&u)
                throw KeyToCardError.secretUnreadable
            }
            unlocked.setRSA(d: d, p: p, q: q, u: u)
            wipe(&d); wipe(&p); wipe(&q); wipe(&u)
        case .ed25519:
            guard var raw = readMPI(material, &o), raw.count <= 32, let point = key.point25519 else {
                throw KeyToCardError.secretUnreadable
            }
            var seed = PGPService.leftPad32(raw)
            wipe(&raw)
            guard let derived = try? Curve25519.Signing.PrivateKey(rawRepresentation: Data(seed)),
                  Array(derived.publicKey.rawRepresentation) == point else {
                wipe(&seed)
                throw KeyToCardError.secretUnreadable
            }
            unlocked.setSeed(seed)
            wipe(&seed)
        case .cv25519:
            guard var raw = readMPI(material, &o), raw.count <= 32, let point = key.point25519 else {
                throw KeyToCardError.secretUnreadable
            }
            // Keys made by PGPony before 7.1.1 stored the scalar little-endian
            // and sometimes with a short MPI header; the public point decides.
            let physical: [UInt8]? = material.count == 34 ? Array(material[2..<34]) : nil
            guard let resolved = PGPService.resolveCv25519Scalar(wireBytes: raw, physical32: physical, publicPoint: point) else {
                wipe(&raw)
                throw KeyToCardError.secretUnreadable
            }
            wipe(&raw)
            var scalar = clampX25519(resolved.leScalar)
            unlocked.setX25519(scalar)
            wipe(&scalar)
        }
        return unlocked
    }

    /// RFC 7748 clamping of a little-endian X25519 scalar. X25519 clamps
    /// anyway, so the public key and every shared secret stay the same; the
    /// card gets the form gpg would send.
    static func clampX25519(_ le: [UInt8]) -> [UInt8] {
        guard le.count == 32 else { return le }
        var k = le
        k[0] &= 248
        k[31] &= 127
        k[31] |= 64
        return k
    }

    // MARK: - The stub left on the device

    /// A v4 secret packet body with its secret replaced by the stub gpg writes
    /// for a key whose secret is on a card: S2K usage 255, cipher 0, S2K type
    /// 101 with hash 0, "GNU", mode 2 (1002, divert to card), then the card's
    /// application ID (1 to 16 octets) prefixed by its length. Exported, it
    /// goes back into gpg as `ssb>` (or `sec>`).
    static func divertToCardStubBody(secretBody body: [UInt8], cardAID: [UInt8]) throws -> [UInt8] {
        guard (1...16).contains(cardAID.count), let key = keyPacket(body: body), key.version == 4 else {
            throw KeyToCardError.unsupported
        }
        return key.publicBody + [0xFF, 0x00, 0x65, 0x00, 0x47, 0x4E, 0x55, 0x02, UInt8(cardAID.count)] + cardAID
    }

    /// `secretRing` with the secret packets of the keys in `fingerprints`
    /// (uppercase hex) replaced by divert-to-card stubs. Every other packet
    /// keeps its body byte for byte.
    static func divertToCardStubRing(secretRing: [UInt8], fingerprints: Set<String>, cardAID: [UInt8]) throws -> [UInt8] {
        let packets = try OpenPGPPacketParser.parsePackets(data: secretRing)
        var out: [UInt8] = []
        var replaced = 0
        for packet in packets {
            if packet.tag == 5 || packet.tag == 7,
               let key = keyPacket(body: packet.body), fingerprints.contains(key.fingerprintHex) {
                out += CertificationService.newFormatPacket(tag: packet.tag,
                                                            body: try divertToCardStubBody(secretBody: packet.body, cardAID: cardAID))
                replaced += 1
            } else {
                out += CertificationService.newFormatPacket(tag: packet.tag, body: packet.body)
            }
        }
        guard replaced == fingerprints.count else { throw KeyToCardError.secretUnreadable }
        return out
    }

    // MARK: - Helpers

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }

    /// Hex (as OpenPGPCardInfo.aidHex carries it) to octets; nil when not hex.
    static func bytes(hex: String) -> [UInt8]? {
        let chars = Array(hex.filter { !$0.isWhitespace })
        guard chars.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let b = UInt8(String(chars[i...(i + 1)]), radix: 16) else { return nil }
            out.append(b)
            i += 2
        }
        return out
    }

    static func be32(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }

    /// Bit length of a big-endian unsigned value.
    static func bitLength(_ bytes: [UInt8]) -> Int {
        guard let i = bytes.firstIndex(where: { $0 != 0 }) else { return 0 }
        return (bytes.count - i - 1) * 8 + (8 - bytes[i].leadingZeroBitCount)
    }

    static func readMPI(_ b: [UInt8], _ o: inout Int) -> [UInt8]? {
        guard o + 2 <= b.count else { return nil }
        let bits = Int(b[o]) << 8 | Int(b[o + 1])
        let length = (bits + 7) / 8
        guard o + 2 + length <= b.count else { return nil }
        defer { o += 2 + length }
        return Array(b[(o + 2)..<(o + 2 + length)])
    }

    private static func readLengthPrefixed(_ b: [UInt8], _ o: inout Int) -> [UInt8]? {
        guard o < b.count else { return nil }
        let n = Int(b[o])
        guard n != 0, n != 0xFF, o + 1 + n <= b.count else { return nil }
        defer { o += 1 + n }
        return Array(b[(o + 1)..<(o + 1 + n)])
    }

    /// Overwrite `bytes` with zeros in place (best effort, see the header).
    static func wipe(_ bytes: inout [UInt8]) {
        bytes.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress, raw.count > 0 else { return }
            _ = memset_s(base, rsize_t(raw.count), 0, rsize_t(raw.count))
        }
    }

    static func wipe(_ parts: inout [Part]) {
        for i in parts.indices { wipe(&parts[i].value) }
    }
}

// MARK: - Unsigned big integers (RSA CRT values only)

/// Just enough arbitrary-precision arithmetic for the card's RSA CRT parts:
/// multiply, subtract, divide with remainder and a modular inverse. Limbs are
/// 32-bit, least significant first, with no trailing zero limbs. Not constant
/// time; it runs once per move on the user's own key, on the device.
struct BigNum: Equatable {
    private(set) var limbs: [UInt32]

    init() { limbs = [] }

    init(_ v: UInt32) { limbs = v == 0 ? [] : [v] }

    init(limbs: [UInt32]) {
        self.limbs = limbs
        normalize()
    }

    /// From big-endian octets.
    init(bytes: [UInt8]) {
        var out: [UInt32] = []
        out.reserveCapacity(bytes.count / 4 + 1)
        var i = bytes.count
        while i > 0 {
            var limb: UInt32 = 0
            let start = Swift.max(0, i - 4)
            for k in start..<i { limb = (limb << 8) | UInt32(bytes[k]) }
            out.append(limb)
            i = start
        }
        limbs = out
        normalize()
    }

    private mutating func normalize() {
        while let last = limbs.last, last == 0 { limbs.removeLast() }
    }

    var isZero: Bool { limbs.isEmpty }

    /// Big-endian octets with no leading zeros ([] for zero).
    func bytes() -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(limbs.count * 4)
        for limb in limbs.reversed() {
            out.append(UInt8((limb >> 24) & 0xFF)); out.append(UInt8((limb >> 16) & 0xFF))
            out.append(UInt8((limb >> 8) & 0xFF)); out.append(UInt8(limb & 0xFF))
        }
        let start = out.firstIndex { $0 != 0 } ?? out.count
        return Array(out[start...])
    }

    mutating func wipe() {
        for i in limbs.indices { limbs[i] = 0 }
        limbs = []
    }

    static func compare(_ a: BigNum, _ b: BigNum) -> Int {
        if a.limbs.count != b.limbs.count { return a.limbs.count < b.limbs.count ? -1 : 1 }
        var i = a.limbs.count - 1
        while i >= 0 {
            if a.limbs[i] != b.limbs[i] { return a.limbs[i] < b.limbs[i] ? -1 : 1 }
            i -= 1
        }
        return 0
    }

    static func + (a: BigNum, b: BigNum) -> BigNum {
        let n = Swift.max(a.limbs.count, b.limbs.count)
        var out = [UInt32](repeating: 0, count: n + 1)
        var carry: UInt64 = 0
        for i in 0..<n {
            let s = UInt64(i < a.limbs.count ? a.limbs[i] : 0) + UInt64(i < b.limbs.count ? b.limbs[i] : 0) + carry
            out[i] = UInt32(truncatingIfNeeded: s)
            carry = s >> 32
        }
        out[n] = UInt32(carry)
        return BigNum(limbs: out)
    }

    /// a - b; requires a >= b.
    static func - (a: BigNum, b: BigNum) -> BigNum {
        precondition(compare(a, b) >= 0, "BigNum subtraction underflow")
        var out = a.limbs
        var borrow: Int64 = 0
        for i in 0..<out.count {
            let t = Int64(out[i]) - borrow - Int64(i < b.limbs.count ? b.limbs[i] : 0)
            out[i] = UInt32(truncatingIfNeeded: t)
            borrow = t < 0 ? 1 : 0
        }
        return BigNum(limbs: out)
    }

    static func * (a: BigNum, b: BigNum) -> BigNum {
        if a.isZero || b.isZero { return BigNum() }
        var out = [UInt32](repeating: 0, count: a.limbs.count + b.limbs.count)
        for i in 0..<a.limbs.count {
            var carry: UInt64 = 0
            let ai = UInt64(a.limbs[i])
            for j in 0..<b.limbs.count {
                let t = ai * UInt64(b.limbs[j]) + UInt64(out[i + j]) + carry
                out[i + j] = UInt32(truncatingIfNeeded: t)
                carry = t >> 32
            }
            out[i + b.limbs.count] = UInt32(carry)
        }
        return BigNum(limbs: out)
    }

    /// Quotient and remainder: schoolbook long division with a normalized
    /// divisor (the classic Algorithm D). `b` must not be zero.
    static func divMod(_ a: BigNum, _ b: BigNum) -> (quotient: BigNum, remainder: BigNum) {
        precondition(!b.isZero, "BigNum division by zero")
        if compare(a, b) < 0 { return (BigNum(), a) }
        let n = b.limbs.count
        if n == 1 {
            let d = UInt64(b.limbs[0])
            var q = [UInt32](repeating: 0, count: a.limbs.count)
            var r: UInt64 = 0
            var i = a.limbs.count - 1
            while i >= 0 {
                let cur = (r << 32) | UInt64(a.limbs[i])
                q[i] = UInt32(truncatingIfNeeded: cur / d)
                r = cur % d
                i -= 1
            }
            return (BigNum(limbs: q), BigNum(limbs: [UInt32(r)]))
        }

        let m = a.limbs.count
        let s = UInt64(b.limbs[n - 1].leadingZeroBitCount)
        // Normalize so the divisor's top limb has its high bit set.
        var vn = [UInt32](repeating: 0, count: n)
        for i in stride(from: n - 1, to: 0, by: -1) {
            let hi = UInt64(b.limbs[i]) << s
            let lo = s == 0 ? 0 : UInt64(b.limbs[i - 1]) >> (32 - s)
            vn[i] = UInt32(truncatingIfNeeded: hi | lo)
        }
        vn[0] = UInt32(truncatingIfNeeded: UInt64(b.limbs[0]) << s)
        var un = [UInt32](repeating: 0, count: m + 1)
        un[m] = s == 0 ? 0 : UInt32(truncatingIfNeeded: UInt64(a.limbs[m - 1]) >> (32 - s))
        for i in stride(from: m - 1, to: 0, by: -1) {
            let hi = UInt64(a.limbs[i]) << s
            let lo = s == 0 ? 0 : UInt64(a.limbs[i - 1]) >> (32 - s)
            un[i] = UInt32(truncatingIfNeeded: hi | lo)
        }
        un[0] = UInt32(truncatingIfNeeded: UInt64(a.limbs[0]) << s)

        let base: UInt64 = 1 << 32
        var q = [UInt32](repeating: 0, count: m - n + 1)
        var j = m - n
        while j >= 0 {
            let num = (UInt64(un[j + n]) << 32) | UInt64(un[j + n - 1])
            var qhat = num / UInt64(vn[n - 1])
            var rhat = num % UInt64(vn[n - 1])
            while qhat >= base || qhat * UInt64(vn[n - 2]) > ((rhat << 32) | UInt64(un[j + n - 2])) {
                qhat -= 1
                rhat += UInt64(vn[n - 1])
                if rhat >= base { break }
            }
            // Multiply and subtract.
            var k: Int64 = 0
            var t: Int64 = 0
            for i in 0..<n {
                let p = qhat * UInt64(vn[i])
                t = Int64(un[i + j]) - k - Int64(p & 0xFFFF_FFFF)
                un[i + j] = UInt32(truncatingIfNeeded: t)
                k = Int64(p >> 32) - (t >> 32)
            }
            t = Int64(un[j + n]) - k
            un[j + n] = UInt32(truncatingIfNeeded: t)
            q[j] = UInt32(truncatingIfNeeded: qhat)
            if t < 0 {
                // Subtracted one time too many: add the divisor back.
                q[j] = q[j] &- 1
                var c: UInt64 = 0
                for i in 0..<n {
                    let sum = UInt64(un[i + j]) + UInt64(vn[i]) + c
                    un[i + j] = UInt32(truncatingIfNeeded: sum)
                    c = sum >> 32
                }
                un[j + n] = un[j + n] &+ UInt32(truncatingIfNeeded: c)
            }
            j -= 1
        }

        // Unnormalize the remainder.
        var r = [UInt32](repeating: 0, count: n)
        for i in 0..<n {
            let lo = UInt64(un[i]) >> s
            let hi = s == 0 ? 0 : UInt64(un[i + 1]) << (32 - s)
            r[i] = UInt32(truncatingIfNeeded: lo | hi)
        }
        for i in un.indices { un[i] = 0 }
        return (BigNum(limbs: q), BigNum(limbs: r))
    }

    /// base ^ exponent mod modulus (square and multiply).
    static func modPow(_ base: BigNum, _ exponent: BigNum, _ modulus: BigNum) -> BigNum {
        var result = divMod(BigNum(1), modulus).remainder
        var b = divMod(base, modulus).remainder
        for limb in exponent.limbs {
            var bitsLeft = limb
            for _ in 0..<32 {
                if bitsLeft & 1 == 1 { result = divMod(result * b, modulus).remainder }
                b = divMod(b * b, modulus).remainder
                bitsLeft >>= 1
            }
        }
        return result
    }

    /// 1/q mod p for the card's CRT form. OpenPGP stores u = 1/p mod q (with
    /// p < q); then u*p = 1 + k*q, so q * (-k) = 1 mod p and the inverse is
    /// p - (k mod p). A key whose u is already 1/q mod p is taken as it is,
    /// and if neither holds, q^(p-2) mod p (p is prime). Every answer is checked.
    static func inverseOfQModP(p: BigNum, q: BigNum, openPGPU u: BigNum) -> BigNum? {
        guard !p.isZero, !q.isZero else { return nil }
        let one = BigNum(1)
        func isInverse(_ x: BigNum) -> Bool {
            !x.isZero && divMod(x * q, p).remainder == one
        }
        if !u.isZero {
            let direct = divMod(u, p).remainder
            if isInverse(direct) { return direct }
            let up = u * p
            if compare(up, one) > 0 {
                let (k, rest) = divMod(up - one, q)
                if rest.isZero {
                    let km = divMod(k, p).remainder
                    if !km.isZero {
                        let candidate = p - km
                        if isInverse(candidate) { return candidate }
                    }
                }
            }
        }
        guard compare(p, BigNum(2)) > 0 else { return nil }
        let byPower = modPow(q, p - BigNum(2), p)
        return isInverse(byPower) ? byPower : nil
    }
}

// CORE SEAM: in the app this error lives in KeyToCardService.swift, the
// orchestration layer (Keychain, SwiftData) that drives KeyToCard. The core
// keeps the error, since KeyToCard throws it.
enum KeyToCardError: LocalizedError, Equatable {
    case nothingToMove
    case oneKeyPerSlot
    case pinsRequired
    case wrongPassphrase
    case secretUnreadable
    case unsupported
    case slotsOccupied
    case wrongAdminPIN(retriesRemaining: Int?)
    case adminPINBlocked
    case checkFailed
    case noCardSerial
    case noPublicKey
    case notStored(String)

    var errorDescription: String? {
        switch self {
        case .nothingToMove:
            return String(localized: "Choose at least one key to move.")
        case .oneKeyPerSlot:
            return String(localized: "Each key can go to one slot only.")
        case .pinsRequired:
            return String(localized: "Enter the admin PIN and the user PIN.")
        case .wrongPassphrase:
            return String(localized: "The passphrase is incorrect. Nothing was sent to the hardware key.")
        case .secretUnreadable:
            return String(localized: "The private part of this key could not be read on this device, so it can't be moved. Nothing was sent to the hardware key.")
        case .unsupported:
            return String(localized: "This hardware key cannot hold one of the chosen keys. Choose another key or slot.")
        case .slotsOccupied:
            return String(localized: "A chosen slot on this hardware key already holds another key. Turn on Replace keys already in the chosen slots to overwrite it. Nothing was written.")
        case .wrongAdminPIN(let n):
            if let n {
                return String(localized: "Incorrect admin PIN (PW3). \(n) attempts remaining before the admin PIN is blocked. Nothing was written.")
            }
            return String(localized: "Incorrect admin PIN (PW3). Nothing was written.")
        case .adminPINBlocked:
            return String(localized: "The admin PIN (PW3) is blocked, so keys can't be written to this hardware key. Nothing was written.")
        case .checkFailed:
            return String(localized: "The hardware key did not pass the check after the keys were written, so nothing on this device was changed. Do not rely on the keys on the hardware key.")
        case .noCardSerial:
            return String(localized: "The keys are on the hardware key and passed the check, but it did not report its serial, so the private keys were not removed from this device. Your key on this device is unchanged.")
        case .noPublicKey:
            return String(localized: "The keys are on the hardware key and passed the check, but this key's public part could not be read, so the private keys were not removed from this device. Your key on this device is unchanged.")
        case .notStored(let detail):
            return String(localized: "The keys are on the hardware key and passed the check, but this device could not save the change: \(detail). Your key on this device is unchanged.")
        }
    }
}
