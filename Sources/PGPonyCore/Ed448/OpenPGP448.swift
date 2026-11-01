// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// OpenPGP448.swift
// PGPony
//
// 8.4.0 build 9 (plan 5l): Ed448 and X448 keys, in the two wire forms they
// arrive in.
//
//   LibrePGP v5 (what GnuPG 2.4 and Kleopatra make for ed448 / cv448):
//     - key packets carry a 4-octet key material length; the fingerprint is
//       SHA-256(0x9A | 4-octet length | body) and the key ID its leftmost 64
//       bits;
//     - Ed448 is algorithm 22 with the curve OID 1.3.101.113, the 57-octet
//       point as an MPI (no 0x40 prefix from GnuPG, accepted with one);
//     - X448 is ECDH (algorithm 18) with the OID 1.3.101.111, the bare
//       56-octet value as an MPI, and the RFC 6637 KDF with the leftmost 20
//       octets of the v5 fingerprint;
//     - signatures are version 5: the hashed area keeps v4's 2-octet length,
//       the trailer is 0x05 0xFF and an 8-octet length, and a document
//       signature (0x00, 0x01) also hashes the literal packet's format,
//       file name and date (zeros for a detached signature, "t" and zeros for
//       a cleartext one), placed after the hashed area;
//     - a v4 subkey may sit under a v5 primary; its binding frames the subkey
//       by its own version.
//
//   RFC 9580 v6 native (algorithms 28 and 26):
//     - Ed448: 57-octet public key, 114-octet signature, PureEdDSA with an
//       empty context over the signature digest;
//     - X448: 56-octet public key, a v6 (or v3) PKESK with a 56-octet
//       ephemeral, HKDF-SHA512 over ephemeral | recipient | shared with the
//       info "OpenPGP X448", and AES-256 key wrap of the bare session key.
//
// The curve arithmetic is Ed448.swift and X448.swift (unchanged). This file
// holds the packet-level pieces shared by the parser, the builder, the
// signing service and the import views. No key generation: these keys are
// use only.

import Foundation
import CryptoKit
import CommonCrypto

/// An unlocked Ed448 signing component (primary or subkey).
struct Ed448SigningKey {
    /// The 57-octet RFC 8032 secret seed.
    let seed: [UInt8]
    /// The 57-octet public key.
    let publicKey: [UInt8]
    /// 5 for a LibrePGP key (algorithm 22), 6 for an RFC 9580 key (algorithm 28).
    let keyVersion: UInt8
    /// The component's own 32-octet v5 or v6 fingerprint.
    let fingerprint: [UInt8]

    var keyID: [UInt8] { Array(fingerprint.prefix(8)) }
    var publicKeyAlgorithm: UInt8 { keyVersion == 6 ? 28 : 22 }
}

enum OpenPGP448 {

    static let ed448OID: [UInt8] = [0x2B, 0x65, 0x71]
    static let x448OID: [UInt8] = [0x2B, 0x65, 0x6F]
    static let ed25519LegacyOID: [UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]

    /// SHA-512 for every signature this app makes with an Ed448 key (RFC 9580
    /// asks for a digest of at least 512 bits with Ed448; GnuPG uses it too).
    static let signatureHashAlgorithm: UInt8 = 10
    /// The v6 salt length for SHA-512 (RFC 9580 table 23).
    static let v6SaltLength = 32

    /// What a v5 data signature hashes for a detached signature.
    static let detachedLiteralMetadata: [UInt8] = [0, 0, 0, 0, 0, 0]
    /// What a v5 data signature hashes for a cleartext signature: GnuPG reads
    /// the cleartext as a text literal with no name and date 0.
    static let cleartextLiteralMetadata: [UInt8] = [0x74, 0, 0, 0, 0, 0]

    enum Failure: LocalizedError {
        case unreadableKey
        case unsupportedProtection
        case noSigningComponent

        var errorDescription: String? {
            switch self {
            case .unreadableKey:
                return String(localized: "This key uses a format PGPony can't read yet.")
            case .unsupportedProtection:
                return String(localized: "This key's secret part is protected in a way PGPony can't open yet.")
            case .noSigningComponent:
                return String(localized: "This key has no Sign-capable component; it appears to be certification-only. Use a key with a signing subkey or a Sign-capable primary.")
            }
        }
    }

    // MARK: - Key packets

    /// The public part of a key packet body, public or secret, of key
    /// version 4, 5 or 6. Nil when it does not parse.
    static func publicBody(ofKeyBody body: [UInt8]) -> [UInt8]? {
        guard body.count > 5, let version = body.first else { return nil }
        switch version {
        case 5, 6:
            guard body.count >= 10 else { return nil }
            let n = Int(body[6]) << 24 | Int(body[7]) << 16 | Int(body[8]) << 8 | Int(body[9])
            guard n > 0, 10 + n <= body.count else { return nil }
            return Array(body[0..<(10 + n)])
        case 4:
            if let prefix = OpenPGPPacketParser.v4PublicPrefix(secretBody: body) { return prefix }
            // A v4 key with a native RFC 9580 algorithm (no OID, no MPI).
            guard let length = OpenPGPPacketParser.v6NativeKeyLength(for: body[5]),
                  6 + length <= body.count else { return nil }
            return Array(body[0..<(6 + length)])
        default:
            return nil
        }
    }

    /// SHA-256(0x9A | 4-octet length | body), the LibrePGP v5 fingerprint.
    static func v5Fingerprint(publicBody body: [UInt8]) -> [UInt8] {
        let n = body.count
        var framed: [UInt8] = [0x9A, UInt8((n >> 24) & 0xFF), UInt8((n >> 16) & 0xFF),
                               UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)]
        framed.append(contentsOf: body)
        return Array(SHA256.hash(data: Data(framed)))
    }

    /// The fingerprint of a key packet body (public or secret) of key version
    /// 4, 5 or 6, from its public part.
    static func fingerprint(ofKeyBody body: [UInt8]) -> [UInt8]? {
        guard let pub = publicBody(ofKeyBody: body) else { return nil }
        return CertificateValidator.fingerprint(ofKeyBody: pub)
    }

    /// Lowercase hex of `fingerprint(ofKeyBody:)`.
    static func fingerprintHex(ofKeyBody body: [UInt8]) -> String? {
        fingerprint(ofKeyBody: body).map { $0.map { String(format: "%02x", $0) }.joined() }
    }

    /// The key ID of a key packet: the low 64 bits of a v4 fingerprint, the
    /// high 64 bits of a v5 or v6 one.
    static func keyID(ofKeyBody body: [UInt8]) -> [UInt8]? {
        guard let fp = fingerprint(ofKeyBody: body) else { return nil }
        return body.first == 4 ? Array(fp.suffix(8)) : Array(fp.prefix(8))
    }

    enum Curve { case ed448, x448 }

    /// An Ed448 or X448 key component read off its public part.
    struct Component {
        let curve: Curve
        let keyVersion: UInt8
        let algorithm: UInt8
        /// 57 octets (Ed448) or 56 octets (X448), raw.
        let publicKey: [UInt8]
        /// ECDH KDF parameters (algorithm 18 only; 0 otherwise).
        let kdfHash: UInt8
        let kdfCipher: UInt8
        let publicBody: [UInt8]
        let fingerprint: [UInt8]

        var keyID: [UInt8] { keyVersion == 4 ? Array(fingerprint.suffix(8)) : Array(fingerprint.prefix(8)) }
    }

    /// The Ed448 or X448 component in a key packet body (public or secret),
    /// in either wire form. Nil for any other key.
    static func component(keyBody body: [UInt8]) -> Component? {
        guard let pub = publicBody(ofKeyBody: body), pub.count > 6 else { return nil }
        let version = pub[0]
        let algorithm = pub[5]
        let material = Array(pub[(version == 4 ? 6 : 10)...])
        let fp = CertificateValidator.fingerprint(ofKeyBody: pub)
        switch algorithm {
        case 28:
            guard material.count == 57 else { return nil }
            return Component(curve: .ed448, keyVersion: version, algorithm: 28, publicKey: material,
                             kdfHash: 0, kdfCipher: 0, publicBody: pub, fingerprint: fp)
        case 26:
            guard material.count == 56 else { return nil }
            return Component(curve: .x448, keyVersion: version, algorithm: 26, publicKey: material,
                             kdfHash: 0, kdfCipher: 0, publicBody: pub, fingerprint: fp)
        case 22, 18:
            guard material.count > 1 else { return nil }
            let oidLength = Int(material[0])
            guard oidLength > 0, 1 + oidLength <= material.count else { return nil }
            let oid = Array(material[1..<(1 + oidLength)])
            var o = 1 + oidLength
            guard let point = readMPI(material, &o) else { return nil }
            if algorithm == 22 {
                guard oid == ed448OID, let p = normalized(point, length: 57) else { return nil }
                return Component(curve: .ed448, keyVersion: version, algorithm: 22, publicKey: p,
                                 kdfHash: 0, kdfCipher: 0, publicBody: pub, fingerprint: fp)
            }
            guard oid == x448OID, let p = normalized(point, length: 56) else { return nil }
            // KDF parameters: length(1) | 0x01 | hash | cipher.
            guard o < material.count else { return nil }
            let kdfLength = Int(material[o])
            guard kdfLength >= 3, o + 1 + kdfLength <= material.count, material[o + 1] == 1 else { return nil }
            return Component(curve: .x448, keyVersion: version, algorithm: 18, publicKey: p,
                             kdfHash: material[o + 2], kdfCipher: material[o + 3],
                             publicBody: pub, fingerprint: fp)
        default:
            return nil
        }
    }

    /// A point read from an MPI: a 0x40 prefix dropped, leading zeros put back.
    private static func normalized(_ value: [UInt8], length: Int) -> [UInt8]? {
        var v = value
        if v.count == length + 1, v.first == 0x40 { v.removeFirst() }
        guard !v.isEmpty, v.count <= length else { return nil }
        return [UInt8](repeating: 0, count: length - v.count) + v
    }

    static func isEd448(keyBody body: [UInt8]) -> Bool { component(keyBody: body)?.curve == .ed448 }
    static func isX448(keyBody body: [UInt8]) -> Bool { component(keyBody: body)?.curve == .x448 }

    /// The model algorithm of a key block whose primary is an Ed448 key (or,
    /// for a key that is only X448, whose encryption subkey is X448). Nil for
    /// every other key, so the caller's own detection stands.
    static func keyAlgorithm(packets: [ParsedPacket]) -> KeyAlgorithm? {
        guard let primary = packets.first(where: { $0.tag == 6 || $0.tag == 5 }),
              let c = component(keyBody: primary.body) else { return nil }
        if c.keyVersion == 6 { return c.curve == .ed448 ? .v6Ed448 : .v6X448 }
        return .librePGPEd448
    }

    /// Same, from raw (binary) key data.
    static func keyAlgorithm(keyData: [UInt8]) -> KeyAlgorithm? {
        guard let packets = try? OpenPGPPacketParser.parsePackets(data: keyData) else { return nil }
        return keyAlgorithm(packets: packets)
    }

    // MARK: - Secret material

    /// The unlocked secret key material (the algorithm-specific secret fields)
    /// of a v4, v5 or v6 secret key packet. `packetTag` is 5 or 7 (it enters
    /// the v6 AEAD associated data). Throws `PGPServiceError.passphraseRequired`
    /// for a protected key without a passphrase and
    /// `PGPServiceError.invalidPassphrase` when the passphrase is wrong.
    static func secretMaterial(secretBody body: [UInt8], passphrase: String?, packetTag: UInt8) throws -> [UInt8] {
        guard let pub = publicBody(ofKeyBody: body), body.count > pub.count else { throw Failure.unreadableKey }
        let version = body[0]
        var o = pub.count
        let usage = body[o]; o += 1

        if version == 6 {
            switch usage {
            case 0:
                return Array(body[o...])
            case 253:
                guard let passphrase, !passphrase.isEmpty else { throw PGPServiceError.passphraseRequired }
                let expected = component(keyBody: body)?.curve == .x448 ? 56 : 57
                var offset = o
                return try PGPService.shared.decryptV6SecretKeyMaterial(
                    body: body, offset: &offset, publicBody: pub,
                    packetTagID: packetTag == 5 ? 0xC5 : 0xC7,
                    passphrase: passphrase, expectedKeyLen: expected)
            default:
                throw Failure.unsupportedProtection
            }
        }

        if version == 5 {
            // usage | parameter count(1) | parameters | material length(4) |
            // material | checksum(2, usage 0 only)
            guard o < body.count else { throw Failure.unreadableKey }
            let count = Int(body[o]); o += 1
            guard o + count + 4 <= body.count else { throw Failure.unreadableKey }
            let parameters = Array(body[o..<(o + count)]); o += count
            let n = Int(body[o]) << 24 | Int(body[o + 1]) << 16 | Int(body[o + 2]) << 8 | Int(body[o + 3])
            o += 4
            guard n > 0, o + n <= body.count else { throw Failure.unreadableKey }
            let material = Array(body[o..<(o + n)])
            if usage == 0 {
                if o + n + 2 <= body.count {
                    let stored = UInt16(body[o + n]) << 8 | UInt16(body[o + n + 1])
                    guard checksum16(material) == stored else { throw Failure.unreadableKey }
                }
                return material
            }
            guard usage == 254 || usage == 255 else { throw Failure.unsupportedProtection }
            guard let passphrase, !passphrase.isEmpty else { throw PGPServiceError.passphraseRequired }
            return try openCFBProtected(parameters: parameters, ciphertext: material, usage: usage, passphrase: passphrase)
        }

        guard version == 4 else { throw Failure.unreadableKey }
        if usage == 0 {
            guard body.count >= o + 2 else { throw Failure.unreadableKey }
            let material = Array(body[o..<(body.count - 2)])
            let stored = UInt16(body[body.count - 2]) << 8 | UInt16(body[body.count - 1])
            guard checksum16(material) == stored else { throw Failure.unreadableKey }
            return material
        }
        guard usage == 254 || usage == 255 else { throw Failure.unsupportedProtection }
        guard let passphrase, !passphrase.isEmpty else { throw PGPServiceError.passphraseRequired }
        // v4: cipher | S2K specifier | IV, then the encrypted rest.
        guard let length = cfbParameterLength(body, from: o) else { throw Failure.unsupportedProtection }
        let parameters = Array(body[o..<(o + length)])
        return try openCFBProtected(parameters: parameters, ciphertext: Array(body[(o + length)...]),
                                    usage: usage, passphrase: passphrase)
    }

    /// Length of cipher | S2K specifier | IV starting at `start`, or nil for a
    /// form this file does not open (a GnuPG stub, a non-AES cipher).
    private static func cfbParameterLength(_ b: [UInt8], from start: Int) -> Int? {
        var o = start
        guard o + 3 <= b.count, [7, 8, 9].contains(b[o]) else { return nil }
        o += 1
        switch b[o] {
        case 0: o += 2
        case 1: o += 10
        case 3: o += 11
        default: return nil
        }
        o += 16
        return o <= b.count ? o - start : nil
    }

    /// CFB-protected material (S2K usage 254 or 255): `parameters` is
    /// cipher | S2K specifier | IV.
    private static func openCFBProtected(parameters p: [UInt8], ciphertext: [UInt8], usage: UInt8,
                                         passphrase: String) throws -> [UInt8] {
        guard let length = cfbParameterLength(p, from: 0), length == p.count else { throw Failure.unsupportedProtection }
        let cipher = p[0]
        let keySize = cipher == 7 ? 16 : (cipher == 8 ? 24 : 32)
        let s2kType = p[1]
        let hash = p[2]
        var salt: [UInt8] = []
        var coded: UInt8? = nil
        var o = 3
        if s2kType == 1 || s2kType == 3 { salt = Array(p[o..<(o + 8)]); o += 8 }
        if s2kType == 3 { coded = p[o]; o += 1 }
        let iv = Array(p[o..<(o + 16)])
        let key = try s2kKey(hash: hash, salt: salt, codedCount: coded, passphrase: passphrase, keySize: keySize)
        let plain = cfbDecrypt(ciphertext, key: key, iv: iv)
        if usage == 254 {
            guard plain.count > 20 else { throw PGPServiceError.invalidPassphrase }
            let material = Array(plain[0..<(plain.count - 20)])
            guard Array(Insecure.SHA1.hash(data: Data(material))) == Array(plain[(plain.count - 20)...]) else {
                throw PGPServiceError.invalidPassphrase
            }
            return material
        }
        guard plain.count > 2 else { throw PGPServiceError.invalidPassphrase }
        let material = Array(plain[0..<(plain.count - 2)])
        let stored = UInt16(plain[plain.count - 2]) << 8 | UInt16(plain[plain.count - 1])
        guard checksum16(material) == stored else { throw PGPServiceError.invalidPassphrase }
        return material
    }

    /// Simple (no salt), salted, or iterated and salted S2K with SHA-1,
    /// SHA-256 or SHA-512.
    static func s2kKey(hash: UInt8, salt: [UInt8], codedCount: UInt8?, passphrase: String, keySize: Int) throws -> [UInt8] {
        let unit = salt + Array(passphrase.utf8)
        var total = unit.count
        if let c = codedCount {
            total = max(Int((16 + (UInt32(c) & 15)) << ((UInt32(c) >> 4) + 6)), unit.count)
        }
        var out: [UInt8] = []
        var prefix = 0
        while out.count < keySize {
            let zeros = [UInt8](repeating: 0, count: prefix)
            switch hash {
            case 2:
                var ctx = CC_SHA1_CTX()
                _ = CC_SHA1_Init(&ctx)
                if prefix > 0 { _ = CC_SHA1_Update(&ctx, zeros, CC_LONG(prefix)) }
                S2KStream.feed(unit, count: total) { p, n in _ = CC_SHA1_Update(&ctx, p, CC_LONG(n)) }
                var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
                _ = CC_SHA1_Final(&digest, &ctx)
                out += digest
            case 8:
                var ctx = CC_SHA256_CTX()
                _ = CC_SHA256_Init(&ctx)
                if prefix > 0 { _ = CC_SHA256_Update(&ctx, zeros, CC_LONG(prefix)) }
                S2KStream.feed(unit, count: total) { p, n in _ = CC_SHA256_Update(&ctx, p, CC_LONG(n)) }
                var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
                _ = CC_SHA256_Final(&digest, &ctx)
                out += digest
            case 10:
                var ctx = CC_SHA512_CTX()
                _ = CC_SHA512_Init(&ctx)
                if prefix > 0 { _ = CC_SHA512_Update(&ctx, zeros, CC_LONG(prefix)) }
                S2KStream.feed(unit, count: total) { p, n in _ = CC_SHA512_Update(&ctx, p, CC_LONG(n)) }
                var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
                _ = CC_SHA512_Final(&digest, &ctx)
                out += digest
            default:
                throw Failure.unsupportedProtection
            }
            prefix += 1
        }
        return Array(out.prefix(keySize))
    }

    /// OpenPGP CFB without resynchronization, decrypt direction.
    static func cfbDecrypt(_ ciphertext: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8] {
        var plain = [UInt8](repeating: 0, count: ciphertext.count)
        var feedback = iv
        var offset = 0
        while offset < ciphertext.count {
            var stream = [UInt8](repeating: 0, count: 16)
            var moved = 0
            var cryptor: CCCryptorRef?
            CCCryptorCreate(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                            key, key.count, nil, &cryptor)
            if let cryptor {
                CCCryptorUpdate(cryptor, feedback, 16, &stream, 16, &moved)
                CCCryptorRelease(cryptor)
            }
            let end = min(offset + 16, ciphertext.count)
            for i in offset..<end { plain[i] = ciphertext[i] ^ stream[i - offset] }
            if end - offset == 16 { feedback = Array(ciphertext[offset..<end]) }
            offset += 16
        }
        return plain
    }

    private static func checksum16(_ bytes: [UInt8]) -> UInt16 {
        bytes.reduce(UInt16(0)) { $0 &+ UInt16($1) }
    }

    /// The 57-octet Ed448 seed from unlocked secret material, checked against
    /// the component's public key (GnuPG stores it in RFC 8032 order; the
    /// reversed order is tried too so no reading is guessed silently).
    static func ed448Seed(secretMaterial material: [UInt8], component c: Component) -> [UInt8]? {
        var candidates: [[UInt8]] = []
        if c.algorithm == 28 {
            guard material.count >= 57 else { return nil }
            candidates = [Array(material.prefix(57))]
        } else {
            var o = 0
            guard let value = readMPI(material, &o), let seed = normalized(value, length: 57) else { return nil }
            candidates = [seed, Array(seed.reversed())]
        }
        for seed in candidates {
            if let pub = try? Ed448.publicKey(seed: seed), pub == c.publicKey { return seed }
        }
        return nil
    }

    /// The 56-octet X448 scalar (RFC 7748 order) from unlocked secret material,
    /// chosen by matching the derived public value against the component's
    /// own: GnuPG's native order first, then the reversed one.
    static func x448Scalar(secretMaterial material: [UInt8], component c: Component) -> [UInt8]? {
        var candidates: [[UInt8]] = []
        if c.algorithm == 26 {
            guard material.count >= 56 else { return nil }
            candidates = [Array(material.prefix(56))]
        } else {
            var o = 0
            guard let value = readMPI(material, &o), let scalar = normalized(value, length: 56) else { return nil }
            candidates = [scalar, Array(scalar.reversed())]
        }
        for scalar in candidates {
            if let pub = try? X448.publicKey(for: Data(scalar)), Array(pub) == c.publicKey { return scalar }
        }
        return nil
    }

    // MARK: - Decryption keys

    /// The X448 decryption key of one secret subkey packet (tag 7), or nil
    /// when the packet is not an X448 key. The v5 form keeps the ECDH
    /// convention: the KDF takes the leftmost 20 octets of the fingerprint.
    static func decryptionKey(secretBody body: [UInt8], passphrase: String?, packetTag: UInt8 = 7) throws -> Cv25519DecryptionKey? {
        guard let c = component(keyBody: body), c.curve == .x448 else { return nil }
        let material = try secretMaterial(secretBody: body, passphrase: passphrase, packetTag: packetTag)
        guard let scalar = x448Scalar(secretMaterial: material, component: c) else {
            // Both readings fail the public-value check: a wrong passphrase
            // under usage 255 can get this far, anything else is damage.
            throw PGPServiceError.invalidPassphrase
        }
        if c.algorithm == 26 {
            return Cv25519DecryptionKey(subkeyID: c.keyID, subkeyFingerprint: c.fingerprint, privateKey: scalar,
                                        kdfHashID: 10, kdfCipherID: 9, curve: .x448)
        }
        return Cv25519DecryptionKey(subkeyID: c.keyID, subkeyFingerprint: kdfFingerprint(c),
                                    privateKey: scalar, kdfHashID: c.kdfHash, kdfCipherID: c.kdfCipher,
                                    curve: .x448)
    }

    /// Every X448 decryption key in a secret ring. Locked keys throw
    /// passphraseRequired only when nothing else could be read.
    static func decryptionKeys(secretRing data: [UInt8], passphrase: String?) throws -> [Cv25519DecryptionKey] {
        let packets = try OpenPGPPacketParser.parsePackets(data: data)
        var found: [Cv25519DecryptionKey] = []
        var locked = false
        for packet in packets where packet.tag == 7 || packet.tag == 5 {
            do {
                if let key = try decryptionKey(secretBody: packet.body, passphrase: passphrase, packetTag: packet.tag) {
                    found.append(key)
                }
            } catch PGPServiceError.passphraseRequired {
                locked = true
            }
        }
        if found.isEmpty && locked { throw PGPServiceError.passphraseRequired }
        return found
    }

    /// The fingerprint an ECDH KDF binds: a v4 fingerprint whole, the
    /// leftmost 20 octets of a v5 one (GnuPG's convention).
    static func kdfFingerprint(_ c: Component) -> [UInt8] {
        c.keyVersion == 4 ? c.fingerprint : Array(c.fingerprint.prefix(20))
    }

    /// The encryption recipient for an X448 public subkey, or nil for any
    /// other packet. A v5 subkey is addressed like a v4 ECDH key (v3 PKESK by
    /// key ID, KDF over the leftmost 20 fingerprint octets); a v6 subkey is
    /// addressed natively (algorithm 26).
    static func recipient(subkeyBody body: [UInt8]) -> Cv25519Recipient? {
        guard let c = component(keyBody: body), c.curve == .x448 else { return nil }
        if c.algorithm == 26 {
            var r = Cv25519Recipient(subkeyPublicKey: c.publicKey, subkeyFingerprint: c.fingerprint,
                                     subkeyID: c.keyID, kdfHashID: 10, kdfCipherID: 9, curve: .x448)
            r.keyVersion = c.keyVersion
            return r
        }
        var r = Cv25519Recipient(subkeyPublicKey: c.publicKey, subkeyFingerprint: kdfFingerprint(c),
                                 subkeyID: c.keyID, kdfHashID: c.kdfHash, kdfCipherID: c.kdfCipher, curve: .x448)
        r.keyVersion = c.keyVersion
        if c.keyVersion == 5 { r.fullFingerprint = c.fingerprint }
        return r
    }

    // MARK: - RFC 9580 X448 session keys (5.1.7)

    /// HKDF-SHA512(ikm: ephemeral | recipient | shared, no salt, info
    /// "OpenPGP X448"), 32 octets: the AES-256 key-wrap key.
    static func nativeKEK(ephemeral: [UInt8], recipientPublic: [UInt8], shared: [UInt8]) -> [UInt8] {
        let ikm = SymmetricKey(data: Data(ephemeral + recipientPublic + shared))
        let key = HKDF<SHA512>.deriveKey(inputKeyMaterial: ikm, salt: Data(),
                                         info: Data("OpenPGP X448".utf8), outputByteCount: 32)
        return key.withUnsafeBytes { Array($0) }
    }

    /// Wrap a session key to a native X448 recipient: (56-octet ephemeral,
    /// AES-256 wrapped key).
    static func nativeWrap(sessionKey: [UInt8], recipientPublic: [UInt8]) throws -> (ephemeral: [UInt8], wrapped: [UInt8]) {
        guard recipientPublic.count == 56 else { throw Failure.unreadableKey }
        let secret = try X448.generatePrivateKey()
        let ephemeral = Array(try X448.publicKey(for: secret))
        let shared = Array(try X448.sharedSecret(privateKey: secret, publicKey: Data(recipientPublic)))
        let kek = nativeKEK(ephemeral: ephemeral, recipientPublic: recipientPublic, shared: shared)
        return (ephemeral, try AESKeyWrap.wrap(plaintext: sessionKey, kek: kek))
    }

    /// Unwrap a native X448 PKESK's session key. A key that does not open it
    /// fails the key-wrap integrity check, which the caller treats as "not
    /// this key", the same as every other recipient form.
    static func nativeUnwrap(ephemeral: [UInt8], wrapped: [UInt8], scalar: [UInt8]) throws -> [UInt8] {
        guard ephemeral.count == 56, scalar.count == 56 else { throw ECDHError.invalidEphemeralKey }
        let recipientPublic = Array(try X448.publicKey(for: Data(scalar)))
        let shared = Array(try X448.sharedSecret(privateKey: Data(scalar), publicKey: Data(ephemeral)))
        let kek = nativeKEK(ephemeral: ephemeral, recipientPublic: recipientPublic, shared: shared)
        do {
            return try AESKeyWrap.unwrap(ciphertext: wrapped, kek: kek)
        } catch {
            throw ECDHError.sessionKeyUnwrapFailed(error.localizedDescription)
        }
    }

    // MARK: - Signing keys

    /// The Ed448 component of a secret ring to sign documents with: a signing
    /// subkey whose newest binding grants signing (the newest one first),
    /// else the primary when its self-signature grants signing or carries no
    /// key flags. Nil when the ring has no Ed448 component at all, so the
    /// caller tries its other key types.
    static func signingKey(secretRing data: [UInt8], passphrase: String?) throws -> Ed448SigningKey? {
        let packets = try OpenPGPPacketParser.parsePackets(data: data)
        struct Candidate {
            let body: [UInt8]
            let tag: UInt8
            let component: Component
            var flags: UInt8?
            var flagsTime: Date = .distantPast
            var revoked = false
        }
        var candidates: [Candidate] = []
        var current: Int? = nil
        for packet in packets {
            switch packet.tag {
            case 5, 7:
                if let c = component(keyBody: packet.body), c.curve == .ed448 {
                    candidates.append(Candidate(body: packet.body, tag: packet.tag, component: c))
                    current = candidates.count - 1
                } else {
                    current = nil
                }
            case 2:
                guard let i = current, let sig = try? OpenPGPPacketParser.parseSignaturePacket(body: packet.body) else { continue }
                if sig.signatureType == 0x28, candidates[i].tag == 7 { candidates[i].revoked = true }
                let isSelf = candidates[i].tag == 5 ? (0x10...0x13).contains(sig.signatureType) || sig.signatureType == 0x1F
                                                    : sig.signatureType == 0x18
                guard isSelf, let flags = sig.hashedSubpackets.first(where: { $0.type == 27 })?.data.first else { continue }
                let t = sig.creationTime ?? .distantPast
                if candidates[i].flags == nil || t >= candidates[i].flagsTime {
                    candidates[i].flags = flags
                    candidates[i].flagsTime = t
                }
            default:
                break
            }
        }
        guard !candidates.isEmpty else { return nil }
        let subkeys = candidates.filter { $0.tag == 7 && !$0.revoked && ($0.flags ?? 0) & 0x02 != 0 }
            .sorted { creation($0.component.publicBody) > creation($1.component.publicBody) }
        let primary = candidates.first { $0.tag == 5 && ($0.flags.map { $0 & 0x02 != 0 } ?? true) }
        guard let chosen = subkeys.first ?? primary else { throw Failure.noSigningComponent }
        let material = try secretMaterial(secretBody: chosen.body, passphrase: passphrase, packetTag: chosen.tag)
        guard let seed = ed448Seed(secretMaterial: material, component: chosen.component) else {
            throw PGPServiceError.invalidPassphrase
        }
        return Ed448SigningKey(seed: seed, publicKey: chosen.component.publicKey,
                               keyVersion: chosen.component.keyVersion == 6 ? 6 : 5,
                               fingerprint: chosen.component.fingerprint)
    }

    /// 8.4.0 build 9 (plan 5l): the PRIMARY key of a secret ring, unlocked,
    /// when it is an Ed448 key in RFC 9580 v6 form (algorithm 28). What the
    /// key editing paths certify with (User IDs, subkey revocation,
    /// certifying other keys), all through the v6 builders. Nil for any other
    /// primary, including a LibrePGP v5 Ed448 one, which those paths do not
    /// sign for yet.
    static func v6PrimaryCertificationKey(secretRing data: [UInt8], passphrase: String?) throws -> Ed448SigningKey? {
        let packets = try OpenPGPPacketParser.parsePackets(data: data)
        guard let primary = packets.first(where: { $0.tag == 5 }),
              let c = component(keyBody: primary.body), c.curve == .ed448, c.keyVersion == 6, c.algorithm == 28 else {
            return nil
        }
        let material = try secretMaterial(secretBody: primary.body, passphrase: passphrase, packetTag: 5)
        guard let seed = ed448Seed(secretMaterial: material, component: c) else {
            throw PGPServiceError.invalidPassphrase
        }
        return Ed448SigningKey(seed: seed, publicKey: c.publicKey, keyVersion: 6, fingerprint: c.fingerprint)
    }

    private static func creation(_ body: [UInt8]) -> UInt32 {
        guard body.count >= 5 else { return 0 }
        return UInt32(body[1]) << 24 | UInt32(body[2]) << 16 | UInt32(body[3]) << 8 | UInt32(body[4])
    }

    /// The Ed448 public key of the component (primary or subkey) a signature
    /// names, from a stored public ring. The issuer fingerprint decides when
    /// present, else the issuer key ID.
    static func signerPublicKey(publicRing data: [UInt8], issuerFingerprint: [UInt8]?, issuerKeyID: [UInt8]) -> [UInt8]? {
        guard let packets = try? OpenPGPPacketParser.parsePackets(data: data) else { return nil }
        for packet in packets where packet.tag == 6 || packet.tag == 14 || packet.tag == 5 || packet.tag == 7 {
            guard let c = component(keyBody: packet.body), c.curve == .ed448 else { continue }
            if let fp = issuerFingerprint, !fp.isEmpty {
                if fp == c.fingerprint { return c.publicKey }
            } else if !issuerKeyID.isEmpty, issuerKeyID == c.keyID {
                return c.publicKey
            }
        }
        return nil
    }

    // MARK: - Signatures

    /// The Ed448 signature value (R | S, 114 octets) of a parsed signature:
    /// native for algorithm 28, two MPIs left-padded to 57 for algorithm 22.
    static func signatureValue(_ sig: OpenPGPPacketParser.ParsedSignature) -> [UInt8]? {
        if sig.publicKeyAlgorithm == 28 {
            return sig.signatureData.count == 114 ? sig.signatureData : nil
        }
        var o = 0
        guard let r = readMPI(sig.signatureData, &o), let s = readMPI(sig.signatureData, &o),
              r.count <= 57, s.count <= 57 else { return nil }
        return [UInt8](repeating: 0, count: 57 - r.count) + r + [UInt8](repeating: 0, count: 57 - s.count) + s
    }

    /// The v5 trailer after the hashed area: for a document signature the
    /// literal metadata (zeros when none is given), then 0x05 0xFF and the
    /// 8-octet length of the hashed area.
    static func v5Trailer(signatureType: UInt8, hashedPortionLength: Int, literalMetadata: [UInt8]?) -> [UInt8] {
        var out: [UInt8] = []
        if signatureType == 0x00 || signatureType == 0x01 {
            out += literalMetadata ?? detachedLiteralMetadata
        }
        let n = UInt64(hashedPortionLength)
        out += [5, 0xFF]
        for shift in stride(from: 56, through: 0, by: -8) { out.append(UInt8((n >> UInt64(shift)) & 0xFF)) }
        return out
    }

    /// The literal metadata a v5 data signature hashes: format, name length,
    /// name and date of a literal packet body. Nil when the body is too short.
    static func literalMetadata(ofLiteralBody body: [UInt8]) -> [UInt8]? {
        guard body.count >= 2 else { return nil }
        let end = 2 + Int(body[1]) + 4
        guard end <= body.count else { return nil }
        return Array(body[0..<end])
    }

    /// The metadata of the first literal packet among `packets`.
    static func literalMetadata(in packets: [ParsedPacket]) -> [UInt8]? {
        packets.first(where: { $0.tag == 11 }).flatMap { literalMetadata(ofLiteralBody: $0.body) }
    }

    /// Hash `input` with the named algorithm (SHA-256, 384, 512, SHA3-256, 512).
    static func hashDigest(_ input: Data, hashAlgorithm: UInt8) -> [UInt8]? {
        switch hashAlgorithm {
        case 8: return Array(SHA256.hash(data: input))
        case 9: return Array(SHA384.hash(data: input))
        case 10: return Array(SHA512.hash(data: input))
        case 12: return Keccak.sha3_256(Array(input))
        case 14: return Keccak.sha3_512(Array(input))
        default: return nil
        }
    }

    /// A document signature packet body by `key`: version 5 (algorithm 22,
    /// MPIs) or version 6 (algorithm 28, native), SHA-512.
    /// - Parameters:
    ///   - literalMetadata: v5 only. The literal packet's metadata for an
    ///     inline signature, `cleartextLiteralMetadata` for a cleartext one;
    ///     nil for a detached signature (zeros).
    ///   - salt: v6 only, the salt the matching one-pass packet carries; a
    ///     fresh one is drawn when nil.
    static func signatureBody(key: Ed448SigningKey, signatureType: UInt8, document: [UInt8],
                              literalMetadata: [UInt8]? = nil, salt: [UInt8]? = nil,
                              creationTime: Date = Date()) throws -> [UInt8] {
        let t = UInt32(creationTime.timeIntervalSince1970)
        let time: [UInt8] = [UInt8((t >> 24) & 0xFF), UInt8((t >> 16) & 0xFF), UInt8((t >> 8) & 0xFF), UInt8(t & 0xFF)]
        let h = signatureHashAlgorithm
        if key.keyVersion == 6 {
            let s = try salt ?? SecureRandom.bytes(v6SaltLength)
            let hashed = OpenPGPPacketBuilder.buildSignatureSubpacket(type: 2, data: time)
                + OpenPGPPacketBuilder.buildSignatureSubpacket(type: 33, data: [6] + key.fingerprint)
            let unhashed = OpenPGPPacketBuilder.buildSignatureSubpacket(type: 16, data: key.keyID)
            let hp: [UInt8] = [6, signatureType, 28, h] + be32(hashed.count) + hashed
            var input = Data(s)
            input.append(contentsOf: document)
            input.append(contentsOf: hp)
            input.append(contentsOf: [6, 0xFF] + be32(hp.count))
            guard let digest = hashDigest(input, hashAlgorithm: h) else { throw Failure.unreadableKey }
            let value = try Ed448.sign(message: digest, seed: key.seed)
            var out = hp
            out += be32(unhashed.count)
            out += unhashed
            out += [digest[0], digest[1], UInt8(s.count)]
            out += s
            out += value
            return out
        }
        let hashed = OpenPGPPacketBuilder.buildSignatureSubpacket(type: 33, data: [5] + key.fingerprint)
            + OpenPGPPacketBuilder.buildSignatureSubpacket(type: 2, data: time)
        let unhashed = OpenPGPPacketBuilder.buildSignatureSubpacket(type: 16, data: key.keyID)
        let hp: [UInt8] = [5, signatureType, 22, h] + be16(hashed.count) + hashed
        var input = Data(document)
        input.append(contentsOf: hp)
        input.append(contentsOf: v5Trailer(signatureType: signatureType, hashedPortionLength: hp.count,
                                           literalMetadata: literalMetadata))
        guard let digest = hashDigest(input, hashAlgorithm: h) else { throw Failure.unreadableKey }
        let value = try Ed448.sign(message: digest, seed: key.seed)
        var out = hp
        out += be16(unhashed.count)
        out += unhashed
        out += [digest[0], digest[1]]
        out += edValueMPI(Array(value[0..<57]))
        out += edValueMPI(Array(value[57..<114]))
        return out
    }

    /// One-pass signature packet (framed) for `key`: version 3 for a v5 key
    /// (what GnuPG writes), version 6 with the signature's salt for a v6 key.
    static func onePassPacket(key: Ed448SigningKey, signatureType: UInt8, salt: [UInt8]) -> [UInt8] {
        var body: [UInt8]
        if key.keyVersion == 6 {
            body = [6, signatureType, signatureHashAlgorithm, 28, UInt8(salt.count)] + salt + key.fingerprint + [1]
        } else {
            body = [3, signatureType, signatureHashAlgorithm, 22] + key.keyID + [1]
        }
        return OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 4, body: body)
    }

    /// One-pass signature | literal packet | signature, a binary inline
    /// signature over `data` (the literal packet's content). `literalPacket`
    /// is the framed literal packet the message carries; its metadata enters
    /// a v5 signature.
    static func inlineSigned(key: Ed448SigningKey, literalPacket: [UInt8], data: [UInt8]) throws -> [UInt8] {
        guard let literal = try OpenPGPPacketParser.parsePackets(data: literalPacket).first, literal.tag == 11,
              let meta = literalMetadata(ofLiteralBody: literal.body) else {
            throw Failure.unreadableKey
        }
        let salt: [UInt8] = try key.keyVersion == 6 ? SecureRandom.bytes(v6SaltLength) : []
        let signature = try signatureBody(key: key, signatureType: 0x00, document: data,
                                          literalMetadata: meta, salt: salt)
        var out = onePassPacket(key: key, signatureType: 0x00, salt: salt)
        out += literalPacket
        out += OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 2, body: signature)
        return out
    }

    /// Verify an Ed448 signature (v5 algorithm 22, v6 or v4 algorithm 28) over
    /// `document` with the 57-octet `publicKey`. `literalMetadata` is what a
    /// v5 document signature hashes (nil: zeros, a detached signature).
    static func verify(_ sig: OpenPGPPacketParser.ParsedSignature, document: [UInt8], publicKey: [UInt8],
                       literalMetadata: [UInt8]? = nil) -> Bool {
        guard publicKey.count == 57, let value = signatureValue(sig) else { return false }
        var input = Data(sig.salt)
        input.append(contentsOf: document)
        input.append(contentsOf: sig.rawHashedPortion)
        let n = sig.rawHashedPortion.count
        if sig.version == 5 {
            input.append(contentsOf: v5Trailer(signatureType: sig.signatureType, hashedPortionLength: n,
                                               literalMetadata: literalMetadata))
        } else {
            input.append(contentsOf: [sig.version, 0xFF] + be32(n))
        }
        guard let digest = hashDigest(input, hashAlgorithm: sig.hashAlgorithm),
              sig.hashPrefix.count == 2, digest[0] == sig.hashPrefix[0], digest[1] == sig.hashPrefix[1] else {
            return false
        }
        return Ed448.verify(signature: value, message: digest, publicKey: publicKey)
    }

    // MARK: - Encoding helpers

    static func readMPI(_ b: [UInt8], _ o: inout Int) -> [UInt8]? {
        guard o + 2 <= b.count else { return nil }
        let bits = Int(b[o]) << 8 | Int(b[o + 1])
        let n = (bits + 7) / 8
        guard o + 2 + n <= b.count else { return nil }
        defer { o += 2 + n }
        return Array(b[(o + 2)..<(o + 2 + n)])
    }

    /// A canonical MPI: leading zero octets dropped, the exact bit count.
    static func mpi(_ value: [UInt8]) -> [UInt8] {
        var v = value
        while let first = v.first, first == 0 { v.removeFirst() }
        guard let first = v.first else { return [0, 0] }
        let bits = (v.count - 1) * 8 + (8 - first.leadingZeroBitCount)
        return [UInt8((bits >> 8) & 0xFF), UInt8(bits & 0xFF)] + v
    }

    /// R or S of an Ed448 signature as GnuPG writes it: all 57 octets, the
    /// bit count read off the first octet, or the full 456 bits when that
    /// octet is zero. libgcrypt refuses a shorter value ("Invalid length"),
    /// so the minimal MPI form must not be used here (checked with gpg 2.4.4).
    static func edValueMPI(_ value: [UInt8]) -> [UInt8] {
        guard let first = value.first else { return [0, 0] }
        let bits = first == 0 ? value.count * 8 : (value.count - 1) * 8 + (8 - first.leadingZeroBitCount)
        return [UInt8((bits >> 8) & 0xFF), UInt8(bits & 0xFF)] + value
    }

    private static func be16(_ n: Int) -> [UInt8] { [UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)] }
    private static func be32(_ n: Int) -> [UInt8] {
        [UInt8((n >> 24) & 0xFF), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)]
    }
}

// MARK: - Streaming signer

/// 8.4.0 build 9 (plan 5l): an Ed448 document signature over data that
/// arrives in pieces (a large file's detached signature). Ed448 signs the
/// SHA-512 digest, so the data streams through the hash and only the digest
/// is signed at the end, exactly as `OpenPGP448.signatureBody` does in one go.
final class StreamingEd448Signer: StreamingMessageSigner {
    private let key: Ed448SigningKey
    private let signatureType: UInt8
    private let literalMetadata: [UInt8]?
    private let salt: [UInt8]
    private let hashed: [UInt8]
    private let unhashed: [UInt8]
    private let hashedPortion: [UInt8]
    private var hasher = SHA512()

    init(key: Ed448SigningKey, signatureType: UInt8 = 0x00, literalMetadata: [UInt8]? = nil,
         creationTime: Date? = nil) throws {
        self.key = key
        self.signatureType = signatureType
        self.literalMetadata = literalMetadata
        let t = UInt32((creationTime ?? Date()).timeIntervalSince1970)
        let time: [UInt8] = [UInt8((t >> 24) & 0xFF), UInt8((t >> 16) & 0xFF), UInt8((t >> 8) & 0xFF), UInt8(t & 0xFF)]
        let h = OpenPGP448.signatureHashAlgorithm
        unhashed = OpenPGPPacketBuilder.buildSignatureSubpacket(type: 16, data: key.keyID)
        if key.keyVersion == 6 {
            salt = try SecureRandom.bytes(OpenPGP448.v6SaltLength)
            hashed = OpenPGPPacketBuilder.buildSignatureSubpacket(type: 2, data: time)
                + OpenPGPPacketBuilder.buildSignatureSubpacket(type: 33, data: [6] + key.fingerprint)
            let n = hashed.count
            hashedPortion = [6, signatureType, 28, h, UInt8((n >> 24) & 0xFF), UInt8((n >> 16) & 0xFF),
                             UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)] + hashed
            hasher.update(data: Data(salt))
        } else {
            salt = []
            hashed = OpenPGPPacketBuilder.buildSignatureSubpacket(type: 33, data: [5] + key.fingerprint)
                + OpenPGPPacketBuilder.buildSignatureSubpacket(type: 2, data: time)
            let n = hashed.count
            hashedPortion = [5, signatureType, 22, h, UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)] + hashed
        }
    }

    var onePassPacket: [UInt8] {
        OpenPGP448.onePassPacket(key: key, signatureType: signatureType, salt: salt)
    }

    func update(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        hasher.update(data: bytes)
    }

    func finish() throws -> [UInt8] {
        hasher.update(data: Data(hashedPortion))
        let n = hashedPortion.count
        if key.keyVersion == 6 {
            hasher.update(data: Data([6, 0xFF, UInt8((n >> 24) & 0xFF), UInt8((n >> 16) & 0xFF),
                                      UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)]))
        } else {
            hasher.update(data: Data(OpenPGP448.v5Trailer(signatureType: signatureType, hashedPortionLength: n,
                                                          literalMetadata: literalMetadata)))
        }
        let digest = Array(hasher.finalize())
        let value = try Ed448.sign(message: digest, seed: key.seed)
        var body = hashedPortion
        if key.keyVersion == 6 {
            let u = unhashed.count
            body += [UInt8((u >> 24) & 0xFF), UInt8((u >> 16) & 0xFF), UInt8((u >> 8) & 0xFF), UInt8(u & 0xFF)]
            body += unhashed
            body += [digest[0], digest[1], UInt8(salt.count)]
            body += salt
            body += value
        } else {
            body += [UInt8((unhashed.count >> 8) & 0xFF), UInt8(unhashed.count & 0xFF)]
            body += unhashed
            body += [digest[0], digest[1]]
            body += OpenPGP448.edValueMPI(Array(value[0..<57]))
            body += OpenPGP448.edValueMPI(Array(value[57..<114]))
        }
        return OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 2, body: body)
    }
}

// MARK: - Native key summary (import previews)

/// 8.4.0 build 9 (plan 5l): what an import preview needs from a key block the
/// native parser reads (v4, LibrePGP v5 or RFC 9580 v6), without
/// ObjectivePGP: the primary fingerprint, the first User ID, whether secret
/// packets are present, the creation time and the model algorithm when the
/// key is one this file names (Ed448 / X448).
struct NativeKeySummary {
    let fingerprintHex: String
    let userID: String
    let hasSecret: Bool
    let createdAt: Date
    let keyVersion: UInt8
    let algorithm: KeyAlgorithm?

    init?(keyData: [UInt8]) {
        guard let packets = try? OpenPGPPacketParser.parsePackets(data: keyData),
              let primary = packets.first(where: { $0.tag == 6 || $0.tag == 5 }),
              let pub = OpenPGP448.publicBody(ofKeyBody: primary.body),
              let version = pub.first, [4, 5, 6].contains(version) else { return nil }
        fingerprintHex = CertificateValidator.fingerprint(ofKeyBody: pub).map { String(format: "%02x", $0) }.joined()
        userID = packets.first(where: { $0.tag == 13 }).flatMap { String(data: Data($0.body), encoding: .utf8) } ?? "Unknown"
        hasSecret = packets.contains { $0.tag == 5 || $0.tag == 7 }
        let t = UInt32(pub[1]) << 24 | UInt32(pub[2]) << 16 | UInt32(pub[3]) << 8 | UInt32(pub[4])
        createdAt = Date(timeIntervalSince1970: TimeInterval(t))
        keyVersion = version
        algorithm = OpenPGP448.keyAlgorithm(packets: packets)
    }

    init?(armored: String) {
        guard let data = try? OpenPGPPacketParser.dearmor(armored) else { return nil }
        self.init(keyData: Array(data))
    }
}

// MARK: - Key signatures (8.4.0 build 10, plan 5m)

// 8.4.0 build 10 (plan 5m): key editing for Ed448 primaries. A LibrePGP v5
// key signs its certifications, bindings and revocations as version 5
// signatures (what GnuPG 2.4.4 writes, checked against it):
//   - the hashed area keeps v4's 2-octet length; the trailer is 0x05 0xFF
//     and an 8-octet length (no literal fields: those are for 0x00 and 0x01);
//   - SHA-512, the issuer fingerprint subpacket 33 with version 5 and the
//     32-octet fingerprint, no issuer key ID (GnuPG writes none);
//   - R and S as full 57-octet MPIs (`edValueMPI`);
//   - every key in the hashed document is framed by its own version: a v5
//     key as 0x9A and a 4-octet length, a v4 subkey or a v4 target key as
//     0x99 and a 2-octet length, also inside a v5 signature.
// An RFC 9580 v6 key signs as version 6 (salted, 0x9B framing for every key).
// PGPService.extractPrimaryCertificationKey still refuses a v5 primary, so the
// v4 builders can never sign one as if it were a v4 or Ed25519 key.

extension OpenPGP448 {

    /// 8.4.0 build 10 (plan 5m): the PRIMARY of a secret ring, unlocked, when
    /// it is a LibrePGP v5 Ed448 key (algorithm 22 with the Ed448 OID). Nil
    /// for any other primary.
    static func v5PrimaryCertificationKey(secretRing data: [UInt8], passphrase: String?) throws -> Ed448SigningKey? {
        let packets = try OpenPGPPacketParser.parsePackets(data: data)
        guard let primary = packets.first(where: { $0.tag == 5 }),
              let c = component(keyBody: primary.body), c.curve == .ed448, c.keyVersion == 5, c.algorithm == 22 else {
            return nil
        }
        return try unlockedEd448(secretBody: primary.body, component: c, passphrase: passphrase, packetTag: 5)
    }

    /// 8.4.0 build 10 (plan 5m): the Ed448 primary of a secret ring, v5 or
    /// v6, unlocked. Nil for any other primary.
    static func primaryCertificationKey(secretRing data: [UInt8], passphrase: String?) throws -> Ed448SigningKey? {
        if let v5 = try v5PrimaryCertificationKey(secretRing: data, passphrase: passphrase) { return v5 }
        return try v6PrimaryCertificationKey(secretRing: data, passphrase: passphrase)
    }

    /// 8.4.0 build 10 (plan 5m): one secret key packet body (a primary or a
    /// subkey) as an unlocked Ed448 key, v5 or v6. Nil when it is not one.
    static func ed448SigningKey(secretBody body: [UInt8], passphrase: String?, packetTag: UInt8) throws -> Ed448SigningKey? {
        guard let c = component(keyBody: body), c.curve == .ed448,
              (c.keyVersion == 5 && c.algorithm == 22) || (c.keyVersion == 6 && c.algorithm == 28) else { return nil }
        return try unlockedEd448(secretBody: body, component: c, passphrase: passphrase, packetTag: packetTag)
    }

    private static func unlockedEd448(secretBody body: [UInt8], component c: Component, passphrase: String?,
                                      packetTag: UInt8) throws -> Ed448SigningKey {
        let material = try secretMaterial(secretBody: body, passphrase: passphrase, packetTag: packetTag)
        guard let seed = ed448Seed(secretMaterial: material, component: c) else {
            throw PGPServiceError.invalidPassphrase
        }
        return Ed448SigningKey(seed: seed, publicKey: c.publicKey, keyVersion: c.keyVersion == 6 ? 6 : 5,
                               fingerprint: c.fingerprint)
    }

    /// True when a secret key packet body holds no secret (a GnuPG stub, the
    /// primary of an offline key), v4 or v5 form.
    static func isSecretStub(secretBody body: [UInt8]) -> Bool {
        if body.first == 4 { return OpenPGPPacketParser.gnuStub(secretBody: body) != nil }
        guard body.first == 5, let pub = publicBody(ofKeyBody: body), body.count > pub.count + 3 else { return false }
        let o = pub.count
        // usage | parameter count | cipher | S2K type (101: GnuPG extension)
        return (body[o] == 254 || body[o] == 255) && body[o + 3] == 101
    }

    /// How a key enters the hash of a key signature of `signatureVersion`:
    /// 0x9B framing for a v6 signature, else by the key's own version (0x99
    /// for v4, 0x9A for v5), which is what GnuPG hashes.
    static func frameForKeySignature(_ body: [UInt8], signatureVersion: UInt8) -> [UInt8] {
        CertificateValidator.frameKey(body, signatureVersion: signatureVersion == 6 ? 6 : (body.first ?? 4))
    }

    /// A key signature body (certification, binding, back-signature,
    /// revocation, direct key) by an Ed448 key over `document` (the framed
    /// keys and identity), SHA-512: version 5 (algorithm 22, 2-octet areas,
    /// the v5 trailer, R and S as 57-octet MPIs) for a v5 key, version 6
    /// (algorithm 28, salted, 4-octet areas) for a v6 one. `salt` (v6 only)
    /// is drawn fresh when nil.
    static func keySignatureBody(key: Ed448SigningKey, signatureType: UInt8, document: [UInt8],
                                 hashedSubpackets hashed: [UInt8], unhashedSubpackets unhashed: [UInt8] = [],
                                 salt: [UInt8]? = nil) throws -> [UInt8] {
        let h = signatureHashAlgorithm
        if key.keyVersion == 6 {
            let s = try salt ?? SecureRandom.bytes(v6SaltLength)
            var hp: [UInt8] = [6, signatureType, 28, h]
            hp += be32(hashed.count)
            hp += hashed
            var input = Data(s)
            input.append(contentsOf: document)
            input.append(contentsOf: hp)
            input.append(contentsOf: [6, 0xFF] + be32(hp.count))
            guard let digest = hashDigest(input, hashAlgorithm: h) else { throw Failure.unreadableKey }
            let value = try Ed448.sign(message: digest, seed: key.seed)
            var out = hp
            out += be32(unhashed.count)
            out += unhashed
            out += [digest[0], digest[1], UInt8(s.count)]
            out += s
            out += value
            return out
        }
        var hp: [UInt8] = [5, signatureType, 22, h]
        hp += be16(hashed.count)
        hp += hashed
        var input = Data(document)
        input.append(contentsOf: hp)
        input.append(contentsOf: v5Trailer(signatureType: signatureType, hashedPortionLength: hp.count,
                                           literalMetadata: nil))
        guard let digest = hashDigest(input, hashAlgorithm: h) else { throw Failure.unreadableKey }
        let value = try Ed448.sign(message: digest, seed: key.seed)
        var out = hp
        out += be16(unhashed.count)
        out += unhashed
        out += [digest[0], digest[1]]
        out += edValueMPI(Array(value[0..<57]))
        out += edValueMPI(Array(value[57..<114]))
        return out
    }
}

// MARK: - Self-signatures of Ed448 primaries (8.4.0 build 10, plan 5m)

/// 8.4.0 build 10 (plan 5m): Change Expiration and Refresh Self-Signatures
/// for a key pair whose primary is Ed448, LibrePGP v5 (GnuPG 2.4) or RFC 9580
/// v6. Signs again, with the primary and a fresh creation time newer than
/// every self-signature already there:
///   - the newest direct key signature (0x1F) that verifies, when there is one;
///   - the newest self-certification of every User ID that is not revoked;
///   - the newest binding of every subkey that is not revoked. A signing
///     subkey also gets a fresh back-signature (0x19) made by the subkey
///     itself (Ed448 v5 or v6, a v4 Ed25519 subkey as GnuPG adds under a v5
///     primary, or a v6 Ed25519 one); a signing subkey whose secret is not
///     here keeps its old binding and is reported as passed over.
/// Every hashed subpacket is carried over except the creation time, the
/// issuer and the embedded back-signature, which are made again, and the key
/// expiration time when `expiry` sets a new one. A signature that does not
/// verify is never signed again.
///
/// Where a new expiration goes: a v5 key keeps it on its User ID
/// certifications (GnuPG's place) and on a direct key signature if it has
/// one; a v6 key keeps it on its direct key signature, and on a User ID
/// certification only when that certification already carried one (or the
/// key has no direct key signature). Subkeys get it when the caller asks
/// (`includeCurrentSubkeys`) and only while they are still valid: an expired
/// subkey keeps its old binding, as KeyExpirationEditor does for v4.
enum Ed448KeyEditor {

    enum Expiry: Equatable {
        /// Refresh Self-Signatures: every expiry stays as it is.
        case keep
        /// Change Expiration: the new absolute date, nil for never.
        case set(Date?)
    }

    struct Result {
        let publicKeyData: Data
        let secretKeyData: Data
        let directKeyResigned: Bool
        let userIDsResigned: Int
        let subkeysResigned: Int
        /// Lowercase hex fingerprints of signing subkeys that kept their old
        /// binding because no back-signature could be made here.
        let passedOver: [String]
    }

    enum EditError: LocalizedError, Equatable {
        case unsupportedKey
        case noPrimaryKeyPacket
        case primaryNotOnDevice
        case expiryBeforeCreation
        case noLiveUserID
        case nothingToSign

        var errorDescription: String? {
            switch self {
            case .unsupportedKey:
                return String(localized: "This key uses a format PGPony can't read yet.")
            case .noPrimaryKeyPacket:
                return String(localized: "Could not locate the primary key packet in this key.")
            case .primaryNotOnDevice:
                return String(localized: "The primary key's secret is not on this device, so its self-signatures can't be signed again.")
            case .expiryBeforeCreation:
                return String(localized: "The chosen expiration date is before the key was created.")
            case .noLiveUserID:
                return String(localized: "Every User ID on this key is revoked, so there is no identity to carry a new expiration date.")
            case .nothingToSign:
                return String(localized: "No User ID or subkey on this key has a self-signature that could be checked, so nothing was signed again.")
            }
        }
    }

    /// True for an Ed448 primary this editor signs with: LibrePGP v5
    /// (algorithm 22) or RFC 9580 v6 (algorithm 28).
    static func supports(primaryBody body: [UInt8]) -> Bool {
        guard let c = OpenPGP448.component(keyBody: body), c.curve == .ed448 else { return false }
        return (c.keyVersion == 5 && c.algorithm == 22) || (c.keyVersion == 6 && c.algorithm == 28)
    }

    /// Same, from a public ring (binary).
    static func supports(publicKeyData: Data) -> Bool {
        guard let packets = try? OpenPGPPacketParser.parsePackets(data: Array(publicKeyData)),
              let primary = packets.first(where: { $0.tag == 6 }) else { return false }
        return supports(primaryBody: primary.body)
    }

    // MARK: Entry point

    /// Sign the self-signatures of the key pair in (`publicKeyData`,
    /// `secretKeyData`), both binary, again. Passphrase errors of
    /// PGPService surface unchanged. Synchronous, for runOffMainThread.
    static func resign(
        publicKeyData: Data,
        secretKeyData: Data,
        passphrase: String?,
        expiry: Expiry,
        includeCurrentSubkeys: Bool = true,
        now: Date = Date()
    ) throws -> Result {
        let pubPackets = try OpenPGPPacketParser.parsePackets(data: Array(publicKeyData))
        let secPackets = try OpenPGPPacketParser.parsePackets(data: Array(secretKeyData))
        guard let primaryBody = pubPackets.first(where: { $0.tag == 6 })?.body,
              let primarySecret = secPackets.first(where: { $0.tag == 5 }) else {
            throw EditError.noPrimaryKeyPacket
        }
        guard supports(primaryBody: primaryBody), let pc = OpenPGP448.component(keyBody: primaryBody) else {
            throw EditError.unsupportedKey
        }
        if OpenPGP448.isSecretStub(secretBody: primarySecret.body) { throw EditError.primaryNotOnDevice }
        guard let key = try OpenPGP448.primaryCertificationKey(secretRing: Array(secretKeyData), passphrase: passphrase),
              key.fingerprint == pc.fingerprint else {
            throw EditError.unsupportedKey
        }
        let version = pc.keyVersion
        let primaryFrame = OpenPGP448.frameForKeySignature(primaryBody, signatureVersion: version)

        var newest: UInt32 = 0
        for packet in pubPackets where packet.tag == 2 {
            guard let sig = try? OpenPGPPacketParser.parseSignaturePacket(body: packet.body),
                  CertificateValidator.issuedBy(primaryBody: primaryBody, sig) else { continue }
            newest = max(newest, seconds(sig.creationTime))
        }
        let sigTime = max(UInt32(now.timeIntervalSince1970), newest &+ 1)

        func hashedArea(_ base: OpenPGPPacketParser.ParsedSignature, creation: UInt32, setExpiry: Bool,
                        embedded: [UInt8]?) throws -> [UInt8] {
            var out = subpacket(2, u32be(sigTime), critical: version == 6)
            for sp in base.hashedSubpackets where !regenerated.contains(sp.type) {
                out += subpacket(sp.type, sp.data, critical: sp.isCritical)
            }
            if setExpiry, case .set(let date) = expiry {
                if let date {
                    let t = date.timeIntervalSince1970
                    guard t > Double(creation), t < Double(UInt32.max) else { throw EditError.expiryBeforeCreation }
                    out += subpacket(9, u32be(UInt32(t) - creation), critical: version == 6)
                }
            } else if let old = base.hashedSubpackets.first(where: { $0.type == 9 }) {
                out += subpacket(9, old.data, critical: old.isCritical)
            }
            if let embedded, version == 6 { out += subpacket(32, embedded, critical: true) }
            out += subpacket(33, [version] + pc.fingerprint)
            return out
        }
        func sign(_ type: UInt8, _ document: [UInt8], _ hashed: [UInt8], _ unhashed: [UInt8]) throws -> [UInt8] {
            let body = try OpenPGP448.keySignatureBody(key: key, signatureType: type, document: document,
                                                       hashedSubpackets: hashed, unhashedSubpackets: unhashed)
            return OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 2, body: body)
        }
        func newestVerifying(_ sigs: [OpenPGPPacketParser.ParsedSignature], documents: [[UInt8]]) -> OpenPGPPacketParser.ParsedSignature? {
            sigs.sorted { seconds($0.creationTime) > seconds($1.creationTime) }.first { sig in
                documents.contains { CertificateValidator.verify(sig, signerBody: primaryBody, document: $0) == .valid }
            }
        }

        let pubBlocks = blocks(pubPackets)
        let secBlocks = blocks(secPackets)
        let primaryCreation = creation(primaryBody)

        // 1. The direct key signature.
        var newDirect: [UInt8]? = nil
        if let primaryBlock = pubBlocks.first(where: { $0.key.tag == 6 }) {
            let directs = selfSignatures(primaryBlock, primaryBody: primaryBody).filter { $0.signatureType == 0x1F }
            if let base = newestVerifying(directs, documents: [primaryFrame]) {
                newDirect = try sign(0x1F, primaryFrame,
                                     try hashedArea(base, creation: primaryCreation, setExpiry: true, embedded: nil), [])
            }
        }

        // 2. User IDs.
        var newCerts: [[UInt8]: [UInt8]] = [:]
        var liveUserIDs = 0
        for block in pubBlocks where block.key.tag == 13 {
            let sigs = selfSignatures(block, primaryBody: primaryBody)
            let certs = sigs.filter { (0x10...0x13).contains($0.signatureType) }
            let latestCert = certs.map { seconds($0.creationTime) }.max()
            let latestRevocation = sigs.filter { $0.signatureType == 0x30 }.map { seconds($0.creationTime) }.max()
            if let latestRevocation, latestRevocation >= (latestCert ?? 0) { continue }
            let document = primaryFrame + CertificateValidator.frameIdentity(0xB4, block.key.body)
            guard let base = newestVerifying(certs, documents: [document]) else { continue }
            liveUserIDs += 1
            let carriesExpiry = version == 5 || newDirect == nil
                || base.hashedSubpackets.contains { $0.type == 9 }
            newCerts[block.key.body] = try sign(base.signatureType, document,
                                                try hashedArea(base, creation: primaryCreation, setExpiry: carriesExpiry, embedded: nil), [])
        }
        if case .set = expiry, newDirect == nil, liveUserIDs == 0 { throw EditError.noLiveUserID }

        // 3. Subkey bindings.
        var newBindings: [String: [UInt8]] = [:]
        var passedOver: [String] = []
        for block in pubBlocks where block.key.tag == 14 {
            let subBody = block.key.body
            let fp = hex(CertificateValidator.fingerprint(ofKeyBody: subBody))
            let sigs = selfSignatures(block, primaryBody: primaryBody)
            if sigs.contains(where: { $0.signatureType == 0x28 }) { continue }
            let document = primaryFrame + OpenPGP448.frameForKeySignature(subBody, signatureVersion: version)
            let bindings = sigs.filter { $0.signatureType == 0x18 }
            var documents = [document]
            for d in CertificateValidator.bindingDocuments(primaryBody: primaryBody, subkeyBody: subBody,
                                                           signatureVersion: version) where !documents.contains(d) {
                documents.append(d)
            }
            guard let base = newestVerifying(bindings, documents: documents) else { continue }
            let subCreation = creation(subBody)
            if case .set = expiry {
                guard includeCurrentSubkeys else { continue }
                if let d = base.hashedSubpackets.first(where: { $0.type == 9 })?.data, d.count == 4 {
                    let s = UInt32(d[0]) << 24 | UInt32(d[1]) << 16 | UInt32(d[2]) << 8 | UInt32(d[3])
                    if s > 0, Date(timeIntervalSince1970: TimeInterval(subCreation) + TimeInterval(s)) <= now { continue }
                }
            }
            let flags = base.hashedSubpackets.first(where: { $0.type == 27 })?.data.first ?? 0
            var embedded: [UInt8]? = nil
            if flags & 0x02 != 0 {
                guard let back = backSignature(subkeyBody: subBody, secretPackets: secPackets, secretRing: secretKeyData,
                                               document: document, passphrase: passphrase, sigTime: sigTime) else {
                    passedOver.append(fp)
                    continue
                }
                embedded = back
            }
            let hashed = try hashedArea(base, creation: subCreation, setExpiry: true, embedded: embedded)
            // A v5 binding carries the back-signature in its unhashed area, as GnuPG writes it.
            let unhashed: [UInt8] = (version == 5 && embedded != nil) ? subpacket(32, embedded ?? [], critical: false) : []
            newBindings[fp] = try sign(0x18, document, hashed, unhashed)
        }

        guard newDirect != nil || !newCerts.isEmpty || !newBindings.isEmpty else { throw EditError.nothingToSign }

        let newPublic = splice(pubBlocks, primaryBody: primaryBody, newDirect: newDirect,
                               newCerts: newCerts, newBindings: newBindings)
        let newSecret = splice(secBlocks, primaryBody: primaryBody, newDirect: newDirect,
                               newCerts: newCerts, newBindings: newBindings)
        return Result(publicKeyData: Data(newPublic), secretKeyData: Data(newSecret),
                      directKeyResigned: newDirect != nil, userIDsResigned: newCerts.count,
                      subkeysResigned: newBindings.count, passedOver: passedOver)
    }

    // MARK: Back-signatures

    /// A signing subkey's fresh 0x19, made by the subkey over `document`, or
    /// nil when its secret is not here or does not unlock. It must verify
    /// against the subkey's public part, which proves the secret is this
    /// subkey's.
    private static func backSignature(subkeyBody: [UInt8], secretPackets: [ParsedPacket], secretRing: Data,
                                      document: [UInt8], passphrase: String?, sigTime: UInt32) -> [UInt8]? {
        guard subkeyBody.count > 5,
              let secret = secretPackets.first(where: { $0.tag == 7 && OpenPGP448.publicBody(ofKeyBody: $0.body) == subkeyBody })?.body,
              !OpenPGP448.isSecretStub(secretBody: secret) else { return nil }
        let subFP = CertificateValidator.fingerprint(ofKeyBody: subkeyBody)
        var body: [UInt8]? = nil
        if OpenPGP448.isEd448(keyBody: subkeyBody) {
            guard let ed = try? OpenPGP448.ed448SigningKey(secretBody: secret, passphrase: passphrase, packetTag: 7) else { return nil }
            let hashed = subpacket(2, u32be(sigTime), critical: ed.keyVersion == 6)
                + subpacket(33, [ed.keyVersion] + ed.fingerprint)
            body = try? OpenPGP448.keySignatureBody(key: ed, signatureType: 0x19, document: document, hashedSubpackets: hashed)
        } else if subkeyBody[0] == 4, subkeyBody[5] == 22,
                  let sk = v4Ed25519Key(secretBody: secret, publicBody: subkeyBody, passphrase: passphrase) {
            let hashed = subpacket(2, u32be(sigTime)) + subpacket(33, [4] + subFP)
            body = try? v4EdDSASignatureBody(key: sk, signatureType: 0x19, document: document, hashed: hashed,
                                             unhashed: subpacket(16, Array(subFP.suffix(8))))
        } else if subkeyBody[0] == 6, subkeyBody[5] == 27,
                  let info = try? PGPService.shared.extractEd25519SigningKey(
                    fromSecretKeyData: secretRing, passphrase: passphrase, preferSigningSubkey: true),
                  Array(info.fingerprint.suffix(32)) == subFP {
            let hashed = subpacket(2, u32be(sigTime), critical: true) + subpacket(33, [6] + subFP)
            body = try? V6KeyGenerator.assembleV6Signature(signer: .ed25519(info.privateKey), sigType: 0x19,
                                                           documentHashChunks: document, hashedSubpackets: hashed,
                                                           unhashedSubpackets: [])
        }
        guard let body, let parsed = try? OpenPGPPacketParser.parseSignaturePacket(body: body),
              CertificateValidator.verify(parsed, signerBody: subkeyBody, document: document) == .valid else { return nil }
        return body
    }

    /// The Ed25519 secret of a v4 EdDSA (legacy OID) subkey packet, checked
    /// against its public point.
    private static func v4Ed25519Key(secretBody: [UInt8], publicBody: [UInt8], passphrase: String?) -> Curve25519.Signing.PrivateKey? {
        guard let material = try? OpenPGP448.secretMaterial(secretBody: secretBody, passphrase: passphrase, packetTag: 7) else {
            return nil
        }
        var o = 0
        guard let value = OpenPGP448.readMPI(material, &o), value.count <= 32,
              let key = try? Curve25519.Signing.PrivateKey(
                rawRepresentation: Data([UInt8](repeating: 0, count: 32 - value.count) + value)),
              publicBody.count > 33, Array(publicBody.suffix(32)) == Array(key.publicKey.rawRepresentation) else {
            return nil
        }
        return key
    }

    /// A v4 EdDSA (algorithm 22) signature body over `document`, SHA-256, the
    /// shape PGPony's other v4 back-signatures have.
    static func v4EdDSASignatureBody(key: Curve25519.Signing.PrivateKey, signatureType: UInt8, document: [UInt8],
                                     hashed: [UInt8], unhashed: [UInt8]) throws -> [UInt8] {
        var hp: [UInt8] = [4, signatureType, 22, 8]
        hp += u16be(hashed.count)
        hp += hashed
        var input = Data(document)
        input.append(contentsOf: hp)
        input.append(contentsOf: [4, 0xFF] + u32be(UInt32(hp.count)))
        let digest = Array(SHA256.hash(data: input))
        let value = Array(try key.signature(for: Data(digest)))
        guard value.count == 64 else { throw EditError.unsupportedKey }
        var out = hp
        out += u16be(unhashed.count)
        out += unhashed
        out += [digest[0], digest[1]]
        out += OpenPGP448.mpi(Array(value[0..<32]))
        out += OpenPGP448.mpi(Array(value[32..<64]))
        return out
    }

    // MARK: Ring blocks

    /// A key or User ID packet and the packets that follow it up to the next.
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

    /// Re-emit `blocks` with the primary's direct key signatures, each User
    /// ID's self-certifications and each subkey's bindings replaced by the
    /// new one, in the place of the first one. Everything else passes through.
    private static func splice(_ blocks: [Block], primaryBody: [UInt8], newDirect: [UInt8]?,
                               newCerts: [[UInt8]: [UInt8]], newBindings: [String: [UInt8]]) -> [UInt8] {
        var out: [UInt8] = []
        for block in blocks {
            out += OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: block.key.tag, body: block.key.body)
            var replacement: [UInt8]? = nil
            var replacedTypes: Set<UInt8> = []
            switch block.key.tag {
            case 5, 6:
                if let newDirect { replacement = newDirect; replacedTypes = [0x1F] }
            case 13:
                if let cert = newCerts[block.key.body] { replacement = cert; replacedTypes = [0x10, 0x11, 0x12, 0x13] }
            case 7, 14:
                if let pub = OpenPGP448.publicBody(ofKeyBody: block.key.body),
                   let binding = newBindings[hex(CertificateValidator.fingerprint(ofKeyBody: pub))] {
                    replacement = binding
                    replacedTypes = [0x18]
                }
            default:
                break
            }
            var emitted = false
            for packet in block.rest {
                if let replacement, packet.tag == 2,
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

    // MARK: Small encoders

    /// Made again on every signature: creation time, key expiration (written
    /// back as it was unless a new one is set), issuer key ID, embedded
    /// signature, issuer fingerprint.
    private static let regenerated: Set<UInt8> = [2, 9, 16, 32, 33]

    static func subpacket(_ type: UInt8, _ data: [UInt8], critical: Bool = false) -> [UInt8] {
        OpenPGPPacketBuilder.buildSignatureSubpacket(type: critical ? (type | 0x80) : type, data: data)
    }

    private static func creation(_ body: [UInt8]) -> UInt32 {
        guard body.count >= 5 else { return 0 }
        return UInt32(body[1]) << 24 | UInt32(body[2]) << 16 | UInt32(body[3]) << 8 | UInt32(body[4])
    }

    private static func seconds(_ date: Date?) -> UInt32 {
        guard let date else { return 0 }
        let t = date.timeIntervalSince1970
        return t <= 0 ? 0 : UInt32(min(t, Double(UInt32.max)))
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func u16be(_ n: Int) -> [UInt8] { [UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)] }
    private static func u32be(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }
}
