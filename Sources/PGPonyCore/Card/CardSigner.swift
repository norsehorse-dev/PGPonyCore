// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CardSigner.swift
// PGPony
//
// v6.0 — Phase 8b: assemble a real OpenPGP detached signature whose 64-byte
// Ed25519 value is produced on the card (PSO:CDS) rather than by a local key.
//
// The packet construction is identical to the in-app v4 EdDSA detached path
// (binary document, sig type 0x00, SHA-256, issuer-fingerprint subpacket 33) —
// the only difference is that the digest is handed to the card to sign. This is
// both the Phase 8b verification artifact (gpg --verify against the card's signing
// key) and the exact logic Phase 9's card detached-signing feature reuses.

import Foundation
import CryptoKit

enum CardSigner {

    enum SignError: LocalizedError {
        case badSignatureLength(Int)
        case emptyCardSignature
        /// 8.4.0 build 10 (plan 5m): an ECDSA answer that is not r || s for the
        /// slot's curve (nor a DER pair that fits it).
        case badECDSASignatureLength(Int, expected: Int)
        var errorDescription: String? {
            switch self {
            case .badSignatureLength(let n):
                return String(localized: "The card returned a \(n)-byte signature; expected 64.")
            case .emptyCardSignature:
                return String(localized: "The card returned an empty signature.")
            case .badECDSASignatureLength(let n, let expected):
                return String(localized: "The card returned a \(n)-byte signature; expected \(expected).")
            }
        }
    }

    /// Build an ASCII-armored, gpg-verifiable detached signature over `message`,
    /// signed on the card. `signFingerprint20` is the card's signing-key
    /// fingerprint (20 bytes). The session must already have PW1 (mode `.signing`)
    /// verified.
    static func detachedSignature(
        message: [UInt8],
        algorithm: CardSignatureAlgorithm,
        signFingerprint20: [UInt8],
        service: OpenPGPCardService
    ) async throws -> String {
        // Sig type 0x00 = binary document. Output is byte-identical to the
        // pre-9i detached path.
        let (packet, _) = try await signaturePacket(
            message: message, sigType: 0x00, algorithm: algorithm,
            signFingerprint20: signFingerprint20, service: service
        )
        return armorSignature(packet)
    }

    /// v6.0 — Phase 9i: ASCII-armored signature with a caller-chosen sig type,
    /// signed on the card. Clear-signing passes sigType 0x01 over the
    /// canonicalized text bytes. The session must already have PW1 (`.signing`)
    /// verified.
    static func armoredSignature(
        message: [UInt8],
        sigType: UInt8,
        algorithm: CardSignatureAlgorithm,
        signFingerprint20: [UInt8],
        service: OpenPGPCardService
    ) async throws -> String {
        let (packet, _) = try await signaturePacket(
            message: message, sigType: sigType, algorithm: algorithm,
            signFingerprint20: signFingerprint20, service: service
        )
        return armorSignature(packet)
    }

    /// v6.0 — Phase 9i: raw v4 binary-document (sig type 0x00) signature *packet*
    /// over `message`, signed on the card, returned un-armored alongside the
    /// 8-byte issuer key ID. Used to embed an inline signature inside an encrypted
    /// message (OnePassSig || Literal || Signature). The session must already have
    /// PW1 (`.signing`) verified.
    static func binarySignaturePacket(
        message: [UInt8],
        algorithm: CardSignatureAlgorithm,
        signFingerprint20: [UInt8],
        service: OpenPGPCardService
    ) async throws -> (packet: [UInt8], keyID: [UInt8]) {
        try await signaturePacket(
            message: message, sigType: 0x00, algorithm: algorithm,
            signFingerprint20: signFingerprint20, service: service
        )
    }

    /// Shared core: build a v4 signature packet over `message` with the
    /// given sig type, having the card produce the signature value via PSO:CDS.
    /// EdDSA (algo 22) produces a 64-byte R||S (two MPIs); RSA (algo 1) produces
    /// one modulus-length value (a single MPI) over a PKCS#1 v1.5 DigestInfo.
    /// 8.4.0 build 10 (plan 5m): ECDSA (algo 19) produces r || s (two MPIs) over
    /// the curve's hash. EdDSA and RSA keep SHA-256; ECDSA uses SHA-256, SHA-384
    /// or SHA-512 by curve (`algorithm.hashAlgorithmID`).
    /// Returns the new-format tag-2 packet bytes plus the issuer key ID. Subpacket
    /// layout (hashed: creation time + issuer FP; unhashed: issuer key ID) matches
    /// the in-app software signer exactly.
    private static func signaturePacket(
        message: [UInt8],
        sigType: UInt8,
        algorithm: CardSignatureAlgorithm,
        signFingerprint20: [UInt8],
        service: OpenPGPCardService
    ) async throws -> (packet: [UInt8], keyID: [UInt8]) {
        let now = UInt32(Date().timeIntervalSince1970)
        let issuerFP: [UInt8] = [4] + signFingerprint20
        let keyID = Array(signFingerprint20.suffix(8))
        let pubAlgo = algorithm.packetAlgorithmID

        let hashed = buildSubpacket(type: 2, data: u32be(now))
                   + buildSubpacket(type: 33, data: issuerFP)
        let unhashed = buildSubpacket(type: 16, data: keyID)

        let hashAlgo = algorithm.hashAlgorithmID

        // v4 trailer: version, sig type, pubkey algo, hash algo (SHA-256 = 8,
        // or the curve's hash for ECDSA).
        var trailer: [UInt8] = [4, sigType, pubAlgo, hashAlgo]
        trailer += u16be(UInt16(hashed.count)) + hashed

        // Hash the document bytes directly, then the trailer. For sig type 0x01
        // (canonical text) the caller has already canonicalized line endings.
        var hashInput = Data(message)
        hashInput.append(contentsOf: trailer)
        hashInput.append(contentsOf: [4, 0xFF] + u32be(UInt32(trailer.count)))
        let digest = algorithm.digest(hashInput)

        // Produce the algorithm-specific signature MPI list on the card. EdDSA
        // signs the bare digest and returns 64 bytes (R || S, two MPIs); RSA
        // signs a PKCS#1 v1.5 DigestInfo and returns one modulus-length value
        // (a single MPI, leading zero octets stripped); ECDSA signs the hash
        // and returns r || s (two MPIs). 8.4.0 build 10 (plan 5m): one helper
        // for every card signing path, so they cannot disagree.
        let raw = try await service.signDigest(digest, algorithm: algorithm)
        let mpis = try algorithm.signatureMPIs(fromCardOutput: raw)

        let body = assembleSignatureBody(
            pubkeyAlgo: pubAlgo, sigType: sigType,
            hashed: hashed, unhashed: unhashed,
            hashPrefix2: [digest[0], digest[1]], signatureMPIs: mpis,
            hashAlgorithm: hashAlgo
        )
        return (buildNewFormatPacket(tag: 2, body: body), keyID)
    }

    /// Pure, hardware-free assembly of a v4 signature packet body (hash algo is
    /// SHA-256 = 8 unless `hashAlgorithm` says otherwise). `signatureMPIs` is the
    /// algorithm's signature value split into MPIs: [R, S] for EdDSA, [sig] for
    /// RSA, [r, s] for ECDSA. Exposed internally so the framing can be
    /// unit-tested without a card.
    static func assembleSignatureBody(
        pubkeyAlgo: UInt8,
        sigType: UInt8,
        hashed: [UInt8],
        unhashed: [UInt8],
        hashPrefix2: [UInt8],
        signatureMPIs: [[UInt8]],
        hashAlgorithm: UInt8 = 8
    ) -> [UInt8] {
        var body: [UInt8] = [4, sigType, pubkeyAlgo, hashAlgorithm]
        body += u16be(UInt16(hashed.count)) + hashed
        body += u16be(UInt16(unhashed.count)) + unhashed
        body += hashPrefix2
        for mpi in signatureMPIs { body += mpiEncode(mpi) }
        return body
    }

    /// PKCS#1 v1.5 DigestInfo for a SHA-256 hash: the fixed 19-byte DER prefix
    /// — SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }, OCTET STRING }
    /// — followed by the 32-byte digest. This is what an OpenPGP card's PSO:CDS
    /// expects as input for an RSA signing key; the card adds the EMSA-PKCS1-v1_5
    /// padding itself.
    private static let sha256DigestInfoPrefix: [UInt8] = [
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    ]
    static func sha256DigestInfo(_ digest: [UInt8]) -> [UInt8] {
        sha256DigestInfoPrefix + digest
    }

    // MARK: - Encoders (local; same behavior as the rest of the codebase)

    private static func buildSubpacket(type: UInt8, data: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        let total = data.count + 1
        if total < 192 {
            out.append(UInt8(total))
        } else if total < 8384 {
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

    private static func mpiEncode(_ bytes: [UInt8]) -> [UInt8] {
        var leadingZeros = 0
        for b in bytes {
            if b == 0 { leadingZeros += 8; continue }
            var bb = b
            while (bb & 0x80) == 0 { leadingZeros += 1; bb <<= 1 }
            break
        }
        let bitLen = UInt16(bytes.count * 8 - leadingZeros)
        // RFC 4880 3.2: an MPI carries no leading zero octets, and its byte
        // count must equal ceil(bitLen / 8). Emitting the full input (leading
        // zeros included) while declaring the shorter bit length leaves the
        // field self-inconsistent, so a strict reader misaligns the next MPI.
        // On a card signature that is an EdDSA R or S (S, a reduced scalar,
        // often has a high zero octet) or the RSA value, so a card-made
        // signature would intermittently fail to verify. Mirrors the fix in
        // SigningService / KeyExpirationEditor; covered by CardSignerSignatureTests.
        var value = bytes
        while value.first == 0 { value.removeFirst() }
        return [UInt8((bitLen >> 8) & 0xFF), UInt8(bitLen & 0xFF)] + value
    }

    private static func buildNewFormatPacket(tag: UInt8, body: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [0xC0 | (tag & 0x3F)]
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

    private static func u16be(_ v: UInt16) -> [UInt8] { [UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)] }
    private static func u32be(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }

    private static func armorSignature(_ data: [UInt8]) -> String {
        let b64 = Data(data).base64EncodedString(options: .lineLength76Characters)
        let crc = Data(crc24(data)).base64EncodedString()
        // Splice in the user-configured Comment header (or nothing). Card
        // signing is in scope for the armor-comment setting.
        return "-----BEGIN PGP SIGNATURE-----\n\(ArmorComment.headerBlock())\n\(b64)\n=\(crc)\n-----END PGP SIGNATURE-----\n"
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

// MARK: - 8.4.0 build 10 (plan 5m): what each card algorithm hashes, sends and gets back

extension CardSignatureAlgorithm {

    /// The OpenPGP hash ID a card signature of this algorithm uses. EdDSA and
    /// RSA stay on SHA-256 (8), which the RSA DigestInfo prefix assumes. ECDSA
    /// follows the curve as GnuPG and the software ECDSA signer do: SHA-256 (8)
    /// on P-256, SHA-384 (9) on P-384, SHA-512 (10) on P-521.
    var hashAlgorithmID: UInt8 {
        switch self {
        case .eddsa, .rsa: return 8
        case .ecdsa(let curve): return curve.hashAlgorithmID
        }
    }

    /// The cleartext "Hash:" armor header for `hashAlgorithmID`.
    var armorHashName: String {
        switch hashAlgorithmID {
        case 9: return "SHA384"
        case 10: return "SHA512"
        default: return "SHA256"
        }
    }

    /// `data` hashed with `hashAlgorithmID`.
    func digest(_ data: Data) -> [UInt8] {
        var hasher = CardDigestHasher(hashAlgorithmID: hashAlgorithmID)
        hasher.update(data: data)
        return hasher.finalize()
    }

    /// What PSO:COMPUTE DIGITAL SIGNATURE takes for `digest`: the bare digest
    /// for EdDSA, a SHA-256 DigestInfo for RSA, and for ECDSA the hash cut to
    /// the curve's field size (its leftmost octets), per the OpenPGP card spec
    /// 3.4. A natural hash is never longer than its curve, so the cut only
    /// matters for a longer hash.
    func cardInput(forDigest digest: [UInt8]) -> [UInt8] {
        switch self {
        case .eddsa:
            return digest
        case .rsa:
            return CardSigner.sha256DigestInfo(digest)
        case .ecdsa(let curve):
            return digest.count > curve.fieldSize ? Array(digest.prefix(curve.fieldSize)) : digest
        }
    }

    /// The signature MPIs (before MPI framing) from the card's raw PSO:CDS
    /// output: [R, S] for EdDSA (64 octets), [value] for RSA with leading zero
    /// octets stripped, [r, s] for ECDSA (r || s, each the field size; a DER
    /// SEQUENCE of two INTEGERs is taken too, as a fallback for a card that
    /// answers that way). MPI encoding strips the remaining zero octets.
    func signatureMPIs(fromCardOutput raw: [UInt8]) throws -> [[UInt8]] {
        switch self {
        case .eddsa:
            guard raw.count == 64 else { throw CardSigner.SignError.badSignatureLength(raw.count) }
            return [Array(raw[0..<32]), Array(raw[32..<64])]
        case .rsa:
            guard !raw.isEmpty else { throw CardSigner.SignError.emptyCardSignature }
            // Canonical OpenPGP MPI: the byte count must match the bit length, so
            // strip any leading zero bytes the card padded the value with.
            var sig = raw
            while sig.first == 0x00 && sig.count > 1 { sig.removeFirst() }
            return [sig]
        case .ecdsa(let curve):
            guard !raw.isEmpty else { throw CardSigner.SignError.emptyCardSignature }
            guard let rs = Self.ecdsaRawSignature(raw, curve: curve) else {
                throw CardSigner.SignError.badECDSASignatureLength(raw.count, expected: 2 * curve.fieldSize)
            }
            return [Array(rs[0..<curve.fieldSize]), Array(rs[curve.fieldSize...])]
        }
    }

    /// r || s, each left-padded to the field size, from the card's answer:
    /// already that shape (the OpenPGP card form), or a DER SEQUENCE { INTEGER
    /// r, INTEGER s } whose integers fit the field. Nil otherwise.
    static func ecdsaRawSignature(_ raw: [UInt8], curve: NISTCurve) -> [UInt8]? {
        let size = curve.fieldSize
        if raw.count == 2 * size { return raw }
        // DER fallback.
        func readLength(_ bytes: [UInt8], _ i: inout Int) -> Int? {
            guard i < bytes.count else { return nil }
            let first = Int(bytes[i]); i += 1
            if first < 0x80 { return first }
            let n = first & 0x7F
            guard n >= 1, n <= 2, i + n <= bytes.count else { return nil }
            var len = 0
            for _ in 0..<n { len = (len << 8) | Int(bytes[i]); i += 1 }
            return len
        }
        func readInteger(_ bytes: [UInt8], _ i: inout Int) -> [UInt8]? {
            guard i < bytes.count, bytes[i] == 0x02 else { return nil }
            i += 1
            guard let len = readLength(bytes, &i), len >= 1, i + len <= bytes.count else { return nil }
            var value = Array(bytes[i..<(i + len)])
            i += len
            while value.count > 1 && value.first == 0 { value.removeFirst() }
            return curve.padded(value)
        }
        guard raw.first == 0x30 else { return nil }
        var i = 1
        guard let seqLen = readLength(raw, &i), i + seqLen == raw.count else { return nil }
        guard let r = readInteger(raw, &i), let s = readInteger(raw, &i), i == raw.count else { return nil }
        return r + s
    }
}

/// 8.4.0 build 10 (plan 5m): an incremental hash picked by OpenPGP hash ID
/// (8 SHA-256, 9 SHA-384, 10 SHA-512; anything else SHA-256), so a signer that
/// streams its input can follow `CardSignatureAlgorithm.hashAlgorithmID`.
/// `nonisolated` so it can be fed off the main thread like CryptoKit's own.
nonisolated struct CardDigestHasher {
    // Exactly one of the three is set, by the hash ID given at init.
    private var sha256: SHA256?
    private var sha384: SHA384?
    private var sha512: SHA512?

    init(hashAlgorithmID: UInt8) {
        switch hashAlgorithmID {
        case 9: sha384 = SHA384()
        case 10: sha512 = SHA512()
        default: sha256 = SHA256()
        }
    }

    mutating func update<D: DataProtocol>(data: D) {
        sha256?.update(data: data)
        sha384?.update(data: data)
        sha512?.update(data: data)
    }

    func finalize() -> [UInt8] {
        if let h = sha384 { return Array(h.finalize()) }
        if let h = sha512 { return Array(h.finalize()) }
        return Array((sha256 ?? SHA256()).finalize())
    }
}
