// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// StreamingBinarySigner.swift
// PGPony
//
// v8.1.0 — §3a. An inline signature over data that is never all present.
//
// This was the last thing keeping large files from being signed, and the reason
// it held out is that `buildBinarySignaturePacket` takes `literalBody: [UInt8]`.
// That is not a small detail — it is the whole message, in memory, as a
// parameter. For a 1.6 GB file the signature was the one remaining place the
// old design was baked into a type signature.
//
// Nothing about the CRYPTOGRAPHY needed to change. SHA-256 is incremental by
// construction, and an OpenPGP v4 binary signature hashes:
//
//     literal data ‖ signature trailer ‖ 0x04 0xFF ‖ trailer length (4, BE)
//
// The data comes first and everything after it is fixed at the moment the
// signature's own fields are decided. So the hash can be fed as the file
// streams and closed out at the end — which is exactly what a one-pass
// signature packet promises a reader, and what makes signing a stream possible
// at all.
//
// ONE IMPLEMENTATION, NOT TWO
// `buildBinarySignaturePacket` now delegates here rather than keeping its own
// copy of the subpacket layout and trailer construction. That is deliberate:
// two implementations of a signature's hashed portion would eventually disagree
// by a byte, and the symptom would be signatures this app produces that no
// other implementation — including its own verifier — accepts. The one-shot is
// now "create, update once, finish", and every existing signing test is a test
// of this class.

import Foundation
import CryptoKit
import Security

/// Produces a v4 binary signature over a stream — EdDSA or RSA, chosen at
/// init by `algorithm`. Reuses `CardSignatureAlgorithm` (defined alongside the
/// card protocol layer) rather than a second enum, since the two mean exactly
/// the same thing: which packet shape a public-key algorithm produces.
///
/// Lifecycle: `onePassPacket` goes into the message BEFORE the literal packet,
/// `update` is called with the literal DATA (not the literal packet's header),
/// and `finish` returns the signature packet that goes after it.
final class StreamingBinarySigner {

    /// nil for a card-backed EdDSA signer or any RSA signer — the card path
    /// (either algorithm) uses `finalizeDigest()` + `packet(signature:)`
    /// directly instead of `finish()`.
    private let signingKey: Curve25519.Signing.PrivateKey?
    /// The RSA counterpart to `signingKey`, used by `finish()` when
    /// `algorithm == .rsa`. CryptoKit has no RSA support, so a local RSA
    /// signature goes through the Security framework instead — see `finish()`.
    private let rsaPrivateKey: SecKey?
    private let keyID: [UInt8]
    /// Which packet shape this signer builds. Fixed at v8.1.0 build 8 at SHA-256
    /// for both algorithms — see the file header on why hash isn't parameterized
    /// on the SIGNING side (the verifier, which must read other implementations'
    /// output, is a different story — see StreamingBinaryVerifier).
    let algorithm: CardSignatureAlgorithm

    /// 0x00 = binary document (the streaming large-file case this class was
    /// built for), 0x01 = canonical text. The text type exists here for the
    /// clear-sign path: a cleartext-framework signature MUST be type 0x01 over
    /// CRLF-canonicalized text, and until v8.1.0 build 10 the RSA clear-sign
    /// route had no way to produce one — ObjectivePGP hardcodes
    /// PGPSignatureBinaryDocument (and SHA-512), which gpg rejects inside a
    /// cleartext frame ("signature digest conflict"). The caller canonicalizes;
    /// this class signs whatever bytes it is fed and stamps the type it is told.
    private let sigType: UInt8

    private let hashedSubpackets: [UInt8]
    private let unhashedSubpackets: [UInt8]
    /// version ‖ sigType ‖ pubAlgo ‖ hashAlgo ‖ hashedLen ‖ hashedSubpackets.
    private let trailer: [UInt8]

    private var hasher = SHA256()
    private var finished = false
    /// Set by `finalizeDigest()`; its first two octets are the packet's hash
    /// prefix, so `packet(signature:)` needs it.
    private var finalizedDigest: [UInt8]?

    /// - Parameter creationTime: TEST SEAM. A signature embeds its creation
    ///   time in the HASHED subpackets, so two signatures made a second apart
    ///   sign different digests. Fixing it lets the streaming and one-shot paths
    ///   be compared.
    ///
    ///   Note what that comparison can and cannot be. RFC 8032 Ed25519 is
    ///   deterministic, but Apple's CryptoKit randomises, so the same message
    ///   signed twice yields different R and S values. Only the part of the
    ///   packet before those values is comparable, which is enough: it ends with
    ///   the two-octet hash prefix taken from the digest.
    init(
        signingKey: Curve25519.Signing.PrivateKey?,
        rsaPrivateKey: SecKey? = nil,
        keyID: [UInt8],
        fingerprint: [UInt8],
        algorithm: CardSignatureAlgorithm = .eddsa,
        sigType: UInt8 = 0x00,
        creationTime: Date? = nil
    ) {
        self.signingKey = signingKey
        self.rsaPrivateKey = rsaPrivateKey
        self.keyID = keyID
        self.algorithm = algorithm
        self.sigType = sigType

        let seconds = UInt32((creationTime ?? Date()).timeIntervalSince1970)

        var hashed: [UInt8] = []
        hashed.append(contentsOf: OpenPGPPacketBuilder.buildSignatureSubpacket(type: 2, data: [
            UInt8((seconds >> 24) & 0xFF),
            UInt8((seconds >> 16) & 0xFF),
            UInt8((seconds >> 8) & 0xFF),
            UInt8(seconds & 0xFF),
        ]))
        // Issuer fingerprint (type 33): version byte, then the fingerprint.
        var fingerprintData: [UInt8] = [4]
        fingerprintData.append(contentsOf: fingerprint)
        hashed.append(contentsOf: OpenPGPPacketBuilder.buildSignatureSubpacket(type: 33, data: fingerprintData))
        self.hashedSubpackets = hashed

        self.unhashedSubpackets = OpenPGPPacketBuilder.buildSignatureSubpacket(type: 16, data: keyID)

        // v4, [binary=0x00 or text=0x01], [EdDSA=22 or RSA=1], SHA-256.
        var t: [UInt8] = [4, sigType, algorithm.packetAlgorithmID, 8]
        t.append(UInt8((UInt16(hashed.count) >> 8) & 0xFF))
        t.append(UInt8(UInt16(hashed.count) & 0xFF))
        t.append(contentsOf: hashed)
        self.trailer = t
    }

    /// The one-pass signature packet (tag 4), which tells a reader a signature
    /// is coming and which key made it — so it can hash the data as it arrives
    /// rather than needing to keep it. Advertises the SAME algorithm as
    /// `packet(signature:)` will emit; a one-pass packet claiming EdDSA ahead of
    /// an RSA signature fails verification even though the signature itself is
    /// fine, because a reader picks its verification routine off this packet.
    var onePassPacket: [UInt8] {
        OpenPGPPacketBuilder.buildOnePassSignaturePacket(keyID: keyID, pubkeyAlgo: algorithm.packetAlgorithmID)
    }

    /// Feed literal data. The literal packet's own header is NOT signed — a
    /// binary signature covers the content, not the framing.
    func update(_ bytes: [UInt8]) {
        guard !finished, !bytes.isEmpty else { return }
        hasher.update(data: bytes)
    }

    /// Close the hash: fold in the trailer and the v4 footer, finalize, and keep
    /// the digest. The software path (`finish()`) does this then signs locally;
    /// the card path calls this, hands the digest to the card for PSO:CDS, and
    /// then builds the packet with `packet(signature:)`.
    @discardableResult
    func finalizeDigest() -> [UInt8] {
        finished = true

        // The trailer, then the v4 footer: 0x04 0xFF and the trailer's length.
        hasher.update(data: trailer)
        let trailerLength = UInt32(trailer.count)
        hasher.update(data: [
            4, 0xFF,
            UInt8((trailerLength >> 24) & 0xFF),
            UInt8((trailerLength >> 16) & 0xFF),
            UInt8((trailerLength >> 8) & 0xFF),
            UInt8(trailerLength & 0xFF),
        ])

        let digest = Array(hasher.finalize())
        finalizedDigest = digest
        return digest
    }

    /// Build the tag-2 signature packet from a raw signature value, however it
    /// was produced — a local key or a card's PSO:CDS. For EdDSA, `sigBytes` is
    /// the 64-byte R‖S CryptoKit/card output, split into two MPIs. For RSA,
    /// `sigBytes` is the single modulus-length value (m^d mod n), a single MPI —
    /// this is exactly the shape `CardSigner`'s RSA branch already uses, mirrored
    /// here for the streaming case. Requires `finalizeDigest()` first, whose
    /// digest supplies the two-octet hash prefix.
    func packet(signature sigBytes: [UInt8]) throws -> [UInt8] {
        guard let digest = finalizedDigest else {
            throw PacketBuilderError.signingFailed("packet(signature:) called before finalizeDigest()")
        }

        let mpis: [[UInt8]]
        switch algorithm {
        case .eddsa:
            guard sigBytes.count == 64 else {
                throw PacketBuilderError.signingFailed("Unexpected Ed25519 signature length \(sigBytes.count)")
            }
            mpis = [Array(sigBytes[0..<32]), Array(sigBytes[32..<64])]
        case .rsa:
            guard !sigBytes.isEmpty else {
                throw PacketBuilderError.signingFailed("Empty RSA signature")
            }
            // Same leading-zero strip CardSigner's RSA branch does: a modulus-
            // length value that happens to start with a zero byte (the top bits
            // of a random signature landing below the modulus's bit length, not
            // a rare event for RSA) must not be encoded with that zero byte
            // included, or the declared MPI bit length disagrees with the bytes
            // that follow it.
            var sig = sigBytes
            while sig.first == 0x00 && sig.count > 1 { sig.removeFirst() }
            mpis = [sig]
        }

        // The packet's first four octets MUST equal the trailer's first four —
        // they are the same bytes, hashed as the trailer and then written as
        // the packet header. sigType in particular: a verifier reconstructs
        // the trailer from the packet, so a byte that differs here from what
        // was hashed produces a signature nothing can verify.
        var body: [UInt8] = [4, sigType, algorithm.packetAlgorithmID, 8]
        body.append(UInt8((UInt16(hashedSubpackets.count) >> 8) & 0xFF))
        body.append(UInt8(UInt16(hashedSubpackets.count) & 0xFF))
        body.append(contentsOf: hashedSubpackets)

        body.append(UInt8((UInt16(unhashedSubpackets.count) >> 8) & 0xFF))
        body.append(UInt8(UInt16(unhashedSubpackets.count) & 0xFF))
        body.append(contentsOf: unhashedSubpackets)

        // Left 16 bits of the hash, the reader's cheap wrong-key check.
        body.append(digest[0])
        body.append(digest[1])

        for mpi in mpis {
            let bits = UInt16(mpi.count * 8 - OpenPGPPacketBuilder.countLeadingZeroBits(mpi))
            // An MPI writes only its significant bytes: ceil(bits/8) of them, with
            // the leading zero bytes stripped so the declared bit count matches the
            // bytes that follow. When an Ed25519 R or S has a zero high byte (~1 in
            // 256 each), appending the full 32 bytes made the length disagree with
            // the bit count, and every strict reader — including this app's own
            // verifier — then misaligned and rejected the signature.
            let byteCount = (Int(bits) + 7) / 8
            body.append(UInt8((bits >> 8) & 0xFF))
            body.append(UInt8(bits & 0xFF))
            body.append(contentsOf: mpi.suffix(byteCount))
        }

        return OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 2, body: body)
    }

    /// Close the hash and produce the signature packet with a LOCAL key —
    /// `signingKey` for EdDSA, `rsaPrivateKey` for RSA. A card-backed signer
    /// (either algorithm) has neither and does not call this; it calls
    /// `finalizeDigest()` itself, hands the digest to the card, and builds the
    /// packet with `packet(signature:)` directly.
    ///
    /// The RSA branch goes through the Security framework — CryptoKit has no
    /// RSA support. The DIGEST algorithm variant is used (not the message
    /// variant): the file is already reduced to a digest by `finalizeDigest()`,
    /// and `SecKeyCreateSignature` with `.rsaSignatureDigestPKCS1v15SHA256`
    /// takes that digest directly, applying the PKCS#1 v1.5 DigestInfo wrapping
    /// and padding itself — the same overall operation a card performs, just
    /// done locally instead of asked of a card (there, `CardSigner.
    /// sha256DigestInfo` builds that wrapping by hand, because a card's
    /// PSO:CDS expects the DigestInfo handed to it already built, where
    /// `SecKeyCreateSignature` builds it internally).
    func finish() throws -> [UInt8] {
        let digest = finalizeDigest()
        switch algorithm {
        case .eddsa:
            guard let signingKey else {
                throw PacketBuilderError.signingFailed("This signer has no local Ed25519 key; use the card path.")
            }
            let signature: Data
            do {
                signature = try signingKey.signature(for: Data(digest))
            } catch {
                throw PacketBuilderError.signingFailed(error.localizedDescription)
            }
            return try packet(signature: Array(signature))
        case .rsa:
            guard let rsaPrivateKey else {
                throw PacketBuilderError.signingFailed("This signer has no local RSA key; use the card path.")
            }
            var err: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(
                rsaPrivateKey, .rsaSignatureDigestPKCS1v15SHA256, Data(digest) as CFData, &err
            ) as Data? else {
                let msg = (err?.takeRetainedValue()).map { CFErrorCopyDescription($0) as String } ?? "RSA signing failed"
                throw PacketBuilderError.signingFailed(msg)
            }
            return try packet(signature: Array(signature))
        }
    }
}

// MARK: - Verifying a streamed signature

/// A signer's public key, resolved from the keyring, in whichever shape its
/// algorithm needs. `StreamingBinaryVerifier.verify` takes this instead of a
/// bare `Curve25519.Signing.PublicKey?` so RSA signers (Stage 3, v8.1.0 build
/// 8) can be checked over the same streaming path Ed25519 always has been.
enum SignerPublicKey {
    case ed25519(Curve25519.Signing.PublicKey)
    case rsa(SecKey)
    /// 8.3.0 (4.1): an RFC 9980 composite ML-DSA + EdDSA primary, as
    /// EdDSA public || ML-DSA public.
    case composite(CompositeSignSuite, [UInt8])
    /// 8.3.0 (NIST D): an ECDSA key on a NIST curve, as its SEC 1 point.
    case ecdsa(NISTCurve, [UInt8])
}

/// Checks a v4 binary signature — EdDSA or RSA, SHA-256 or SHA-512 — over data
/// that arrives in pieces.
///
/// The mirror of `StreamingBinarySigner`, and possible for the same reason the
/// signer is: the hash covers the message first and the signature's own fields
/// afterwards. What makes it work on the READ side is the one-pass signature
/// packet — it announces the key and hash algorithm BEFORE the data, so a
/// verifier can start hashing immediately instead of holding the message until
/// the signature turns up at the end. That packet exists precisely to solve, in
/// the format, the problem this whole section solves in the code.
///
/// v8.1.0 build 8 — this app's OWN streaming signer only ever produces SHA-256
/// (see `StreamingBinarySigner`), but the verifier has to read what OTHER
/// implementations produced, and GnuPG's default for RSA is SHA-512. Both are
/// accepted, selected off the one-pass packet's hash octet, since CryptoKit's
/// SHA256 and SHA512 are separate types with no common incremental-hash base
/// this file already depended on — `any HashFunction` is the existential that
/// lets one property hold either without a second copy of this whole class.
///
/// WHAT A FALSE RESULT MEANS HERE
/// `isValid == false` means the bytes were altered or the signer is not who the
/// packet claims. `isValid == nil` means no verification was possible — usually
/// the signer's public key is not in the keyring, or its type doesn't match
/// what the packet claims — and is NOT a failure of the message. Conflating the
/// two would either cry wolf on mail from strangers or stay silent on
/// tampering, so they stay separate all the way to the caller.
final class StreamingBinaryVerifier {

    /// The key that claims to have signed, from the one-pass packet.
    let signerKeyID: [UInt8]

    private var hasher: any HashFunction
    private let hashAlgorithm: UInt8
    /// 22 = EdDSA (v4), 27 = Ed25519 native (v6), 1 = RSA (Encrypt-or-Sign),
    /// 3 = RSA Sign-Only (old keys).
    private let pubkeyAlgorithm: UInt8
    /// Signature version this verifier is set up for: 4 or 6.
    private let version: UInt8
    /// v6 only: the 16-octet salt, prepended to the hash at init (v4 = empty).
    private let salt: [UInt8]

    /// - Parameter onePassBody: a tag 4 packet body:
    ///   version, sigType, hashAlgo, pubAlgo, keyID(8), nested.
    init?(onePassBody: [UInt8]) {
        guard let opsVersion = onePassBody.first else { return nil }
        // Only binary-document signatures are streamed; a text signature would
        // need canonicalisation of the data as it passes, which is a different
        // job and not one to guess at.
        if opsVersion == 6 {
            // v6 OPS (RFC 9580 §5.4): version|sigType|hashAlgo|pubAlgo|saltLen|
            //                         salt|issuerFingerprint(32)|nested.
            guard onePassBody.count >= 5 else { return nil }
            guard onePassBody[1] == 0x00 else { return nil }
            let hashAlgo = onePassBody[2]
            let pubAlgo = onePassBody[3]
            // Ed25519 native (v6), or a composite ML-DSA + EdDSA key (8.3.0, 4.1).
            guard pubAlgo == 27 || CompositeSignSuite.isComposite(pubAlgo) else { return nil }
            let saltLen = Int(onePassBody[4])
            guard onePassBody.count >= 5 + saltLen + 32 + 1 else { return nil }
            switch hashAlgo {
            case 8:  self.hasher = SHA256()
            case 10: self.hasher = SHA512()
            case 12: self.hasher = SHA3_256()   // 8.3.0 (4.1): RFC 9980 composite signatures
            case 14: self.hasher = SHA3_512()
            default: return nil
            }
            self.version = 6
            self.hashAlgorithm = hashAlgo
            self.pubkeyAlgorithm = pubAlgo
            let s = Array(onePassBody[5..<(5 + saltLen)])
            self.salt = s
            let fingerprint = Array(onePassBody[(5 + saltLen)..<(5 + saltLen + 32)])
            self.signerKeyID = Array(fingerprint.prefix(8))
        } else {
            guard onePassBody.count >= 13 else { return nil }
            guard onePassBody[1] == 0x00 else { return nil }
            let hashAlgo = onePassBody[2]
            let pubAlgo = onePassBody[3]
            guard pubAlgo == 22 || pubAlgo == 1 || pubAlgo == 3 || pubAlgo == 19 else { return nil }
            switch hashAlgo {
            case 8:  self.hasher = SHA256()
            case 9:  self.hasher = SHA384()   // 8.3.0 (NIST D): GnuPG's P-384 pairing
            case 10: self.hasher = SHA512()
            default: return nil   // unsupported hash — treat as unverifiable, not a crash
            }
            self.version = 4
            self.hashAlgorithm = hashAlgo
            self.pubkeyAlgorithm = pubAlgo
            self.salt = []
            self.signerKeyID = Array(onePassBody[4..<12])
        }
        // v6 hashes salt || document || ...; fold the salt in before any data.
        if !salt.isEmpty { hasher.update(data: Data(salt)) }
    }

    func update(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        hasher.update(data: bytes)
    }

    /// Finish the hash using the signature packet's own hashed portion, then
    /// check it against the signer's public key.
    ///
    /// - Returns: nil when the signature cannot be checked at all — unknown
    ///   signer, unsupported algorithm, a public-key TYPE that doesn't match
    ///   what the packet claims (e.g. an Ed25519 key on file for an issuer
    ///   whose packet claims RSA — the keyring entry is for the wrong key),
    ///   or a malformed packet.
    func verify(signatureBody body: [UInt8], publicKey: SignerPublicKey?) -> Bool? {
        guard let publicKey else { return nil }
        if version == 6 { return verifyV6(signatureBody: body, publicKey: publicKey) }
        guard body.count > 6, body[0] == 4, body[1] == 0x00 else { return nil }
        // The signature packet's own algorithm octets must match what the
        // one-pass packet announced — a mismatch here means the message is
        // malformed (or hostile), not that verification legitimately failed.
        guard body[2] == pubkeyAlgorithm, body[3] == hashAlgorithm else { return nil }

        let hashedLength = (Int(body[4]) << 8) | Int(body[5])
        let hashedEnd = 6 + hashedLength
        guard body.count > hashedEnd + 1 else { return nil }

        // The trailer is the signature packet's first six octets plus its
        // hashed subpackets — exactly the bytes the signer hashed after the
        // message.
        let trailer = Array(body[0..<hashedEnd])
        hasher.update(data: trailer)

        let trailerLength = UInt32(trailer.count)
        hasher.update(data: [
            4, 0xFF,
            UInt8((trailerLength >> 24) & 0xFF),
            UInt8((trailerLength >> 16) & 0xFF),
            UInt8((trailerLength >> 8) & 0xFF),
            UInt8(trailerLength & 0xFF),
        ])
        let digest = Array(hasher.finalize())

        // Skip the unhashed subpackets and the two-octet hash prefix, then read
        // the signature MPI(s).
        var offset = hashedEnd
        let unhashedLength = (Int(body[offset]) << 8) | Int(body[offset + 1])
        offset += 2 + unhashedLength
        guard body.count > offset + 1 else { return nil }
        offset += 2                                   // left 16 bits of the hash

        switch (pubkeyAlgorithm, publicKey) {
        case (22, .ed25519(let key)):
            guard let r = readMPI(body, &offset), let s = readMPI(body, &offset) else { return nil }
            let signature = pad32(r) + pad32(s)
            guard signature.count == 64 else { return nil }
            return key.isValidSignature(Data(signature), for: Data(digest))

        case (19, .ecdsa(let curve, let point)):
            // 8.3.0 (NIST D): r and s as written; the verifier pads them.
            guard let r = readMPI(body, &offset), let s = readMPI(body, &offset) else { return nil }
            return try? NISTECDSAService.verify(r: r, s: s, digest: digest, curve: curve, publicPoint: point)

        case (1, .rsa(let key)), (3, .rsa(let key)):
            guard let sig = readMPI(body, &offset) else { return nil }
            // The DIGEST variant: `digest` is already the finalized hash, and
            // this asks Security to apply PKCS#1 v1.5 verification against it
            // directly rather than hashing a message itself.
            let secAlgorithm: SecKeyAlgorithm = hashAlgorithm == 10
                ? .rsaSignatureDigestPKCS1v15SHA512
                : .rsaSignatureDigestPKCS1v15SHA256
            return SecKeyVerifySignature(
                key, secAlgorithm, Data(digest) as CFData, Data(sig) as CFData, nil
            )

        default:
            // The packet's claimed algorithm and the resolved key's actual
            // type disagree — e.g. `resolveSigner` found an Ed25519 model
            // whose key ID happens to collide with an RSA issuer's. Cannot be
            // verified; NOT the same as bytes having been altered.
            return nil
        }
    }

    /// v6 counterpart of `verify`: reconstruct the v6 hash (salt was folded in
    /// at init, the document streamed through `update`) from the v6 signature
    /// packet's own hashed portion, then check the native 64-byte Ed25519
    /// signature. Mirrors OpenPGPPacketBuilder.buildBinarySignaturePacketV6 and
    /// StreamingV6Signer.
    private func verifyV6(signatureBody body: [UInt8], publicKey: SignerPublicKey) -> Bool? {
        guard body.count > 8, body[0] == 6, body[1] == 0x00 else { return nil }
        guard body[2] == pubkeyAlgorithm, body[3] == hashAlgorithm else { return nil }

        // v6 hashed length is four octets (v4 uses two).
        let hashedLength = (Int(body[4]) << 24) | (Int(body[5]) << 16)
                         | (Int(body[6]) << 8) | Int(body[7])
        let hashedEnd = 8 + hashedLength
        guard body.count > hashedEnd else { return nil }

        // rawHashedPortion = 6|sigType|27|8|hashedLen(4)|hashed, then the v6
        // footer 0x06 0xFF + 4-octet big-endian length.
        let rawHashed = Array(body[0..<hashedEnd])
        hasher.update(data: Data(rawHashed))
        let total = UInt32(rawHashed.count)
        hasher.update(data: Data([
            0x06, 0xFF,
            UInt8((total >> 24) & 0xFF),
            UInt8((total >> 16) & 0xFF),
            UInt8((total >> 8) & 0xFF),
            UInt8(total & 0xFF),
        ]))
        let digest = Array(hasher.finalize())

        // After the hashed area: unhashedLen(4)|unhashed|hashPrefix(2)|
        // saltLen(1)|salt|signature(native, no MPI: 64 for Ed25519, the
        // composite length for algorithm 30/31).
        let sigLen = CompositeSignSuite.forAlgorithm(pubkeyAlgorithm)?.compositeSignatureLength ?? 64
        var offset = hashedEnd
        guard body.count >= offset + 4 else { return nil }
        let unhashedLength = (Int(body[offset]) << 24) | (Int(body[offset + 1]) << 16)
                           | (Int(body[offset + 2]) << 8) | Int(body[offset + 3])
        offset += 4 + unhashedLength
        guard body.count >= offset + 2 else { return nil }
        offset += 2                                   // two-octet hash prefix
        guard body.count >= offset + 1 else { return nil }
        let sigSaltLen = Int(body[offset]); offset += 1
        guard body.count >= offset + sigSaltLen + sigLen else { return nil }
        offset += sigSaltLen
        let signature = Array(body[offset..<(offset + sigLen)])

        switch publicKey {
        case .ed25519(let key) where pubkeyAlgorithm == 27:
            return key.isValidSignature(Data(signature), for: Data(digest))
        case .composite(let suite, let material) where suite.rawValue == pubkeyAlgorithm:
            // 8.3.0 (4.1): both components over the same digest. An
            // uncheckable composite (no ML-DSA on this OS) is nil, not false:
            // the bytes were not found wrong, they could not be checked.
            switch CompositeSigVerifier.verify(suite: suite, compositePublic: material,
                                               signature: signature, digest: digest) {
            case .valid: return true
            case .invalid: return false
            case .unsupported: return nil
            }
        default:
            // The packet's claimed algorithm and the resolved key's type disagree.
            return nil
        }
    }

    /// An OpenPGP MPI: a two-octet bit count, then that many bits of big-endian
    /// data.
    private func readMPI(_ body: [UInt8], _ offset: inout Int) -> [UInt8]? {
        guard body.count > offset + 1 else { return nil }
        let bits = (Int(body[offset]) << 8) | Int(body[offset + 1])
        let bytes = (bits + 7) / 8
        offset += 2
        guard body.count >= offset + bytes else { return nil }
        defer { offset += bytes }
        return Array(body[offset..<(offset + bytes)])
    }

    /// MPIs drop leading zero bytes; Ed25519 wants a fixed 32.
    private func pad32(_ value: [UInt8]) -> [UInt8] {
        guard value.count < 32 else { return Array(value.suffix(32)) }
        return [UInt8](repeating: 0, count: 32 - value.count) + value
    }
}

// MARK: - Streaming signer protocol

/// The three moves the streaming message-builder (`LargeFileCrypto.pump`) needs
/// from a signer, independent of signature version: the one-pass packet that
/// goes in front of the literal data, the running hash update per chunk, and the
/// terminating signature packet. `StreamingBinarySigner` (v4 EdDSA/RSA) and
/// `StreamingV6Signer` (v6 Ed25519) both satisfy it, so the same pump loop signs
/// either without knowing which version it is feeding.
protocol StreamingMessageSigner: AnyObject {
    var onePassPacket: [UInt8] { get }
    func update(_ bytes: [UInt8])
    func finish() throws -> [UInt8]
}

extension StreamingBinarySigner: StreamingMessageSigner {}

// MARK: - v6 streaming signer

/// Inline v6 Ed25519 signature over data that is never all present — the v6
/// counterpart to `StreamingBinarySigner`, and the piece that lets a large file
/// be signed AND encrypted to a post-quantum (ML-KEM composite) recipient
/// without holding the plaintext.
///
/// It is byte-for-byte the same construction `OpenPGPPacketBuilder`'s
/// `buildOnePassSignaturePacketV6` + `buildBinarySignaturePacketV6` produce for
/// the in-memory path; the only difference is that the literal body is hashed as
/// it streams instead of being passed as one `[UInt8]`. A v6 binary signature
/// hashes:
///
///     salt ‖ literal data ‖ rawHashedPortion ‖ 0x06 0xFF ‖ len(rawHashedPortion) (4, BE)
///
/// Everything except the literal data is fixed the moment the signature's own
/// fields are chosen, so `salt` is fed first, each chunk next, and the trailer
/// last — the same shape the v4 signer uses, one version up.
final class StreamingV6Signer: StreamingMessageSigner {

    /// 8.3.0 (4.1): Ed25519 (algorithm 27) or a composite ML-DSA + EdDSA
    /// primary (30/31); the algorithm octet and signature come from it.
    private let signer: V6SignatureKey
    private let fingerprint: [UInt8]          // 32-byte v6 fingerprint
    private let salt: [UInt8]                 // 16 octets, shared with the OPS packet
    private let hashedSubpackets: [UInt8]
    private let unhashedSubpackets: [UInt8]
    private let rawHashedPortion: [UInt8]     // 6|type|27|8|hashedLen(4)|hashed

    private var hasher = SHA256()
    private var finished = false

    /// - Parameter creationTime: TEST SEAM, same role as in `StreamingBinarySigner`
    ///   — pinning it lets the streamed packet be compared against the one-shot
    ///   builder up to the signature value (Ed25519 via CryptoKit randomises R‖S).
    convenience init(signingKey: Curve25519.Signing.PrivateKey,
                     fingerprint: [UInt8],
                     salt: [UInt8]? = nil,
                     creationTime: Date? = nil) throws {
        try self.init(signer: .ed25519(signingKey), fingerprint: fingerprint, salt: salt, creationTime: creationTime)
    }

    init(signer: V6SignatureKey,
         fingerprint: [UInt8],
         salt: [UInt8]? = nil,
         creationTime: Date? = nil) throws {
        self.signer = signer
        self.fingerprint = Array(fingerprint.prefix(32))

        if let salt, salt.count == 16 {
            self.salt = salt
        } else {
            var s = [UInt8](repeating: 0, count: 16)
            guard SecRandomCopyBytes(kSecRandomDefault, s.count, &s) == errSecSuccess else {
                throw PacketBuilderError.signingFailed("could not generate v6 signature salt")
            }
            self.salt = s
        }

        let seconds = UInt32((creationTime ?? Date()).timeIntervalSince1970)

        // Hashed subpackets: creation time (type 2) + issuer fingerprint (type 33, v6 = 6‖fp).
        var hashed: [UInt8] = []
        hashed.append(contentsOf: OpenPGPPacketBuilder.buildSignatureSubpacket(type: 2, data: [
            UInt8((seconds >> 24) & 0xFF),
            UInt8((seconds >> 16) & 0xFF),
            UInt8((seconds >> 8) & 0xFF),
            UInt8(seconds & 0xFF),
        ]))
        var fpData: [UInt8] = [6]
        fpData.append(contentsOf: self.fingerprint)
        hashed.append(contentsOf: OpenPGPPacketBuilder.buildSignatureSubpacket(type: 33, data: fpData))
        self.hashedSubpackets = hashed

        // Unhashed: issuer key ID (type 16) = leading 8 of the v6 fingerprint.
        self.unhashedSubpackets =
            OpenPGPPacketBuilder.buildSignatureSubpacket(type: 16, data: Array(self.fingerprint.prefix(8)))

        // rawHashedPortion: 6 | sigType(0x00) | algo | hash(8) | hashedLen(4) | hashed
        var raw: [UInt8] = [6, 0x00, signer.publicKeyAlgorithm, 8]
        let hashedLen32 = UInt32(hashed.count)
        raw.append(UInt8((hashedLen32 >> 24) & 0xFF))
        raw.append(UInt8((hashedLen32 >> 16) & 0xFF))
        raw.append(UInt8((hashedLen32 >> 8) & 0xFF))
        raw.append(UInt8(hashedLen32 & 0xFF))
        raw.append(contentsOf: hashed)
        self.rawHashedPortion = raw

        // Hash begins with the salt, exactly as the in-memory builder prepends it.
        hasher.update(data: self.salt)
    }

    /// The v6 one-pass signature packet (tag 4), carrying the shared salt and the
    /// full 32-byte issuer fingerprint. Goes in BEFORE the literal packet.
    var onePassPacket: [UInt8] {
        var body: [UInt8] = []
        body.append(6)                          // version 6
        body.append(0x00)                       // sig type: binary document
        body.append(8)                          // hash algo: SHA-256
        body.append(signer.publicKeyAlgorithm)  // pub algo: 27 Ed25519, 30/31 composite
        body.append(UInt8(salt.count))
        body.append(contentsOf: salt)
        body.append(contentsOf: fingerprint)    // 32-byte issuer fingerprint
        body.append(1)                          // nested flag: last OPS
        return OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 4, body: body)
    }

    /// Feed literal data. The literal packet framing is not signed — only content.
    func update(_ bytes: [UInt8]) {
        guard !finished, !bytes.isEmpty else { return }
        hasher.update(data: bytes)
    }

    /// Close the hash (rawHashedPortion, then the v6 footer 0x06 0xFF ‖ length),
    /// sign the digest, and build the tag-2 v6 signature packet.
    func finish() throws -> [UInt8] {
        finished = true

        hasher.update(data: Data(rawHashedPortion))
        let totalHashed4 = UInt32(rawHashedPortion.count)
        hasher.update(data: Data([
            0x06, 0xFF,
            UInt8((totalHashed4 >> 24) & 0xFF),
            UInt8((totalHashed4 >> 16) & 0xFF),
            UInt8((totalHashed4 >> 8) & 0xFF),
            UInt8(totalHashed4 & 0xFF),
        ]))

        let digestBytes = Array(hasher.finalize())
        let sigBytes: [UInt8]
        do {
            sigBytes = try signer.sign(digest: digestBytes)
        } catch {
            throw PacketBuilderError.signingFailed((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
        }
        guard sigBytes.count == signer.signatureLength else {
            throw PacketBuilderError.signingFailed("v6 signature must be \(signer.signatureLength) bytes, got \(sigBytes.count)")
        }

        // Packet body: 6 | type | algo | 8 | hashedLen(4) | hashed | unhashedLen(4) |
        //              unhashed | hashPrefix(2) | saltLen(1) | salt | sig
        var sigBody: [UInt8] = [6, 0x00, signer.publicKeyAlgorithm, 8]
        let hashedLen32 = UInt32(hashedSubpackets.count)
        sigBody.append(UInt8((hashedLen32 >> 24) & 0xFF))
        sigBody.append(UInt8((hashedLen32 >> 16) & 0xFF))
        sigBody.append(UInt8((hashedLen32 >> 8) & 0xFF))
        sigBody.append(UInt8(hashedLen32 & 0xFF))
        sigBody.append(contentsOf: hashedSubpackets)
        let unhashedLen32 = UInt32(unhashedSubpackets.count)
        sigBody.append(UInt8((unhashedLen32 >> 24) & 0xFF))
        sigBody.append(UInt8((unhashedLen32 >> 16) & 0xFF))
        sigBody.append(UInt8((unhashedLen32 >> 8) & 0xFF))
        sigBody.append(UInt8(unhashedLen32 & 0xFF))
        sigBody.append(contentsOf: unhashedSubpackets)
        sigBody.append(digestBytes[0])
        sigBody.append(digestBytes[1])
        sigBody.append(UInt8(salt.count))
        sigBody.append(contentsOf: salt)
        sigBody.append(contentsOf: sigBytes)   // native signature value (no MPI)

        return OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: 2, body: sigBody)
    }
}
