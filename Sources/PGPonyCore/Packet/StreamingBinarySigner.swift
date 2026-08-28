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
    /// 22 = EdDSA, 1 = RSA (Encrypt-or-Sign), 3 = RSA Sign-Only (old keys).
    private let pubkeyAlgorithm: UInt8

    /// - Parameter onePassBody: a tag 4 packet body:
    ///   version, sigType, hashAlgo, pubAlgo, keyID(8), nested.
    init?(onePassBody: [UInt8]) {
        guard onePassBody.count >= 13 else { return nil }
        // Only binary-document signatures are streamed; a text signature would
        // need canonicalisation of the data as it passes, which is a different
        // job and not one to guess at.
        guard onePassBody[1] == 0x00 else { return nil }
        let hashAlgo = onePassBody[2]
        let pubAlgo = onePassBody[3]
        guard pubAlgo == 22 || pubAlgo == 1 || pubAlgo == 3 else { return nil }
        switch hashAlgo {
        case 8:  self.hasher = SHA256()
        case 10: self.hasher = SHA512()
        default: return nil   // unsupported hash — treat as unverifiable, not a crash
        }
        self.hashAlgorithm = hashAlgo
        self.pubkeyAlgorithm = pubAlgo
        self.signerKeyID = Array(onePassBody[4..<12])
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
