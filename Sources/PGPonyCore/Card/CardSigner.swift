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
        var errorDescription: String? {
            switch self {
            case .badSignatureLength(let n):
                return "The card returned a \(n)-byte signature; expected 64."
            case .emptyCardSignature:
                return "The card returned an empty signature."
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

    /// Shared core: build a v4 SHA-256 signature packet over `message` with the
    /// given sig type, having the card produce the signature value via PSO:CDS.
    /// EdDSA (algo 22) produces a 64-byte R||S (two MPIs); RSA (algo 1) produces
    /// one modulus-length value (a single MPI) over a PKCS#1 v1.5 DigestInfo.
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

        // v4 trailer: version, sig type, pubkey algo, SHA-256 (8).
        var trailer: [UInt8] = [4, sigType, pubAlgo, 8]
        trailer += u16be(UInt16(hashed.count)) + hashed

        // Hash the document bytes directly, then the trailer. For sig type 0x01
        // (canonical text) the caller has already canonicalized line endings.
        var hashInput = Data(message)
        hashInput.append(contentsOf: trailer)
        hashInput.append(contentsOf: [4, 0xFF] + u32be(UInt32(trailer.count)))
        let digest = Array(SHA256.hash(data: hashInput))

        // Produce the algorithm-specific signature MPI list on the card. EdDSA
        // signs the bare digest and returns 64 bytes (R || S, two MPIs); RSA
        // signs a PKCS#1 v1.5 DigestInfo and returns one modulus-length value
        // (a single MPI).
        let mpis: [[UInt8]]
        switch algorithm {
        case .eddsa:
            let sig = try await service.sign(digest: digest)
            guard sig.count == 64 else { throw SignError.badSignatureLength(sig.count) }
            mpis = [Array(sig[0..<32]), Array(sig[32..<64])]
        case .rsa:
            var sig = try await service.signRSA(digestInfo: sha256DigestInfo(digest))
            guard !sig.isEmpty else { throw SignError.emptyCardSignature }
            // Canonical OpenPGP MPI: the byte count must match the bit length, so
            // strip any leading zero bytes the card padded the value with. Without
            // this, a signature with a zero top byte (~1/256) encodes a bit length
            // shorter than the bytes written and parses misaligned.
            while sig.first == 0x00 && sig.count > 1 { sig.removeFirst() }
            mpis = [sig]
        }

        let body = assembleSignatureBody(
            pubkeyAlgo: pubAlgo, sigType: sigType,
            hashed: hashed, unhashed: unhashed,
            hashPrefix2: [digest[0], digest[1]], signatureMPIs: mpis
        )
        return (buildNewFormatPacket(tag: 2, body: body), keyID)
    }

    /// Pure, hardware-free assembly of a v4 signature packet body (hash algo is
    /// SHA-256 = 8). `signatureMPIs` is the algorithm's signature value split into
    /// MPIs: [R, S] for EdDSA, [sig] for RSA. Exposed internally so the framing
    /// can be unit-tested without a card.
    static func assembleSignatureBody(
        pubkeyAlgo: UInt8,
        sigType: UInt8,
        hashed: [UInt8],
        unhashed: [UInt8],
        hashPrefix2: [UInt8],
        signatureMPIs: [[UInt8]]
    ) -> [UInt8] {
        var body: [UInt8] = [4, sigType, pubkeyAlgo, 8]
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
        return [UInt8((bitLen >> 8) & 0xFF), UInt8(bitLen & 0xFF)] + bytes
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
