// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// PairCrypto.swift
// The key exchange and derivations of the pairing protocol (docs/PAIRING_PROTOCOL.md, sections
// 3 and 5), on CryptoKit. HKDF is written out as two HMAC steps, exactly as the spec and the
// Kotlin core do it, so no API detail can change a byte.

import CryptoKit
import Foundation

/// Why a pairing ended. The first five are the ABORT reasons of section 3.
public enum PairFailure: Sendable, Equatable {
    case busy, version, handshake, refused, timeout, protocolError, closed

    /// The ABORT reason byte; 0 for failures that have none.
    public var abortReason: UInt8 {
        switch self {
        case .busy: return 1
        case .version: return 2
        case .handshake: return 3
        case .refused: return 4
        case .timeout: return 5
        case .protocolError, .closed: return 0
        }
    }

    public static func of(reason: UInt8) -> PairFailure {
        switch reason {
        case 1: return .busy
        case 2: return .version
        case 3: return .handshake
        case 4: return .refused
        case 5: return .timeout
        default: return .protocolError
        }
    }
}

public struct PairError: Error, Sendable, CustomStringConvertible {
    public let failure: PairFailure
    public let message: String

    public init(_ failure: PairFailure, _ message: String) {
        self.failure = failure
        self.message = message
    }

    public var description: String { "\(failure): \(message)" }
}

public enum PairRole: Sendable {
    case host, joiner
}

/// Where the protocol's random bytes come from. Always `.secure` in the app; the tests replay
/// the fixed randomness of the published session transcript.
public struct PairRandom: Sendable {
    public let bytes: @Sendable (Int) -> Data

    public init(_ bytes: @escaping @Sendable (Int) -> Data) {
        self.bytes = bytes
    }

    public static let secure = PairRandom { PairCrypto.randomBytes($0) }
}

extension Data {
    /// A copy of `count` bytes from `offset` (counted from this value's own start), indexed from 0.
    func slice(_ offset: Int, _ count: Int) -> Data {
        let start = startIndex + offset
        return Data(self[start ..< start + count])
    }
}

public enum PairCrypto {

    static let labelCommit = Data("pgpony/pair/commit/v1".utf8)
    static let labelTranscript = Data("pgpony/pair/transcript/v1".utf8)
    static let labelKey = Data("pgpony/pair/key/v1".utf8)
    static let labelHostToJoiner = Data("pgpony/pair/host-to-joiner/v1".utf8)
    static let labelJoinerToHost = Data("pgpony/pair/joiner-to-host/v1".utf8)
    static let labelCode = Data("pgpony/pair/code/v1".utf8)
    static let labelMessage = Data("pgpony/pair/msg/v1".utf8)

    /// `n` bytes from the system's secure generator.
    public static func randomBytes(_ n: Int) -> Data {
        SymmetricKey(size: SymmetricKeySize(bitCount: n * 8)).withUnsafeBytes { Data($0) }
    }

    /// An X25519 key pair: the 32-byte secret and its public key.
    public struct KeyPair: Sendable {
        public let secret: Data
        public let publicKey: Data
    }

    public static func keyPair(secret: Data? = nil) throws -> KeyPair {
        let sk = secret ?? randomBytes(32)
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: sk)
        return KeyPair(secret: Data(sk), publicKey: key.publicKey.rawRepresentation)
    }

    /// X25519(secret, peer); nil when it fails or the result is all zero (a low-order peer key).
    public static func agree(secret: Data, peer: Data) -> Data? {
        guard let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secret),
              let peerKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer),
              let shared = try? key.sharedSecretFromKeyAgreement(with: peerKey)
        else { return nil }
        let z = shared.withUnsafeBytes { Data($0) }
        return z.allSatisfy({ $0 == 0 }) ? nil : z
    }

    public static func hmac(_ key: Data, _ parts: Data...) -> Data {
        var mac = HMAC<SHA256>(key: SymmetricKey(data: key))
        for p in parts { mac.update(data: p) }
        return Data(mac.finalize())
    }

    public static func sha256(_ parts: Data...) -> Data {
        var h = SHA256()
        for p in parts { h.update(data: p) }
        return Data(h.finalize())
    }

    public static func commit(nonceHost: Data, pkHost: Data, pkJoiner: Data) -> Data {
        hmac(nonceHost, labelCommit, pkHost, pkJoiner)
    }

    /// T binds the phase 1 magic and the protocol version the joiner sent and the host accepted,
    /// so two sides that ran different versions (or were steered into one) never share a code.
    public static func transcript(pkJ: Data, pkH: Data, nJ: Data, nH: Data, version: UInt8 = PairProtocol.version) -> Data {
        sha256(labelTranscript, PairProtocol.magic, Data([version]), pkJ, pkH, nJ, nH)
    }

    /// The three session keys (RFC 5869 HKDF-SHA256, one 32-byte block each).
    public struct Keys: Sendable {
        public let pairKey: Data
        public let hostToJoiner: Data
        public let joinerToHost: Data
    }

    public static func derive(z: Data, transcript: Data) -> Keys {
        let prk = hmac(transcript, z)
        func expand(_ info: Data) -> Data { hmac(prk, info, Data([1])) }
        return Keys(pairKey: expand(labelKey), hostToJoiner: expand(labelHostToJoiner), joinerToHost: expand(labelJoinerToHost))
    }

    /// The six-digit comparison code, as shown: "042 917".
    public static func code(transcript: Data) -> String {
        let h = sha256(labelCode, transcript)
        let v = h.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        var digits = String(v % 1_000_000)
        while digits.count < 6 { digits = "0" + digits }
        return String(digits.prefix(3)) + " " + String(digits.suffix(3))
    }

    public static func seqBytes(_ seq: UInt64) -> Data {
        withUnsafeBytes(of: seq.bigEndian) { Data($0) }
    }

    /// `seq || AES-256-GCM(...)` (section 5).
    public static func seal(key: Data, seq: UInt64, plaintext: Data) throws -> Data {
        let s = seqBytes(seq)
        let nonce = try AES.GCM.Nonce(data: Data(count: 4) + s)
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: nonce, authenticating: labelMessage + s)
        return s + box.ciphertext + box.tag
    }

    /// The plaintext of a sealed message whose sequence number must be `expectedSeq`.
    public static func open(key: Data, expectedSeq: UInt64, sealed: Data) throws -> Data {
        guard sealed.count >= 8 + 16 else { throw PairError(.protocolError, "short message") }
        let s = sealed.slice(0, 8)
        guard s == seqBytes(expectedSeq) else { throw PairError(.protocolError, "message out of order") }
        let body = sealed.slice(8, sealed.count - 8)
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: Data(count: 4) + s),
                ciphertext: body.slice(0, body.count - 16),
                tag: body.slice(body.count - 16, 16)
            )
            return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: labelMessage + s)
        } catch {
            throw PairError(.protocolError, "message failed authentication")
        }
    }
}
