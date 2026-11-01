// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// PairProtocol.swift
// The pairing handshake and key confirmation (docs/PAIRING_PROTOCOL.md, sections 3 and 4).
//
// Usage, on each side: PairProtocol.host(...) or PairProtocol.join(...) runs phase 1 and returns
// a PairAttempt holding the comparison code. The joiner shows the code and asks whether the other
// screen shows the same; the host asks its user to type the code the joiner shows and checks it
// with matches(typedCode:) (section 4). The user's answer is confirm() (phase 2, returns the
// session) or reject(). Meanwhile the attempt already reads the other side's answer, so
// peerRefusal() reports a refusal over there without waiting for this user.

import Foundation

public enum PairProtocol {

    public static let magic = Data("PGPP".utf8)
    public static let version: UInt8 = 1

    public static let frameJoin: UInt8 = 0x41
    public static let frameAccept: UInt8 = 0x42
    public static let frameNonceJ: UInt8 = 0x43
    public static let frameNonceH: UInt8 = 0x44
    public static let frameAbort: UInt8 = 0x4F

    /// Phase 1 frame deadline, and the time the users get to compare the code (section 3). The
    /// session also ends after this long without a message (section 5). Each bounds a whole
    /// frame, not each read.
    public static let frameTimeout: Double = 30
    public static let confirmTimeout: Double = 300

    /// The longest phase 2 frame: HELLO, HELLO_ACK and NO_MATCH are 48 bytes.
    static let phase2MaxFrame = 48

    /// Runs phase 1 as the host over a connection that just arrived. `keyPair` is the key fixed
    /// when the window opened (the invite carries its hash).
    public static func host(transport: PairTransport, keyPair: PairCrypto.KeyPair) async throws -> PairAttempt {
        try await host(transport: transport, keyPair: keyPair, random: .secure)
    }

    /// Runs phase 1 as the joiner. `expectedHostKeyHash` is the invite's `h` when there is one.
    public static func join(transport: PairTransport, expectedHostKeyHash: Data? = nil) async throws -> PairAttempt {
        try await join(transport: transport, expectedHostKeyHash: expectedHostKeyHash, random: .secure)
    }

    /// `host` with its randomness supplied: the published session transcript only.
    static func host(transport: PairTransport, keyPair: PairCrypto.KeyPair, random: PairRandom) async throws -> PairAttempt {
        let wire = PairWire(transport)
        do {
            guard try await wire.readExact(4, timeout: frameTimeout) == magic else {
                throw PairError(.protocolError, "not a PGPony pairing connection")
            }
            try await wire.writeRaw(magic)
            let joinFrame = try await expect(wire, frameJoin, 33)
            if joinFrame[joinFrame.startIndex] != version {
                await abort(wire, .version)
                throw PairError(.version, "the other side speaks pairing version \(joinFrame[joinFrame.startIndex])")
            }
            let pkJ = joinFrame.slice(1, 32)
            let nH = random.bytes(32)
            try await wire.writeFrame(frameAccept, keyPair.publicKey + PairCrypto.commit(nonceHost: nH, pkHost: keyPair.publicKey, pkJoiner: pkJ))
            let nJ = try await expect(wire, frameNonceJ, 32)
            try await wire.writeFrame(frameNonceH, nH)
            return try await finish(.host, wire, keyPair, pkJ: pkJ, pkH: keyPair.publicKey, nJ: nJ, nH: nH, random: random)
        } catch {
            wire.close()
            throw wrap(error)
        }
    }

    /// `join` with its randomness supplied: the published session transcript only.
    static func join(transport: PairTransport, expectedHostKeyHash: Data?, random: PairRandom) async throws -> PairAttempt {
        // An empty hash would match any host key and a longer one none: only the invite's 16 bytes.
        if let h = expectedHostKeyHash, h.count != PairInvite.hashBytes {
            transport.close()
            throw PairError(.protocolError, "the expected host key hash is \(PairInvite.hashBytes) bytes")
        }
        let wire = PairWire(transport)
        do {
            let keyPair = try PairCrypto.keyPair(secret: random.bytes(32))
            try await wire.writeRaw(magic)
            guard try await wire.readExact(4, timeout: frameTimeout) == magic else {
                throw PairError(.protocolError, "not a PGPony pairing host")
            }
            try await wire.writeFrame(frameJoin, Data([version]) + keyPair.publicKey)
            let acceptFrame = try await expect(wire, frameAccept, 64)
            let pkH = acceptFrame.slice(0, 32)
            let commit = acceptFrame.slice(32, 32)
            if let expected = expectedHostKeyHash,
               !PairFrames.constantTimeEquals(PairCrypto.sha256(pkH).prefix(expected.count), expected) {
                await abort(wire, .handshake)
                throw PairError(.handshake, "the host key does not match the invite")
            }
            let nJ = random.bytes(32)
            try await wire.writeFrame(frameNonceJ, nJ)
            let nH = try await expect(wire, frameNonceH, 32)
            guard PairFrames.constantTimeEquals(PairCrypto.commit(nonceHost: nH, pkHost: pkH, pkJoiner: keyPair.publicKey), commit) else {
                await abort(wire, .handshake)
                throw PairError(.handshake, "the host changed its nonce")
            }
            return try await finish(.joiner, wire, keyPair, pkJ: keyPair.publicKey, pkH: pkH, nJ: nJ, nH: nH, random: random)
        } catch {
            wire.close()
            throw wrap(error)
        }
    }

    private static func finish(
        _ role: PairRole, _ wire: PairWire, _ own: PairCrypto.KeyPair,
        pkJ: Data, pkH: Data, nJ: Data, nH: Data, random: PairRandom
    ) async throws -> PairAttempt {
        let peer = role == .host ? pkJ : pkH
        guard let z = PairCrypto.agree(secret: own.secret, peer: peer) else {
            await abort(wire, .handshake)
            throw PairError(.handshake, "the other side sent an invalid key")
        }
        let t = PairCrypto.transcript(pkJ: pkJ, pkH: pkH, nJ: nJ, nH: nH, version: version)
        return PairAttempt(role: role, wire: wire, keys: PairCrypto.derive(z: z, transcript: t), code: PairCrypto.code(transcript: t), random: random)
    }

    private static func expect(_ wire: PairWire, _ type: UInt8, _ size: Int) async throws -> Data {
        let (t, payload) = try await wire.readFrame(timeout: frameTimeout, maxLength: max(size, 1))
        if t == frameAbort && payload.count == 1 {
            let f = PairFailure.of(reason: payload[payload.startIndex])
            throw PairError(f, "the other side ended the pairing (\(f))")
        }
        guard t == type && payload.count == size else { throw PairError(.protocolError, "unexpected pairing message") }
        return payload
    }

    static func abort(_ wire: PairWire, _ failure: PairFailure) async {
        try? await wire.writeFrame(frameAbort, Data([failure.abortReason]))
    }

    static func wrap(_ error: Error) -> PairError {
        if let e = error as? PairError { return e }
        if error is CancellationError { return PairError(.closed, "cancelled") }
        return PairError(.closed, String(describing: error))
    }
}

/// Holds the other side's phase 2 answer once it has been read.
private final class AnswerBox: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<(UInt8, Data), PairError>?

    func set(_ r: Result<(UInt8, Data), PairError>) {
        lock.lock(); defer { lock.unlock() }
        result = r
    }

    func get() -> Result<(UInt8, Data), PairError>? {
        lock.lock(); defer { lock.unlock() }
        return result
    }
}

/// Phase 1 is done and both screens can show `code`. Exactly one of `confirm()` or `reject()`
/// must follow. Swift cannot wipe `Data`, so the keys are dropped as soon as they are used.
public final class PairAttempt: @unchecked Sendable {
    public let role: PairRole
    public let code: String

    private let wire: PairWire
    private let random: PairRandom
    private let lock = NSLock()
    private var keys: PairCrypto.Keys?
    private let answer: AnswerBox
    private let peerAnswer: Task<(UInt8, Data), Error>

    init(role: PairRole, wire: PairWire, keys: PairCrypto.Keys, code: String, random: PairRandom) {
        self.role = role
        self.code = code
        self.wire = wire
        self.random = random
        self.keys = keys
        let box = AnswerBox()
        self.answer = box
        // The other side's answer: its phase 2 frame, read as soon as it arrives.
        // One deadline for the whole answer, however slowly its bytes arrive.
        peerAnswer = Task {
            do {
                let frame = try await PairWire.deadline(PairProtocol.confirmTimeout, wire.transport) { @Sendable () async throws -> (UInt8, Data) in
                    let first = try await wire.readRaw(1)
                    if first[first.startIndex] == UInt8(ascii: "P") {
                        guard try await wire.readRaw(3) == Data("DR1".utf8) else {
                            throw PairError(.protocolError, "unexpected data")
                        }
                        let type = try await wire.readRaw(1)
                        return try await wire.readFrameRaw(afterType: type[type.startIndex], maxLength: PairProtocol.phase2MaxFrame)
                    }
                    return try await wire.readFrameRaw(afterType: first[first.startIndex], maxLength: PairProtocol.phase2MaxFrame)
                }
                box.set(.success(frame))
                return frame
            } catch {
                let e = PairProtocol.wrap(error)
                box.set(.failure(e))
                throw e
            }
        }
    }

    /// Returns how the pairing ended when the other side refuses or goes away before this user
    /// answers, or nil once the other side has confirmed. Await it beside the code screen.
    public func peerRefusal() async -> PairFailure? {
        do {
            let frame = try await peerAnswer.value
            return frame.0 == PairProtocol.frameAbort ? PairFailure.of(reason: frame.1.first ?? 0) : nil
        } catch {
            return PairProtocol.wrap(error).failure
        }
    }

    private func takeKeys() -> PairCrypto.Keys? {
        lock.lock(); defer { lock.unlock() }
        let k = keys
        keys = nil
        return k
    }

    private func refusedBy(_ frame: (UInt8, Data)) -> PairError? {
        guard frame.0 == PairProtocol.frameAbort else { return nil }
        let f = PairFailure.of(reason: frame.1.first ?? 0)
        return PairError(f, f == .refused ? "the other side said the codes do not match" : "the other side ended the pairing")
    }

    private func refusalSoFar() -> PairError? {
        guard case .success(let frame)? = answer.get() else { return nil }
        return refusedBy(frame)
    }

    /// Whether `typed`, the code this user typed from the other screen, is this attempt's code.
    /// Spaces and hyphens between the digits are ignored; anything else makes it a mismatch.
    /// Compared in constant time. The host asks for the code this way instead of a "same code"
    /// button, so its user cannot confirm without reading the other screen (section 4).
    public func matches(typedCode typed: String) -> Bool {
        var digits: [UInt8] = []
        for u in typed.trimmingCharacters(in: .whitespacesAndNewlines).unicodeScalars {
            if ("0" ... "9").contains(u) {
                digits.append(UInt8(u.value))
            } else if u != " " && u != "-" {
                return false
            }
        }
        guard digits.count == 6 else { return false }
        let own = code.unicodeScalars.filter { ("0" ... "9").contains($0) }.map { UInt8($0.value) }
        return PairFrames.constantTimeEquals(Data(digits), Data(own))
    }

    /// This user says the codes match: phase 2. Returns the session or throws.
    public func confirm() async throws -> PairSession {
        guard let keys = takeKeys() else { throw PairError(.closed, "this attempt was already answered") }
        do {
            if role == .joiner {
                // A refusal may already be here; it explains a failed write better than the write.
                if let r = refusalSoFar() { throw r }
                let dialerNonce = random.bytes(16)
                do {
                    try await wire.writeRaw(PairFrames.pdr1)
                    try await wire.writeFrame(PairFrames.hello, dialerNonce + PairFrames.identifyTag(pairKey: keys.pairKey, dialerNonce: dialerNonce))
                } catch {
                    for _ in 0 ..< 20 {
                        if let r = refusalSoFar() { throw r }
                        try? await Task.sleep(nanoseconds: 100_000_000)
                    }
                    throw error
                }
                let frame = try await peerAnswer.value
                if let r = refusedBy(frame) { throw r }
                guard frame.0 == PairFrames.helloAck, frame.1.count == 48 else {
                    throw PairError(.handshake, "the codes did not match")
                }
                let listenerNonce = frame.1.slice(0, 16)
                let expected = PairFrames.identifyAckTag(pairKey: keys.pairKey, dialerNonce: dialerNonce, listenerNonce: listenerNonce)
                guard PairFrames.constantTimeEquals(expected, frame.1.slice(16, 32)) else {
                    throw PairError(.handshake, "the codes did not match")
                }
            } else {
                let frame = try await peerAnswer.value
                if let r = refusedBy(frame) { throw r }
                let ok = frame.0 == PairFrames.hello && frame.1.count == 48 &&
                    PairFrames.constantTimeEquals(
                        PairFrames.identifyTag(pairKey: keys.pairKey, dialerNonce: frame.1.slice(0, 16)),
                        frame.1.slice(16, 32)
                    )
                try await wire.writeRaw(PairFrames.pdr1)
                if !ok {
                    try await wire.writeFrame(PairFrames.noMatch, random.bytes(48))
                    throw PairError(.handshake, "the codes did not match")
                }
                let listenerNonce = random.bytes(16)
                try await wire.writeFrame(
                    PairFrames.helloAck,
                    listenerNonce + PairFrames.identifyAckTag(pairKey: keys.pairKey, dialerNonce: frame.1.slice(0, 16), listenerNonce: listenerNonce)
                )
            }
            let send = role == .host ? keys.hostToJoiner : keys.joinerToHost
            let receive = role == .host ? keys.joinerToHost : keys.hostToJoiner
            return PairSession(role: role, wire: wire, sendKey: send, receiveKey: receive)
        } catch {
            wire.close()
            throw PairProtocol.wrap(error)
        }
    }

    /// This user says the codes differ, or cancels.
    public func reject() async {
        _ = takeKeys()
        await PairProtocol.abort(wire, .refused)
        wire.close()
    }
}
