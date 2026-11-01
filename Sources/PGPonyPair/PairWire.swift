// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// PairWire.swift
// Framing, the PonyDirect pieces phase 2 and 3 reuse, and the byte stream both phases run over
// (docs/PAIRING_PROTOCOL.md, sections 2 and 4).

import Foundation

/// The PonyDirect LAN identify handshake and ENVELOPE frame, byte for byte. Kept here so the
/// pairing code needs nothing but CryptoKit; the test vectors pin every byte.
public enum PairFrames {
    /// Prefixes phase 2 in each direction.
    public static let pdr1 = Data("PDR1".utf8)

    public static let hello: UInt8 = 0x01
    public static let helloAck: UInt8 = 0x02
    public static let noMatch: UInt8 = 0x03
    public static let envelope: UInt8 = 0x04

    static let labelIdentify = Data("ponydirect/id/v1".utf8)
    static let labelIdentifyAck = Data("ponydirect/id-ack/v1".utf8)

    /// `type(1) | length(4, big-endian) | payload`.
    public static func frame(_ type: UInt8, _ payload: Data) -> Data {
        var out = Data([type])
        out.append(withUnsafeBytes(of: UInt32(payload.count).bigEndian) { Data($0) })
        out.append(payload)
        return out
    }

    /// HELLO tag: HMAC-SHA256(K, "ponydirect/id/v1" || dialer nonce).
    public static func identifyTag(pairKey: Data, dialerNonce: Data) -> Data {
        PairCrypto.hmac(pairKey, labelIdentify, dialerNonce)
    }

    /// HELLO_ACK tag: HMAC-SHA256(K, "ponydirect/id-ack/v1" || dialer nonce || listener nonce).
    public static func identifyAckTag(pairKey: Data, dialerNonce: Data, listenerNonce: Data) -> Data {
        PairCrypto.hmac(pairKey, labelIdentifyAck, dialerNonce, listenerNonce)
    }

    public static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for (x, y) in zip(a, b) { diff |= x ^ y }
        return diff == 0
    }
}

/// A connected byte stream: a TCP connection in the app (NWPairTransport), a pipe in the tests.
/// `read(exactly:)` returns exactly that many bytes or throws; `close()` must end a pending read.
public protocol PairTransport: AnyObject, Sendable {
    func write(_ data: Data) async throws
    func read(exactly count: Int) async throws -> Data
    func close()
}

/// The framed stream both phases run over. Every frame read has one deadline for the whole
/// frame (not one per read, which a peer sending a byte at a time could stretch for ever); when
/// it passes, the transport is closed so the read ends, and the read throws a timeout.
final class PairWire: @unchecked Sendable {
    static let maxFrame = 1_048_576 + 65_536

    let transport: PairTransport

    init(_ transport: PairTransport) {
        self.transport = transport
    }

    func writeRaw(_ bytes: Data) async throws {
        try await transport.write(bytes)
    }

    func writeFrame(_ type: UInt8, _ payload: Data) async throws {
        try await writeRaw(PairFrames.frame(type, payload))
    }

    func readExact(_ count: Int, timeout: Double) async throws -> Data {
        if count == 0 { return Data() }
        return try await PairWire.deadline(timeout, transport) { [self] in try await self.readRaw(count) }
    }

    /// One frame whose type byte was already read; `timeout` bounds the rest of the frame.
    func readFrame(afterType type: UInt8, timeout: Double, maxLength: Int = PairWire.maxFrame) async throws -> (UInt8, Data) {
        try await PairWire.deadline(timeout, transport) { [self] in
            try await self.readFrameRaw(afterType: type, maxLength: maxLength)
        }
    }

    /// One whole frame within `timeout`.
    func readFrame(timeout: Double, maxLength: Int = PairWire.maxFrame) async throws -> (UInt8, Data) {
        try await PairWire.deadline(timeout, transport) { @Sendable [self] () async throws -> (UInt8, Data) in
            let type = try await self.readRaw(1)
            return try await self.readFrameRaw(afterType: type[type.startIndex], maxLength: maxLength)
        }
    }

    /// Reads with no deadline of its own: only inside `deadline`.
    func readRaw(_ count: Int) async throws -> Data {
        if count == 0 { return Data() }
        return try await transport.read(exactly: count)
    }

    /// The rest of a frame with no deadline of its own: only inside `deadline`. A declared length
    /// above `maxLength` is refused before anything is read for it.
    func readFrameRaw(afterType type: UInt8, maxLength: Int) async throws -> (UInt8, Data) {
        let header = try await readRaw(4)
        let length = header.reduce(0) { ($0 << 8) | Int($1) }
        guard length <= min(maxLength, PairWire.maxFrame) else { throw PairError(.protocolError, "frame too long") }
        return (type, try await readRaw(length))
    }

    func close() {
        transport.close()
    }

    /// Runs `operation` (a read) with a deadline. When the deadline passes, or the calling task
    /// is cancelled, the transport is closed so the read ends; a passed deadline always reports
    /// as a timeout, whichever child finishes first.
    static func deadline<T: Sendable>(
        _ seconds: Double, _ transport: PairTransport, _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        let fired = PairFlag()
        do {
            return try await withThrowingTaskGroup(of: T.self) { group in
                group.addTask {
                    try await withTaskCancellationHandler {
                        try await operation()
                    } onCancel: {
                        transport.close()
                    }
                }
                group.addTask {
                    try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                    fired.set()
                    transport.close()
                    throw PairError(.timeout, "the other side stopped answering")
                }
                defer { group.cancelAll() }
                guard let first = try await group.next() else { throw PairError(.closed, "connection lost") }
                return first
            }
        } catch {
            if fired.get() { throw PairError(.timeout, "the other side stopped answering") }
            throw error
        }
    }
}

/// A thread-safe one-way switch.
final class PairFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    func set() {
        lock.lock(); value = true; lock.unlock()
    }

    func get() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}
