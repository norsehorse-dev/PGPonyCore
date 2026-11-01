// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// Support.swift
// Test plumbing: an in-memory connection that records what each side writes, fixed randomness,
// and the vector files (copied unchanged from PGPonyAndroid app/src/test/resources/pairing/).

import Foundation
import XCTest
@testable import PGPonyPair

/// One direction of an in-memory connection. Bytes written before a close can still be read.
final class MemoryPipe: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer = Data()
    private var closed = false
    private var waiting: [(count: Int, continuation: CheckedContinuation<Data, Error>)] = []

    func write(_ data: Data) throws {
        lock.lock()
        if closed {
            lock.unlock()
            throw PairError(.closed, "the connection is closed")
        }
        buffer.append(data)
        let ready = serveLocked()
        lock.unlock()
        ready.forEach { $0() }
    }

    func read(_ count: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { c in
            lock.lock()
            waiting.append((count, c))
            let ready = serveLocked()
            lock.unlock()
            ready.forEach { $0() }
        }
    }

    func close() {
        lock.lock()
        closed = true
        let ready = serveLocked()
        lock.unlock()
        ready.forEach { $0() }
    }

    private func serveLocked() -> [() -> Void] {
        var out: [() -> Void] = []
        while let first = waiting.first {
            if buffer.count >= first.count {
                waiting.removeFirst()
                let data = Data(buffer.prefix(first.count))
                buffer = Data(buffer.dropFirst(first.count))
                out.append { first.continuation.resume(returning: data) }
            } else if closed {
                waiting.removeFirst()
                out.append { first.continuation.resume(throwing: PairError(.closed, "the other side closed the connection")) }
            } else {
                break
            }
        }
        return out
    }
}

final class MemoryTransport: PairTransport, @unchecked Sendable {
    private let incoming: MemoryPipe
    private let outgoing: MemoryPipe
    private let lock = NSLock()
    private var record = Data()

    init(incoming: MemoryPipe, outgoing: MemoryPipe) {
        self.incoming = incoming
        self.outgoing = outgoing
    }

    /// Every byte this side wrote, in order.
    var written: Data {
        lock.lock(); defer { lock.unlock() }
        return record
    }

    func write(_ data: Data) async throws {
        try outgoing.write(data)
        lock.withLock { record.append(data) }
    }

    func read(exactly count: Int) async throws -> Data {
        try await incoming.read(count)
    }

    func close() {
        incoming.close()
        outgoing.close()
    }

    /// A connected pair: (host side, joiner side).
    static func pair() -> (MemoryTransport, MemoryTransport) {
        let toJoiner = MemoryPipe()
        let toHost = MemoryPipe()
        return (MemoryTransport(incoming: toHost, outgoing: toJoiner), MemoryTransport(incoming: toJoiner, outgoing: toHost))
    }
}

/// Hands out the listed values in order; the protocol asking for anything else fails the test.
final class FixedRandom: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Data]

    init(_ values: [Data]) {
        self.values = values
    }

    var random: PairRandom {
        PairRandom { [self] n in self.next(n) }
    }

    private func next(_ n: Int) -> Data {
        lock.lock(); defer { lock.unlock() }
        precondition(!values.isEmpty, "no fixed random bytes left")
        let v = values.removeFirst()
        precondition(v.count == n, "asked for \(n) random bytes, the fixed value has \(v.count)")
        return v
    }
}

func hex(_ d: Data) -> String {
    d.map { String(format: "%02x", $0) }.joined()
}

func unhex(_ s: String) -> Data {
    var out = Data()
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        out.append(UInt8(s[i ..< j], radix: 16)!)
        i = j
    }
    return out
}

func vector(_ name: String) throws -> [String: Any] {
    let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Vectors"), "missing Vectors/\(name).json")
    return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
}

extension Dictionary where Key == String, Value == Any {
    func str(_ key: String) -> String { self[key] as! String }
    func bytes(_ key: String) -> Data { unhex(str(key)) }
}
