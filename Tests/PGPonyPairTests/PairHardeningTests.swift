// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// PairHardeningTests.swift
// The pairing protocol's guard rails (docs/PAIRING_PROTOCOL.md): strict invite addresses, the
// host key hash length, the typed code on the host, whole-frame deadlines, the offer rules of
// section 5, items that go out unbroken, and ending a session whose peer stopped reading.
// Mirrors the Kotlin PairHardeningTest.

import Foundation
import XCTest
@testable import PGPonyPair

final class PairHardeningTests: XCTestCase {

    private func attempts() async throws -> (PairAttempt, PairAttempt) {
        let (h, j) = MemoryTransport.pair()
        let key = try PairCrypto.keyPair()
        let host = Task { try await PairProtocol.host(transport: h, keyPair: key) }
        let joiner = try await PairProtocol.join(transport: j)
        return (try await host.value, joiner)
    }

    private func sessions() async throws -> (PairSession, PairSession) {
        let (h, j) = try await attempts()
        async let hs = h.confirm()
        let js = try await j.confirm()
        return (try await hs, js)
    }

    private func expectProtocolError(_ what: String, _ body: () async throws -> Void) async {
        do {
            try await body()
            XCTFail(what + ": no error")
        } catch let e as PairError {
            XCTAssertEqual(e.failure, .protocolError, what)
        } catch {
            XCTFail(what + ": \(error)")
        }
    }

    // MARK: PAIRING-PROTOCOL-2 / PAIRING-IMPL-4: invite addresses

    func testIPv6LiteralsAreParsedStrictly() {
        let good = [
            "::1": "00000000000000000000000000000001",
            "1:2:3:4:5:6:7:8": "00010002000300040005000600070008",
            "1:2:3:4:5:6:7::": "00010002000300040005000600070000",
            "::ffff:1.2.3.4": "00000000000000000000ffff01020304",
            "FD00::ABCD": "fd00000000000000000000000000abcd",
            "::": "00000000000000000000000000000000",
        ]
        for (text, bytes) in good {
            XCTAssertEqual(PairInvite.hostBytes(text).map(hex), bytes, text)
        }
        let bad = [
            ":::1", "1:2", ".:1", "..:", "1::2::3", "1.2.3.4:5", ":1", "1:", "12345::1", "::1.2.3.04",
            "1.2.3.4::", "fe80::1%en0", "fe80::1%25en0", "g::1", "1:2:3:4:5:6:7:8:9", "1::2:3:4:5:6:7:8",
            "::1.2.3", " ::1", "::1 ", "[::1]", "localhost", "pgpony.local", "\u{0661}::1",
        ]
        for text in bad {
            XCTAssertNil(PairInvite.hostBytes(text), text)
        }
    }

    func testAMalformedIPv6InviteIsRefused() {
        let h = String(repeating: "A", count: 22)
        for inner in [":::1", "1:2", ".:1", "..:", "1::2::3", "1.2.3.4:5", "....::"] {
            XCTAssertNil(PairInvite.parse("pgpony-pair:1?a=[\(inner)]:5&h=\(h)"), inner)
            XCTAssertNil(PairInvite.parseAddress("[\(inner)]:5"), inner)
        }
    }

    func testNoPastedTextBreaksTheParser() {
        let alphabet = Array("pgony-air:1?a=h&,[]:.0123456789abcdefABCDEF%_- \n\u{0131}\u{0130}\u{00e9}")
        var state: UInt64 = 20_261_001
        func next(_ n: Int) -> Int {
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            return Int((state >> 33) % UInt64(n))
        }
        for _ in 0 ..< 20_000 {
            var text = next(2) == 0 ? "pgpony-pair:1?" : ""
            for _ in 0 ..< next(80) { text.append(alphabet[next(alphabet.count)]) }
            if let invite = PairInvite.parse(text) {
                for a in invite.addresses { XCTAssertTrue(a.bytes.count == 4 || a.bytes.count == 16, text) }
            }
            _ = PairInvite.parseAddress(text)
        }
    }

    // MARK: PAIRING-PROTOCOL-7: the expected host key hash

    func testAnExpectedHostKeyHashMustBeSixteenBytes() async {
        for size in [0, 8, 15, 17, 32] {
            let (_, j) = MemoryTransport.pair()
            await expectProtocolError("hash of \(size) bytes") {
                _ = try await PairProtocol.join(transport: j, expectedHostKeyHash: Data(count: size))
            }
            XCTAssertEqual(j.written, Data(), "nothing was sent")
        }
    }

    // MARK: PAIRING-PROTOCOL-1: the host types the code

    func testTheHostChecksTheCodeItsUserTyped() async throws {
        let (host, joiner) = try await attempts()
        let digits = joiner.code.replacingOccurrences(of: " ", with: "")
        XCTAssertTrue(host.matches(typedCode: joiner.code))
        XCTAssertTrue(host.matches(typedCode: digits))
        XCTAssertTrue(host.matches(typedCode: " \(digits.prefix(3))-\(digits.suffix(3)) "))
        let wrong = String(format: "%06ld", (Int(digits)! + 1) % 1_000_000)
        XCTAssertFalse(host.matches(typedCode: wrong))
        XCTAssertFalse(host.matches(typedCode: String(digits.prefix(5))))
        XCTAssertFalse(host.matches(typedCode: digits + "0"))
        XCTAssertFalse(host.matches(typedCode: ""))
        XCTAssertFalse(host.matches(typedCode: "\u{0661}" + digits.dropFirst()))
        XCTAssertFalse(host.matches(typedCode: digits + ".x"))
        await host.reject()
        let refusal = await joiner.peerRefusal()
        XCTAssertEqual(refusal, .refused)
    }

    // MARK: PAIRING-PROTOCOL-5: whole-frame deadlines

    func testAFrameThatDripsInEndsAtItsDeadline() async throws {
        // Each byte comes in time, but the frame never completes: the deadline closes it.
        let drip = DripTransport([0x41, 0, 0, 0, 33])
        let wire = PairWire(drip)
        let started = Date()
        do {
            _ = try await wire.readFrame(timeout: 0.4, maxLength: 33)
            XCTFail("the frame completed")
        } catch let e as PairError {
            XCTAssertEqual(e.failure, .timeout)
        }
        XCTAssertTrue(drip.isClosed)
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
    }

    func testADeclaredLengthIsCheckedBeforeAnythingIsRead() async throws {
        let (h, j) = MemoryTransport.pair()
        let host = Task { try await PairProtocol.host(transport: h, keyPair: try PairCrypto.keyPair()) }
        // JOIN claiming 1,114,112 bytes: refused at once instead of waiting for a megabyte.
        try await j.write(PairProtocol.magic + Data([0x41, 0x00, 0x11, 0x00, 0x00]))
        await expectProtocolError("oversized JOIN") { _ = try await host.value }
    }

    // MARK: PAIRING-PROTOCOL-3: the version is in T

    func testTheTranscriptCoversTheVersion() {
        let pk = PairCrypto.randomBytes(32)
        let n = PairCrypto.randomBytes(32)
        let t = PairCrypto.transcript(pkJ: pk, pkH: pk, nJ: n, nH: n)
        XCTAssertEqual(t, PairCrypto.transcript(pkJ: pk, pkH: pk, nJ: n, nH: n, version: 1))
        XCTAssertNotEqual(t, PairCrypto.transcript(pkJ: pk, pkH: pk, nJ: n, nH: n, version: 2))
        XCTAssertEqual(t, PairCrypto.sha256(Data("pgpony/pair/transcript/v1".utf8), Data("PGPP".utf8), Data([1]), pk, pk, n, n))
    }

    // MARK: PAIRING-PROTOCOL-4: one offer at a time

    private let fp1 = String(repeating: "AB", count: 20)
    private let fp2 = String(repeating: "CD", count: 20)
    private let rawOffer = Data(#"{"items":[{"id":2,"kind":"public-key","name":"x","fingerprint":null,"size":1}]}"#.utf8)

    func testASecondOfferBeforeTheAnswerEndsTheSession() async throws {
        let (host, joiner) = try await sessions()
        try await host.sendOffer(PairOffer(items: [PairItem(id: 1, kind: PairItem.publicKey, name: "first", fingerprint: fp1, size: 10)]))
        guard case .offer = try await joiner.receive() else { return XCTFail("expected OFFER") }
        // A well-behaved sender cannot even send it.
        await expectProtocolError("second sendOffer") {
            try await host.sendOffer(PairOffer(items: [PairItem(id: 2, kind: PairItem.publicKey, name: "second", fingerprint: fp2, size: 10)]))
        }
        // One that skips the check is cut off by the receiver.
        try await host.send(PairSession.offer, rawOffer)
        await expectProtocolError("second offer received") { _ = try await joiner.receive() }
        await host.close()
    }

    func testAnOfferBeforeTheResultsOfTheLastEndsTheSession() async throws {
        let (host, joiner) = try await sessions()
        let bytes = Data("0123456789".utf8)
        try await host.sendOffer(PairOffer(items: [PairItem(id: 1, kind: PairItem.publicKey, name: "first", fingerprint: fp1, size: Int64(bytes.count))]))
        guard case .offer = try await joiner.receive() else { return XCTFail("expected OFFER") }
        try await joiner.sendAnswer(PairAnswer(accept: [1]))
        guard case .answer = try await host.receive() else { return XCTFail("expected ANSWER") }
        try await host.sendItem(id: 1, bytes: bytes)
        guard case .item = try await joiner.receive(expectedItems: [1: Int64(bytes.count)]) else { return XCTFail("expected the item") }
        await expectProtocolError("offer before results") {
            try await host.sendOffer(PairOffer(items: [PairItem(id: 2, kind: PairItem.publicKey, name: "next", fingerprint: fp2, size: 1)]))
        }
        try await host.send(PairSession.offer, rawOffer)
        await expectProtocolError("offer received before results") { _ = try await joiner.receive() }
        await host.close()
    }

    func testTheNextOfferFollowsTheResults() async throws {
        let (host, joiner) = try await sessions()
        let bytes = Data("0123456789".utf8)
        try await host.sendOffer(PairOffer(items: [PairItem(id: 1, kind: PairItem.publicKey, name: "first", fingerprint: fp1, size: Int64(bytes.count))]))
        guard case .offer = try await joiner.receive() else { return XCTFail("expected OFFER") }
        // An answer may only name ids the offer listed, and only once.
        await expectProtocolError("answer with an unknown id") { try await joiner.sendAnswer(PairAnswer(accept: [9])) }
        try await joiner.sendAnswer(PairAnswer(accept: [1]))
        await expectProtocolError("second answer") { try await joiner.sendAnswer(PairAnswer(accept: [1])) }
        guard case .answer = try await host.receive() else { return XCTFail("expected ANSWER") }
        try await host.sendItem(id: 1, bytes: bytes)
        guard case .item = try await joiner.receive(expectedItems: [1: Int64(bytes.count)]) else { return XCTFail("expected the item") }
        await expectProtocolError("result for an id not owed") { try await joiner.sendResult(PairResult(id: 5, ok: true)) }
        try await joiner.sendResult(PairResult(id: 1, ok: true))
        guard case .result = try await host.receive() else { return XCTFail("expected RESULT") }
        try await host.sendOffer(PairOffer(items: [PairItem(id: 2, kind: PairItem.publicKey, name: "next", fingerprint: fp2, size: 1)]))
        guard case .offer = try await joiner.receive() else { return XCTFail("expected OFFER") }
        try await joiner.sendAnswer(PairAnswer(accept: []))
        let declined = try await host.receive()
        XCTAssertEqual(declined, .answer(PairAnswer(accept: [])))
        // A declined offer leaves nothing open.
        try await host.sendOffer(PairOffer(items: [PairItem(id: 3, kind: PairItem.publicKey, name: "third", fingerprint: fp1, size: 1)]))
        guard case .offer = try await joiner.receive() else { return XCTFail("expected OFFER") }
        await host.close()
    }

    func testAnAcceptedItemComesOnceAndAnAnswerNamesEachIdOnce() async throws {
        let (host, joiner) = try await sessions()
        let bytes = Data("0123456789".utf8)
        try await host.sendOffer(PairOffer(items: [PairItem(id: 1, kind: PairItem.publicKey, name: "first", fingerprint: fp1, size: Int64(bytes.count))]))
        guard case .offer = try await joiner.receive() else { return XCTFail("expected OFFER") }
        await expectProtocolError("answer naming an id twice") { try await joiner.sendAnswer(PairAnswer(accept: [1, 1])) }
        try await joiner.sendAnswer(PairAnswer(accept: [1]))
        guard case .answer = try await host.receive() else { return XCTFail("expected ANSWER") }
        try await host.sendItem(id: 1, bytes: bytes)
        guard case .item = try await joiner.receive(expectedItems: [1: Int64(bytes.count)]) else { return XCTFail("expected the item") }
        // The same item again, even with the caller still expecting it, ends the session.
        try await host.sendItem(id: 1, bytes: bytes)
        await expectProtocolError("item sent twice") { _ = try await joiner.receive(expectedItems: [1: Int64(bytes.count)]) }
        await host.close()
    }

    func testAnAnswerOrResultThatFitsNoOfferEndsTheSession() async throws {
        for c in 0 ... 2 {
            let (host, joiner) = try await sessions()
            switch c {
            case 0:
                try await joiner.send(PairSession.answer, Data(#"{"accept":[1]}"#.utf8))
            case 1:
                try await host.sendOffer(PairOffer(items: [PairItem(id: 1, kind: PairItem.publicKey, name: "a", fingerprint: fp1, size: 1)]))
                guard case .offer = try await joiner.receive() else { return XCTFail("expected OFFER") }
                try await joiner.send(PairSession.answer, Data(#"{"accept":[1,2]}"#.utf8))
            default:
                try await joiner.send(PairSession.result, Data(#"{"id":1,"ok":true,"error":null}"#.utf8))
            }
            await expectProtocolError("case \(c)") { _ = try await host.receive() }
            await joiner.close()
        }
    }

    // MARK: PAIRING-PROTOCOL-6: an item goes out unbroken

    func testAMessageSentDuringAnItemNeverLandsInsideIt() async throws {
        let (host, joiner) = try await sessions()
        let big = PairCrypto.randomBytes(2_500_000)
        try await host.sendOffer(PairOffer(items: [PairItem(id: 1, kind: PairItem.keyPair, name: "big", fingerprint: fp1, size: Int64(big.count))]))
        guard case .offer = try await joiner.receive() else { return XCTFail("expected OFFER") }
        try await joiner.sendAnswer(PairAnswer(accept: [1]))
        try await joiner.sendOffer(PairOffer(items: [PairItem(id: 9, kind: PairItem.publicKey, name: "small", fingerprint: fp2, size: 3)]))
        guard case .answer = try await host.receive() else { return XCTFail("expected ANSWER") }
        guard case .offer = try await host.receive() else { return XCTFail("expected OFFER") }

        // The item and an answer go out at the same time; the answer may come first or after the
        // item, never between its pieces.
        async let item: Void = host.sendItem(id: 1, bytes: big)
        async let answer: Void = host.sendAnswer(PairAnswer(accept: [9]))
        var got: [String] = []
        for _ in 0 ..< 2 {
            switch try await joiner.receive(expectedItems: [1: Int64(big.count)]) {
            case .item(let id, let bytes):
                XCTAssertEqual(id, 1)
                XCTAssertEqual(bytes, big)
                got.append("item")
            case .answer(let a):
                XCTAssertEqual(a, PairAnswer(accept: [9]))
                got.append("answer")
            default:
                XCTFail("unexpected message")
            }
        }
        try await item
        try await answer
        XCTAssertEqual(Set(got), ["item", "answer"])
        await host.close()
        await joiner.close()
    }

    // MARK: PAIRING-IMPL-5: ending never waits on the network

    func testEndSendsByeAndCloses() async throws {
        let (host, joiner) = try await sessions()
        host.end(grace: 0.2)
        let bye = try await joiner.receive()
        XCTAssertEqual(bye, .bye)
        try await Task.sleep(nanoseconds: 300_000_000)
        do {
            try await host.sendInfo(PairInfo(name: "x", app: "y"))
            XCTFail("sent on an ended session")
        } catch let e as PairError {
            XCTAssertEqual(e.failure, .closed)
        }
    }

    func testEndingASessionWhosePeerStoppedReadingClosesIt() async throws {
        let stuck = StuckTransport()
        let session = PairSession(role: .host, wire: PairWire(stuck), sendKey: PairCrypto.randomBytes(32), receiveKey: PairCrypto.randomBytes(32))
        let sending = Task { try await session.sendItem(id: 1, bytes: Data(count: 3_000_000)) }
        try await Task.sleep(nanoseconds: 200_000_000)
        let started = Date()
        session.end(grace: 0.2)
        XCTAssertLessThan(Date().timeIntervalSince(started), 0.1, "end returns at once")
        do {
            try await sending.value
            XCTFail("the stuck item finished")
        } catch {
            XCTAssertTrue(stuck.isClosed)
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
    }

    // MARK: PairPeer

    func testAHostLetsOnlyLocalSourcesThrough() throws {
        let subnets = [try XCTUnwrap(PairPeer.Subnet(address: PairInvite.hostBytes("203.0.113.10")!, prefixLength: 24))]
        XCTAssertTrue(PairPeer.isAllowed(PairInvite.hostBytes("127.0.0.1")!, subnets: subnets))
        XCTAssertTrue(PairPeer.isAllowed(PairInvite.hostBytes("203.0.113.99")!, subnets: subnets))
        XCTAssertFalse(PairPeer.isAllowed(PairInvite.hostBytes("203.0.112.99")!, subnets: subnets))
        XCTAssertFalse(PairPeer.isAllowed(PairInvite.hostBytes("100.100.1.1")!, subnets: subnets))
        XCTAssertFalse(PairPeer.isAllowed(Data(count: 5), subnets: subnets))
        XCTAssertNil(PairPeer.Subnet(address: Data(count: 4), prefixLength: 33))
        XCTAssertNotNil(PairPeer.Subnet(address: Data(count: 16), prefixLength: 128))
    }
}

/// Hands out one byte every 50 ms for ever (header bytes first, then filler) until closed.
final class DripTransport: PairTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var source: [UInt8]
    private var closed = false

    init(_ bytes: [UInt8]) {
        source = bytes
    }

    var isClosed: Bool { lock.withLock { closed } }

    func write(_ data: Data) async throws {}

    func read(exactly count: Int) async throws -> Data {
        var out = Data()
        while out.count < count {
            try await Task.sleep(nanoseconds: 50_000_000)
            let next: UInt8? = lock.withLock { () -> UInt8? in
                if closed { return nil }
                return source.isEmpty ? 0x41 : source.removeFirst()
            }
            guard let b = next else { throw PairError(.closed, "the connection is closed") }
            out.append(b)
        }
        return out
    }

    func close() {
        lock.withLock { closed = true }
    }
}

/// A connection whose peer stopped reading: every write waits until the connection is closed.
final class StuckTransport: PairTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var closed = false

    var isClosed: Bool { lock.withLock { closed } }

    func write(_ data: Data) async throws {
        while !isClosed { try await Task.sleep(nanoseconds: 10_000_000) }
        throw PairError(.closed, "the connection is closed")
    }

    func read(exactly count: Int) async throws -> Data {
        while !isClosed { try await Task.sleep(nanoseconds: 10_000_000) }
        throw PairError(.closed, "the connection is closed")
    }

    func close() {
        lock.withLock { closed = true }
    }
}
