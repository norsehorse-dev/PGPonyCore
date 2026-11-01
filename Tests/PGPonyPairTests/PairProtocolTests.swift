// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// PairProtocolTests.swift
// The pairing protocol end to end over in-memory connections (and once over a real loopback
// TCP connection): a transfer both ways, refusals, someone in the middle, the invite's key
// check, and the checks that end a session. Mirrors the Kotlin PairProtocolTest.

import Foundation
import XCTest
@testable import PGPonyPair

final class PairProtocolTests: XCTestCase {

    private func attempts(hostKey: PairCrypto.KeyPair? = nil, hostKeyHash: Data? = nil) async throws -> (PairAttempt, PairAttempt) {
        let (h, j) = MemoryTransport.pair()
        let key = try hostKey ?? PairCrypto.keyPair()
        let host = Task { try await PairProtocol.host(transport: h, keyPair: key) }
        let joiner = try await PairProtocol.join(transport: j, expectedHostKeyHash: hostKeyHash)
        return (try await host.value, joiner)
    }

    private func sessions() async throws -> (PairSession, PairSession) {
        let (h, j) = try await attempts()
        XCTAssertEqual(h.code, j.code)
        XCTAssertNotNil(h.code.range(of: "^[0-9]{3} [0-9]{3}$", options: .regularExpression))
        async let hs = h.confirm()
        let js = try await j.confirm()
        return (try await hs, js)
    }

    func testPairsAndMovesItemsBothWays() async throws {
        let (host, joiner) = try await sessions()
        try await host.sendInfo(PairInfo(name: "Office Mac", app: "PGPony Desktop 3.0.0"))
        try await joiner.sendInfo(PairInfo(name: "iPhone", app: "PGPony 8.4.0", accepts: [PairItem.publicKey, PairItem.keyPair]))
        guard case .info(let joinerInfo) = try await host.receive() else { return XCTFail("expected INFO") }
        XCTAssertEqual(joinerInfo.name, "iPhone")
        XCTAssertTrue(joinerInfo.takes(PairItem.keyPair))
        XCTAssertFalse(joinerInfo.takes(PairItem.backup))
        guard case .info(let hostInfo) = try await joiner.receive() else { return XCTFail("expected INFO") }
        XCTAssertTrue(hostInfo.takes(PairItem.backup)) // no accepts member: all three

        // Host offers two items; the joiner takes one. The big one spans three ITEM_DATA.
        let big = PairCrypto.randomBytes(2_500_000)
        let cert = Data("-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n".utf8)
        try await host.sendOffer(PairOffer(items: [
            PairItem(id: 1, kind: PairItem.keyPair, name: "Alice", fingerprint: String(repeating: "AB", count: 20), size: Int64(big.count)),
            PairItem(id: 2, kind: PairItem.publicKey, name: "Bob", fingerprint: nil, size: Int64(cert.count)),
        ]))
        guard case .offer(let offer) = try await joiner.receive() else { return XCTFail("expected OFFER") }
        XCTAssertEqual(offer.items.count, 2)
        try await joiner.sendAnswer(PairAnswer(accept: [1]))
        let answer = try await host.receive()
        XCTAssertEqual(answer, .answer(PairAnswer(accept: [1])))

        let sending = Task { try await host.sendItem(id: 1, bytes: big) }
        let progress = ProgressBox()
        let item = try await joiner.receive(expectedItems: [1: Int64(big.count)]) { _, n in progress.set(n) }
        try await sending.value
        XCTAssertEqual(item, .item(id: 1, bytes: big))
        XCTAssertEqual(progress.get(), Int64(big.count))
        try await joiner.sendResult(PairResult(id: 1, ok: true))
        let result = try await host.receive()
        XCTAssertEqual(result, .result(PairResult(id: 1, ok: true)))

        // The other direction, in the same session.
        try await joiner.sendOffer(PairOffer(items: [PairItem(id: 7, kind: PairItem.publicKey, name: "Carol", size: Int64(cert.count))]))
        guard case .offer = try await host.receive() else { return XCTFail("expected OFFER") }
        try await host.sendAnswer(PairAnswer(accept: [7]))
        guard case .answer = try await joiner.receive() else { return XCTFail("expected ANSWER") }
        try await joiner.sendItem(id: 7, bytes: cert)
        let back = try await host.receive(expectedItems: [7: Int64(cert.count)])
        XCTAssertEqual(back, .item(id: 7, bytes: cert))

        await joiner.sendBye()
        let bye = try await host.receive()
        XCTAssertEqual(bye, .bye)
        await joiner.close()
    }

    func testAnItemThatWasNotAcceptedEndsTheSession() async throws {
        let (host, joiner) = try await sessions()
        try await host.sendItem(id: 3, bytes: Data("unasked".utf8))
        do {
            _ = try await joiner.receive()
            XCTFail("an unasked item was taken")
        } catch let e as PairError {
            XCTAssertEqual(e.failure, .protocolError)
        }
        await host.close()
    }

    func testARefusalOnEitherSideEndsTheAttempt() async throws {
        for hostRefuses in [true, false] {
            let (host, joiner) = try await attempts()
            let (no, yes) = hostRefuses ? (host, joiner) : (joiner, host)
            await no.reject()
            let refusal = await yes.peerRefusal()
            XCTAssertEqual(refusal, .refused)
            do {
                _ = try await yes.confirm()
                XCTFail("confirmed after a refusal")
            } catch let e as PairError {
                XCTAssertEqual(e.failure, .refused, hostRefuses ? "host refused" : "joiner refused")
            }
        }
    }

    func testSomeoneInTheMiddleGetsTwoDifferentCodes() async throws {
        // The middle runs its own exchange with each side.
        let (hostToMiddle, middleAsJoinerSide) = MemoryTransport.pair()
        let (middleAsHostSide, joinerSide) = MemoryTransport.pair()
        let hostKey = try PairCrypto.keyPair()
        let middleKey = try PairCrypto.keyPair()
        let host = Task { try await PairProtocol.host(transport: hostToMiddle, keyPair: hostKey) }
        let middleAsHost = Task { try await PairProtocol.host(transport: middleAsHostSide, keyPair: middleKey) }
        let middleAsJoiner = try await PairProtocol.join(transport: middleAsJoinerSide)
        let joiner = try await PairProtocol.join(transport: joinerSide)
        let codeOnHost = try await host.value.code
        let codeMiddleShowsJoiner = try await middleAsHost.value.code
        XCTAssertEqual(joiner.code, codeMiddleShowsJoiner)
        XCTAssertEqual(codeOnHost, middleAsJoiner.code)
        XCTAssertNotEqual(joiner.code, codeOnHost)
    }

    func testTheInviteHashPinsTheHostKey() async throws {
        let hostKey = try PairCrypto.keyPair()
        let pinned = try XCTUnwrap(PairInvite.forHostKey(hostKey.publicKey, addresses: [PairInvite.Address(host: "127.0.0.1", port: 1)])).hostKeyHash
        let (host, joiner) = try await attempts(hostKey: hostKey, hostKeyHash: pinned)
        XCTAssertEqual(host.code, joiner.code)
        await joiner.reject()

        let other = try XCTUnwrap(PairInvite.forHostKey(try PairCrypto.keyPair().publicKey, addresses: [PairInvite.Address(host: "127.0.0.1", port: 1)])).hostKeyHash
        let (h, j) = MemoryTransport.pair()
        let hostTask = Task { try await PairProtocol.host(transport: h, keyPair: hostKey) }
        do {
            _ = try await PairProtocol.join(transport: j, expectedHostKeyHash: other)
            XCTFail("joined a host the invite did not name")
        } catch let e as PairError {
            XCTAssertEqual(e.failure, .handshake)
        }
        do {
            _ = try await hostTask.value
            XCTFail("the host went on after the joiner aborted")
        } catch let e as PairError {
            XCTAssertEqual(e.failure, .handshake)
        }
    }

    func testAJoinerThatDoesNotSpeakPairingIsTurnedAway() async throws {
        let (h, j) = MemoryTransport.pair()
        let host = Task { try await PairProtocol.host(transport: h, keyPair: try PairCrypto.keyPair()) }
        try await j.write(Data("GET / HTTP/1.1\r\n\r\n".utf8))
        do {
            _ = try await host.value
            XCTFail("a stranger got through")
        } catch let e as PairError {
            XCTAssertEqual(e.failure, .protocolError)
        }
    }

    func testSealedMessagesMustArriveInOrder() throws {
        let key = PairCrypto.randomBytes(32)
        let m0 = try PairCrypto.seal(key: key, seq: 0, plaintext: Data([1, 2, 3]))
        var m1 = try PairCrypto.seal(key: key, seq: 1, plaintext: Data([4]))
        XCTAssertEqual(Data([1, 2, 3]), try PairCrypto.open(key: key, expectedSeq: 0, sealed: m0))
        XCTAssertThrowsError(try PairCrypto.open(key: key, expectedSeq: 0, sealed: m1))
        XCTAssertThrowsError(try PairCrypto.open(key: key, expectedSeq: 1, sealed: m0))
        m1[m1.count - 1] ^= 1
        XCTAssertThrowsError(try PairCrypto.open(key: key, expectedSeq: 1, sealed: m1))
    }

    #if canImport(Network)
    func testPairsOverALoopbackTCPConnection() async throws {
        let listener = try NWPairListener()
        let port = try await listener.start()
        XCTAssertNotEqual(port, 0)
        let hostKey = try PairCrypto.keyPair()
        let host = Task { () -> PairAttempt in
            let transport = try await listener.accept(timeout: 10)
            return try await PairProtocol.host(transport: transport, keyPair: hostKey)
        }
        let invite = try XCTUnwrap(PairInvite.forHostKey(hostKey.publicKey, addresses: [PairInvite.Address(host: "127.0.0.1", port: port)]))
        let joiner = try await PairProtocol.join(invite: invite)
        let hostAttempt = try await host.value
        XCTAssertEqual(hostAttempt.code, joiner.code)
        async let hs = hostAttempt.confirm()
        let js = try await joiner.confirm()
        let hostSession = try await hs
        try await js.sendInfo(PairInfo(name: "loopback", app: "PGPonyPair tests"))
        let info = try await hostSession.receive()
        XCTAssertEqual(info, .info(PairInfo(name: "loopback", app: "PGPonyPair tests")))
        await js.sendBye()
        let bye = try await hostSession.receive()
        XCTAssertEqual(bye, .bye)
        await js.close()
        listener.close()
    }
    #endif
}

final class ProgressBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Int64 = 0

    func set(_ v: Int64) {
        lock.lock(); value = v; lock.unlock()
    }

    func get() -> Int64 {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}
