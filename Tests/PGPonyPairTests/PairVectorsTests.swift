// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// PairVectorsTests.swift
// The published pairing vectors (docs/PAIRING_PROTOCOL.md, section 10), the same files the
// Kotlin core checks:
//
//   v1-vectors.json  the derivations of one attempt
//   v1-session.json  every byte of one whole session, both directions, with fixed randomness
//   v1-invites.json  QR invites that must parse, with their fields, and ones that must not
//   v1-peers.json    connection sources a host lets through to phase 1, and ones it closes

import Foundation
import XCTest
@testable import PGPonyPair

final class PairVectorsTests: XCTestCase {

    func testDerivationsReproduce() throws {
        let v = try vector("v1-vectors")
        let j = try PairCrypto.keyPair(secret: v.bytes("sk_J"))
        let h = try PairCrypto.keyPair(secret: v.bytes("sk_H"))
        XCTAssertEqual(v.str("pk_J"), hex(j.publicKey))
        XCTAssertEqual(v.str("pk_H"), hex(h.publicKey))
        let nJ = v.bytes("n_J")
        let nH = v.bytes("n_H")
        XCTAssertEqual(v.str("commit"), hex(PairCrypto.commit(nonceHost: nH, pkHost: h.publicKey, pkJoiner: j.publicKey)))
        let version = v.bytes("version")
        XCTAssertEqual(version, Data([PairProtocol.version]))
        let t = PairCrypto.transcript(pkJ: j.publicKey, pkH: h.publicKey, nJ: nJ, nH: nH, version: version[version.startIndex])
        XCTAssertEqual(v.str("T"), hex(t))
        // The version is part of T: another version gives another code.
        XCTAssertNotEqual(t, PairCrypto.transcript(pkJ: j.publicKey, pkH: h.publicKey, nJ: nJ, nH: nH, version: 2))
        let z = try XCTUnwrap(PairCrypto.agree(secret: v.bytes("sk_H"), peer: j.publicKey))
        XCTAssertEqual(v.str("Z"), hex(z))
        XCTAssertEqual(v.str("Z"), hex(try XCTUnwrap(PairCrypto.agree(secret: v.bytes("sk_J"), peer: h.publicKey))))
        let keys = PairCrypto.derive(z: z, transcript: t)
        XCTAssertEqual(v.str("K"), hex(keys.pairKey))
        XCTAssertEqual(v.str("k_HJ"), hex(keys.hostToJoiner))
        XCTAssertEqual(v.str("k_JH"), hex(keys.joinerToHost))
        XCTAssertEqual(v.str("code"), PairCrypto.code(transcript: t))
        XCTAssertEqual(v.str("host_msg_0_sealed"), hex(try PairCrypto.seal(key: keys.hostToJoiner, seq: 0, plaintext: v.bytes("host_msg_0_plaintext"))))
        XCTAssertEqual(v.str("joiner_msg_0_sealed"), hex(try PairCrypto.seal(key: keys.joinerToHost, seq: 0, plaintext: v.bytes("joiner_msg_0_plaintext"))))
    }

    func testALowOrderPeerKeyIsRefused() {
        XCTAssertNil(PairCrypto.agree(secret: PairCrypto.randomBytes(32), peer: Data(count: 32)))
    }

    func testTheWholeSessionReproducesByteForByte() async throws {
        let v = try vector("v1-session")
        let run = try await SessionScript.run(v)
        XCTAssertEqual(v.str("code"), run.code)
        // The handshake prefixes first: a mismatch there says which phase is off.
        XCTAssertTrue(hex(run.hostToJoiner).hasPrefix(v.str("handshake_host_to_joiner")), "host handshake bytes")
        XCTAssertTrue(hex(run.joinerToHost).hasPrefix(v.str("handshake_joiner_to_host")), "joiner handshake bytes")
        XCTAssertEqual(v.str("host_to_joiner"), hex(run.hostToJoiner))
        XCTAssertEqual(v.str("joiner_to_host"), hex(run.joinerToHost))
        let items = try XCTUnwrap(v["items"] as? [String: String])
        XCTAssertEqual(items["1"], hex(run.received))
    }

    func testEachSessionMessageSealsAndReadsAsListed() throws {
        let v = try vector("v1-session")
        let skH = v.bytes("sk_H")
        let skJ = v.bytes("sk_J")
        let pkH = try PairCrypto.keyPair(secret: skH).publicKey
        let pkJ = try PairCrypto.keyPair(secret: skJ).publicKey
        let keys = PairCrypto.derive(
            z: try XCTUnwrap(PairCrypto.agree(secret: skH, peer: pkJ)),
            transcript: PairCrypto.transcript(pkJ: pkJ, pkH: pkH, nJ: v.bytes("n_J"), nH: v.bytes("n_H"))
        )
        let messages = try XCTUnwrap(v["messages"] as? [[String: Any]])
        XCTAssertEqual(messages.count, 9)
        for m in messages {
            let key = m.str("from") == "host" ? keys.hostToJoiner : keys.joinerToHost
            let seq = UInt64(try XCTUnwrap(m["seq"] as? Int))
            let plaintext = m.bytes("plaintext")
            XCTAssertEqual(try XCTUnwrap(m["type"] as? Int), Int(plaintext[plaintext.startIndex]))
            let frame = PairFrames.frame(PairFrames.envelope, try PairCrypto.seal(key: key, seq: seq, plaintext: plaintext))
            XCTAssertEqual(m.str("frame"), hex(frame))
            XCTAssertEqual(plaintext, try PairCrypto.open(key: key, expectedSeq: seq, sealed: frame.slice(5, frame.count - 5)))
            if let json = m["json"] {
                // Same JSON value, whatever the member order.
                let parsed = try JSONSerialization.jsonObject(with: plaintext.slice(1, plaintext.count - 1))
                XCTAssertEqual(parsed as? NSObject, json as? NSObject, m.str("name"))
            }
        }
    }

    func testInvitesParseAsListed() throws {
        let v = try vector("v1-invites")
        for c in try XCTUnwrap(v["valid"] as? [[String: Any]]) {
            let invite = try XCTUnwrap(PairInvite.parse(c.str("uri")), c.str("uri"))
            XCTAssertEqual(c["addresses"] as? [String], invite.addresses.map(\.description))
            XCTAssertEqual(c.str("h"), hex(invite.hostKeyHash))
            if let canonical = c["canonical"] as? String { XCTAssertEqual(canonical, invite.uri) }
            if let pk = c["pk_H"] as? String {
                XCTAssertEqual(invite, PairInvite.forHostKey(unhex(pk), addresses: invite.addresses))
            }
            if let bytes = c["address_bytes"] as? [String] {
                XCTAssertEqual(bytes, invite.addresses.map { hex($0.bytes) }, c.str("uri"))
            }
        }
        for bad in try XCTUnwrap(v["invalid"] as? [[String: Any]]) {
            XCTAssertNil(PairInvite.parse(bad.str("uri")), bad.str("why"))
        }
    }

    func testPeersClassifyAsListed() throws {
        let v = try vector("v1-peers")
        let subnets = try XCTUnwrap(v["subnets"] as? [[String: Any]]).map { s -> PairPeer.Subnet in
            let bytes = PairInvite.hostBytes(s.str("address"))!
            return PairPeer.Subnet(address: bytes, prefixLength: s["prefix"] as! Int)!
        }
        for (key, expected) in [("allowed", true), ("refused", false)] {
            for c in try XCTUnwrap(v[key] as? [[String: Any]]) {
                let bytes = try XCTUnwrap(PairInvite.hostBytes(c.str("address")), c.str("address"))
                XCTAssertEqual(PairPeer.isAllowed(bytes, subnets: subnets), expected, c.str("address") + ": " + c.str("why"))
            }
        }
        // Without the subnets only the always-local ranges pass.
        XCTAssertTrue(PairPeer.isAllowed(PairInvite.hostBytes("192.168.1.5")!))
        XCTAssertFalse(PairPeer.isAllowed(PairInvite.hostBytes("203.0.113.200")!))
    }

    func testAnInviteWritesWhatItReads() throws {
        let invite = try XCTUnwrap(PairInvite.forHostKey(
            try PairCrypto.keyPair().publicKey,
            addresses: [PairInvite.Address(host: "192.168.1.20", port: 49152), PairInvite.Address(host: "fd00::1", port: 49152)]
        ))
        XCTAssertTrue(invite.uri.hasPrefix("pgpony-pair:1?a=192.168.1.20:49152,[fd00::1]:49152&h="))
        XCTAssertEqual(invite, PairInvite.parse(invite.uri))
    }
}

/// The scripted session behind v1-session.json, over an in-memory connection with the vector's
/// randomness. Each direction is written by one side in script order, so the bytes do not
/// depend on timing.
enum SessionScript {
    static let hostInfo = PairInfo(name: "Office Mac", app: "PGPony Desktop 3.0.0", accepts: Set(PairItem.kinds))
    static let joinerInfo = PairInfo(name: "Pixel", app: "PGPony Android 4.7.0", accepts: [PairItem.publicKey, PairItem.keyPair])
    static let item1 = Data("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nPGPony pairing test item: not a key.\n-----END PGP PUBLIC KEY BLOCK-----\n".utf8)
    static let fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
    static let offer = PairOffer(items: [
        PairItem(id: 1, kind: PairItem.publicKey, name: "Alice <alice@example.org>", fingerprint: fingerprint, size: Int64(item1.count)),
        PairItem(id: 2, kind: PairItem.keyPair, name: "Alice <alice@example.org>", fingerprint: fingerprint, size: 1234),
    ])

    struct Run {
        let code: String
        let hostToJoiner: Data
        let joinerToHost: Data
        let received: Data
    }

    static func run(_ v: [String: Any]) async throws -> Run {
        let (hostSide, joinerSide) = MemoryTransport.pair()
        let hostKey = try PairCrypto.keyPair(secret: v.bytes("sk_H"))
        let hostRandom = FixedRandom([v.bytes("n_H"), v.bytes("ack_nonce")]).random
        let joinerRandom = FixedRandom([v.bytes("sk_J"), v.bytes("n_J"), v.bytes("hello_nonce")]).random

        let hostTask = Task { try await PairProtocol.host(transport: hostSide, keyPair: hostKey, random: hostRandom) }
        let joinerAttempt = try await PairProtocol.join(transport: joinerSide, expectedHostKeyHash: nil, random: joinerRandom)
        let hostAttempt = try await hostTask.value
        XCTAssertEqual(hostAttempt.code, joinerAttempt.code)
        async let hostSessionF = hostAttempt.confirm()
        let joiner = try await joinerAttempt.confirm()
        let host = try await hostSessionF

        try await host.sendInfo(hostInfo)
        try await joiner.sendInfo(joinerInfo)
        let m1 = try await host.receive()
        XCTAssertEqual(m1, .info(joinerInfo))
        let m2 = try await joiner.receive()
        XCTAssertEqual(m2, .info(hostInfo))
        try await host.sendOffer(offer)
        let m3 = try await joiner.receive()
        XCTAssertEqual(m3, .offer(offer))
        try await joiner.sendAnswer(PairAnswer(accept: [1]))
        let m4 = try await host.receive()
        XCTAssertEqual(m4, .answer(PairAnswer(accept: [1])))
        try await host.sendItem(id: 1, bytes: item1)
        let m5 = try await joiner.receive(expectedItems: [1: Int64(item1.count)])
        guard case .item(let id, let received) = m5 else { throw PairError(.protocolError, "expected the item, got \(m5)") }
        XCTAssertEqual(id, 1)
        try await joiner.sendResult(PairResult(id: 1, ok: true))
        let m6 = try await host.receive()
        XCTAssertEqual(m6, .result(PairResult(id: 1, ok: true)))
        await host.sendBye()
        let m7 = try await joiner.receive()
        XCTAssertEqual(m7, .bye)
        await host.close()
        await joiner.close()
        return Run(code: joinerAttempt.code, hostToJoiner: hostSide.written, joinerToHost: joinerSide.written, received: received)
    }
}
