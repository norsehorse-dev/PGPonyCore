// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// PairSession.swift
// Phase 3 of the pairing protocol (docs/PAIRING_PROTOCOL.md, section 5): sealed messages inside
// ENVELOPE frames, and the offer and item messages that move keys and backups.
//
// JSON is written by hand, compact and in the Kotlin core's member order, so the whole session
// replays byte for byte against v1-session.json. Member order is not significant to a reader.

import Foundation

/// One item on offer (section 5, `ITEM`).
public struct PairItem: Equatable, Sendable {
    public static let publicKey = "public-key"
    public static let keyPair = "key-pair"
    public static let backup = "backup"
    /// The kinds this version knows, in the order INFO lists them.
    public static let kinds = [publicKey, keyPair, backup]

    public let id: Int
    public let kind: String
    public let name: String
    public let fingerprint: String?
    public let size: Int64

    public init(id: Int, kind: String, name: String, fingerprint: String? = nil, size: Int64) {
        self.id = id
        self.kind = kind
        self.name = name
        self.fingerprint = fingerprint
        self.size = size
    }

    var json: String {
        "{\"id\":\(id),\"kind\":\(PairJSON.string(kind)),\"name\":\(PairJSON.string(name)),\"fingerprint\":\(fingerprint.map(PairJSON.string) ?? "null"),\"size\":\(size)}"
    }

    init(json o: [String: Any]) throws {
        guard let id = PairJSON.int(o["id"]), let kind = o["kind"] as? String, let size = PairJSON.int64(o["size"]) else {
            throw PairError(.protocolError, "malformed message")
        }
        self.init(id: id, kind: kind, name: o["name"] as? String ?? "", fingerprint: o["fingerprint"] as? String, size: size)
    }
}

/// The INFO message. `accepts` lists the item kinds this side can import; nil (the member left
/// out) means all three. A sender offers nothing the receiver does not accept.
public struct PairInfo: Equatable, Sendable {
    public let name: String
    public let app: String
    public let accepts: Set<String>?

    public init(name: String, app: String, accepts: Set<String>? = nil) {
        self.name = name
        self.app = app
        self.accepts = accepts
    }

    /// Whether the side that sent this INFO can import items of `kind`.
    public func takes(_ kind: String) -> Bool {
        if let accepts { return accepts.contains(kind) }
        return PairItem.kinds.contains(kind)
    }

    var json: String {
        var out = "{\"name\":\(PairJSON.string(name)),\"app\":\(PairJSON.string(app))"
        if let accepts {
            let ordered = PairItem.kinds.filter { accepts.contains($0) } + accepts.filter { !PairItem.kinds.contains($0) }.sorted()
            out += ",\"accepts\":[" + ordered.map(PairJSON.string).joined(separator: ",") + "]"
        }
        return out + "}"
    }

    init(json o: [String: Any]) {
        let accepts = (o["accepts"] as? [Any]).map { Set($0.compactMap { $0 as? String }) }
        self.init(name: o["name"] as? String ?? "", app: o["app"] as? String ?? "", accepts: accepts)
    }
}

public struct PairOffer: Equatable, Sendable {
    public let items: [PairItem]

    public init(items: [PairItem]) {
        self.items = items
    }

    var json: String { "{\"items\":[" + items.map(\.json).joined(separator: ",") + "]}" }
}

public struct PairAnswer: Equatable, Sendable {
    public let accept: [Int]

    public init(accept: [Int]) {
        self.accept = accept
    }

    var json: String { "{\"accept\":[" + accept.map(String.init).joined(separator: ",") + "]}" }
}

public struct PairResult: Equatable, Sendable {
    public let id: Int
    public let ok: Bool
    public let error: String?

    public init(id: Int, ok: Bool, error: String? = nil) {
        self.id = id
        self.ok = ok
        self.error = error
    }

    var json: String { "{\"id\":\(id),\"ok\":\(ok),\"error\":\(error.map(PairJSON.string) ?? "null")}" }
}

/// A message received in the session.
public enum PairMessage: Equatable, Sendable {
    case info(PairInfo)
    case offer(PairOffer)
    case answer(PairAnswer)
    /// A whole item, reassembled and checked against its size and hash.
    case item(id: Int, bytes: Data)
    case result(PairResult)
    case bye
}

enum PairJSON {
    /// A JSON string as kotlinx.serialization writes it: quote, backslash and control characters
    /// escaped, everything else (slash and non-ASCII included) as is.
    static func string(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if u.value < 0x20 {
                    let hex = String(u.value, radix: 16)
                    out += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
                } else {
                    out.unicodeScalars.append(u)
                }
            }
        }
        return out + "\""
    }

    static func object(_ body: Data) throws -> [String: Any] {
        guard let o = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            throw PairError(.protocolError, "malformed message")
        }
        return o
    }

    /// A JSON integer in the Int32 range (ids), as Kotlin's `int` reads it; nil for anything else.
    static func int(_ v: Any?) -> Int? {
        guard let n = int64(v), let i = Int32(exactly: n) else { return nil }
        return Int(i)
    }

    /// A JSON integer (sizes); nil for a fraction, a boolean or anything that is not a number.
    static func int64(_ v: Any?) -> Int64? {
        guard let n = v as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return nil }
        let d = n.doubleValue
        guard d == d.rounded(), abs(d) < 9.0e15 else { return nil }
        return n.int64Value
    }
}

/// The paired session. One reader calls `receive` in a loop; sends may come from anywhere and
/// go out in call order. Ends on `close()`, `end(grace:)`, BYE, or a protocol error.
///
/// The session keeps the offer rules of section 5: one OFFER open in each direction (a second one
/// before the first was answered and its RESULTs sent is a protocol error), an ANSWER only for an
/// open offer and only with ids it listed (each once), one item for each accepted id, a RESULT
/// only for an accepted id. An item goes out as one unbroken run of ITEM_BEGIN, ITEM_DATA and
/// ITEM_END: nothing else is sent in between.
public actor PairSession {
    public static let info: UInt8 = 0x01
    public static let offer: UInt8 = 0x10
    public static let answer: UInt8 = 0x11
    public static let itemBegin: UInt8 = 0x20
    public static let itemData: UInt8 = 0x21
    public static let itemEnd: UInt8 = 0x22
    public static let result: UInt8 = 0x30
    public static let bye: UInt8 = 0x3F

    public static let maxPlaintext = 1_048_576
    public static let maxItemBytes: Int64 = 64 * 1024 * 1024
    public static let maxOfferItems = 1000
    /// Item bytes per ITEM_DATA, as the Kotlin core sends them (any split up to the limit reads).
    static let chunk = maxPlaintext - 16 - 4

    public nonisolated let role: PairRole
    private let wire: PairWire
    private var sendKey: Data
    private var receiveKey: Data
    private var sendSeq: UInt64 = 0
    private var receiveSeq: UInt64 = 0
    private var closed = false
    /// The last queued write. Sends chain onto it so frames go out in sequence-number order even
    /// when a send suspends and another starts (actors are reentrant).
    private var lastWrite: Task<Void, Error>?

    // Offer bookkeeping (section 5). Received: the open offer's ids until this side answers, then
    // the accepted ids until their RESULTs go out. Sent: whether our offer waits for its ANSWER,
    // then the accepted ids until their RESULTs arrive.
    private var receivedOffer: Set<Int>?
    private var resultsOwed = Set<Int>()
    // Accepted ids whose item has not arrived yet: each comes once.
    private var itemsDue = Set<Int>()
    private var sentOffer: Set<Int>?
    private var resultsAwaited = Set<Int>()

    init(role: PairRole, wire: PairWire, sendKey: Data, receiveKey: Data) {
        self.role = role
        self.wire = wire
        self.sendKey = sendKey
        self.receiveKey = receiveKey
    }

    // MARK: Sealed messages

    /// One message with no offer bookkeeping (the tests use it to play a peer that breaks the rules).
    func send(_ type: UInt8, _ body: Data) async throws {
        let plaintext = Data([type]) + body
        guard plaintext.count <= PairSession.maxPlaintext else { throw PairError(.protocolError, "message too long") }
        try await sendRun(1) { _ in plaintext }
    }

    /// Seals and writes `count` messages as one unbroken run. Their sequence numbers are taken
    /// here, before any suspension, so a message sent meanwhile gets a later number, and their
    /// writes queue behind earlier ones, so it also goes out after them. `plaintext(i)` is message
    /// i (type byte and body); `sent(i)` runs once it is written.
    private func sendRun(
        _ count: Int, sent: (@Sendable (Int) -> Void)? = nil, _ plaintext: @escaping @Sendable (Int) -> Data
    ) async throws {
        if closed { throw PairError(.closed, "the session is closed") }
        let first = sendSeq
        sendSeq += UInt64(count)
        let key = sendKey
        let previous = lastWrite
        let wire = self.wire
        let write = Task {
            _ = try? await previous?.value
            for i in 0 ..< count {
                let sealed = try PairCrypto.seal(key: key, seq: first + UInt64(i), plaintext: plaintext(i))
                try await wire.writeFrame(PairFrames.envelope, sealed)
                sent?(i)
            }
        }
        lastWrite = write
        do {
            try await write.value
        } catch {
            close()
            throw PairProtocol.wrap(error)
        }
    }

    private func receiveRaw() async throws -> (UInt8, Data) {
        do {
            let (type, payload) = try await wire.readFrame(timeout: PairProtocol.confirmTimeout)
            guard type == PairFrames.envelope else { throw PairError(.protocolError, "unexpected frame") }
            let plaintext = try PairCrypto.open(key: receiveKey, expectedSeq: receiveSeq, sealed: payload)
            receiveSeq += 1
            guard !plaintext.isEmpty, plaintext.count <= PairSession.maxPlaintext else { throw PairError(.protocolError, "bad message") }
            return (plaintext[plaintext.startIndex], plaintext.slice(1, plaintext.count - 1))
        } catch {
            close()
            throw PairProtocol.wrap(error)
        }
    }

    // MARK: Sending

    public func sendInfo(_ info: PairInfo) async throws {
        try await send(PairSession.info, Data(info.json.utf8))
    }

    /// Offers items. Only one offer is open at a time: the next one may follow once the other
    /// side answered this one and sent a RESULT for every item it accepted.
    public func sendOffer(_ offer: PairOffer) async throws {
        guard (1 ... PairSession.maxOfferItems).contains(offer.items.count),
              offer.items.allSatisfy({ PairItem.kinds.contains($0.kind) && (0 ... PairSession.maxItemBytes).contains($0.size) && Int32(exactly: $0.id) != nil }),
              Set(offer.items.map(\.id)).count == offer.items.count
        else { throw PairError(.protocolError, "an offer lists 1 to 1000 items of known kinds, sizes and distinct ids") }
        guard sentOffer == nil, resultsAwaited.isEmpty else { throw PairError(.protocolError, "the previous offer is still open") }
        // Recorded before the write: the answer may arrive before the send returns.
        sentOffer = Set(offer.items.map(\.id))
        try await send(PairSession.offer, Data(offer.json.utf8))
    }

    /// Answers the open offer from the other side with the ids this user accepted (may be none).
    public func sendAnswer(_ answer: PairAnswer) async throws {
        guard let open = receivedOffer else { throw PairError(.protocolError, "there is no offer to answer") }
        guard Set(answer.accept).isSubset(of: open) else { throw PairError(.protocolError, "only ids the offer listed") }
        guard Set(answer.accept).count == answer.accept.count else { throw PairError(.protocolError, "each id once") }
        receivedOffer = nil
        resultsOwed.formUnion(answer.accept)
        itemsDue.formUnion(answer.accept)
        try await send(PairSession.answer, Data(answer.json.utf8))
    }

    /// Reports what became of an accepted item.
    public func sendResult(_ result: PairResult) async throws {
        guard resultsOwed.remove(result.id) != nil else { throw PairError(.protocolError, "no result is owed for item \(result.id)") }
        try await send(PairSession.result, Data(result.json.utf8))
    }

    /// One accepted item: ITEM_BEGIN, ITEM_DATA pieces, ITEM_END, as one unbroken run. `progress`
    /// gets bytes sent.
    public func sendItem(id: Int, bytes: Data, progress: (@Sendable (Int64) -> Void)? = nil) async throws {
        guard Int64(bytes.count) <= PairSession.maxItemBytes else { throw PairError(.protocolError, "item larger than 64 MiB") }
        let idb = PairSession.intBytes(id)
        let chunk = PairSession.chunk
        let total = bytes.count
        let pieces = (total + chunk - 1) / chunk
        let begin = Data([PairSession.itemBegin]) + idb + PairCrypto.seqBytes(UInt64(total))
        let last = Data([PairSession.itemEnd]) + idb + PairCrypto.sha256(bytes)
        try await sendRun(pieces + 2, sent: { i in
            if i >= 1 && i <= pieces { progress?(Int64(min(i * chunk, total))) }
        }) { i in
            if i == 0 { return begin }
            if i == pieces + 1 { return last }
            let offset = (i - 1) * chunk
            return Data([PairSession.itemData]) + idb + bytes.slice(offset, min(chunk, total - offset))
        }
    }

    public func sendBye() async {
        try? await send(PairSession.bye, Data())
    }

    /// Ends the session without making the caller wait on the network: BYE goes out best effort,
    /// and the connection is closed as soon as it is out or after `grace` seconds, whichever comes
    /// first. A peer that stopped reading therefore cannot hold the app, and an item in flight
    /// stops.
    public nonisolated func end(grace: Double = 2) {
        Task {
            await withTaskGroup(of: Void.self) { group in
                group.addTask { await self.sendBye() }
                group.addTask { try? await Task.sleep(nanoseconds: UInt64(grace * 1_000_000_000)) }
                _ = await group.next()
                await self.close()
                group.cancelAll()
            }
        }
    }

    // MARK: Receiving

    /// The next message. Item pieces are gathered here and handed over as one `.item` once
    /// ITEM_END checks out; `itemProgress` gets (id, bytes so far) while one arrives.
    /// `expectedItems` are the ids this side accepted and their announced sizes; an item outside
    /// it ends the session.
    public func receive(
        expectedItems: [Int: Int64] = [:], itemProgress: (@Sendable (Int, Int64) -> Void)? = nil
    ) async throws -> PairMessage {
        let (type, body) = try await receiveRaw()
        switch type {
        case PairSession.info:
            return .info(PairInfo(json: try decode(body)))
        case PairSession.offer:
            let o = try decode(body)
            guard let list = o["items"] as? [Any] else { return try protocolError("bad offer") }
            let items: [PairItem]
            do {
                items = try list.map { entry -> PairItem in
                    guard let d = entry as? [String: Any] else { throw PairError(.protocolError, "bad offer") }
                    return try PairItem(json: d)
                }
            } catch {
                return try protocolError("malformed message")
            }
            if items.isEmpty || items.count > PairSession.maxOfferItems ||
                items.contains(where: { !(0 ... PairSession.maxItemBytes).contains($0.size) }) ||
                Set(items.map(\.id)).count != items.count {
                return try protocolError("bad offer")
            }
            guard receivedOffer == nil, resultsOwed.isEmpty else {
                return try protocolError("a second offer while the first is still open")
            }
            receivedOffer = Set(items.map(\.id))
            return .offer(PairOffer(items: items))
        case PairSession.answer:
            let o = try decode(body)
            guard let list = o["accept"] as? [Any] else { return try protocolError("malformed message") }
            let ids = list.compactMap { PairJSON.int($0) }
            guard ids.count == list.count else { return try protocolError("malformed message") }
            guard let offered = sentOffer, Set(ids).count == ids.count, Set(ids).isSubset(of: offered) else {
                return try protocolError("an answer that does not fit the offer")
            }
            sentOffer = nil
            resultsAwaited.formUnion(ids)
            return .answer(PairAnswer(accept: ids))
        case PairSession.result:
            let o = try decode(body)
            guard let id = PairJSON.int(o["id"]) else { return try protocolError("malformed message") }
            guard resultsAwaited.remove(id) != nil else {
                return try protocolError("a result for an item that was not accepted")
            }
            return .result(PairResult(id: id, ok: o["ok"] as? Bool ?? false, error: o["error"] as? String))
        case PairSession.bye:
            close()
            return .bye
        case PairSession.itemBegin:
            guard body.count == 12 else { return try protocolError("bad item header") }
            let id = PairSession.readInt(body, 0)
            let size = body.slice(4, 8).reduce(Int64(0)) { ($0 << 8) | Int64($1) }
            guard itemsDue.remove(id) != nil else { return try protocolError("an item that was not accepted, or one that came twice") }
            guard let announced = expectedItems[id] else { return try protocolError("an item that was not accepted") }
            guard size == announced, size <= PairSession.maxItemBytes else { return try protocolError("item size does not match the offer") }
            return .item(id: id, bytes: try await receiveItemBody(id: id, size: Int(size), progress: itemProgress))
        default:
            return try protocolError("unknown message")
        }
    }

    private func receiveItemBody(id: Int, size: Int, progress: (@Sendable (Int, Int64) -> Void)?) async throws -> Data {
        var buffer = Data()
        buffer.reserveCapacity(size)
        while true {
            let (type, body) = try await receiveRaw()
            guard body.count >= 4, PairSession.readInt(body, 0) == id else { return try protocolError("item pieces out of order") }
            switch type {
            case PairSession.itemData:
                guard buffer.count + body.count - 4 <= size else { return try protocolError("item longer than announced") }
                buffer.append(body.slice(4, body.count - 4))
                progress?(id, Int64(buffer.count))
            case PairSession.itemEnd:
                guard buffer.count == size, body.count == 36,
                      PairFrames.constantTimeEquals(PairCrypto.sha256(buffer), body.slice(4, 32))
                else { return try protocolError("item damaged in transit") }
                return buffer
            default:
                return try protocolError("item pieces out of order")
            }
        }
    }

    private func decode(_ body: Data) throws -> [String: Any] {
        do {
            return try PairJSON.object(body)
        } catch {
            close()
            throw error
        }
    }

    private func protocolError<T>(_ message: String) throws -> T {
        close()
        throw PairError(.protocolError, message)
    }

    static func intBytes(_ v: Int) -> Data {
        withUnsafeBytes(of: UInt32(truncatingIfNeeded: v).bigEndian) { Data($0) }
    }

    /// A signed 32-bit id, as Kotlin reads it.
    static func readInt(_ b: Data, _ offset: Int) -> Int {
        Int(Int32(bitPattern: b.slice(offset, 4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }))
    }

    /// Ends the session and drops its keys. Safe to call more than once.
    public func close() {
        if closed { return }
        closed = true
        sendKey = Data()
        receiveKey = Data()
        wire.close()
    }
}
