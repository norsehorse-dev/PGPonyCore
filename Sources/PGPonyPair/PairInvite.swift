// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// PairInvite.swift
// The invite a pairing host shows as a QR code (docs/PAIRING_PROTOCOL.md, section 8):
//
//     pgpony-pair:1?a=<address>[,<address>...]&h=<base64url(SHA-256(pk_H)[0..16])>
//
// A phone scans it instead of typing an address, and the joiner checks the host key in ACCEPT
// against `h`. Addresses are IP literals only (an IPv6 one in brackets), so a QR code can never
// make the joiner look up a name: they are parsed to their bytes here, strictly, and the
// connection is built from those bytes. Parsed by hand, rule for rule as the Kotlin core does it.

import Foundation

public struct PairInvite: Equatable, Sendable {

    /// One `host:port` from `a`. `host` is an IPv4 or IPv6 literal, without brackets.
    public struct Address: Equatable, Sendable, CustomStringConvertible {
        public let host: String
        public let port: UInt16

        public init(host: String, port: UInt16) {
            self.host = host
            self.port = port
        }

        public var description: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }

        /// The 4 or 16 bytes of `host` (empty only for an Address not made by the parser).
        public var bytes: Data { PairInvite.hostBytes(host) ?? Data() }
    }

    public static let prefix = "pgpony-pair:1?"
    public static let hashBytes = 16
    public static let maxAddresses = 8
    public static let connectTimeout: Double = 3

    public let addresses: [Address]
    /// The first 16 bytes of SHA-256(pk_H), for PairProtocol.join's expectedHostKeyHash.
    public let hostKeyHash: Data

    /// Nil unless there are 1 to 8 well-formed addresses and a 16-byte hash.
    public init?(addresses: [Address], hostKeyHash: Data) {
        guard (1 ... PairInvite.maxAddresses).contains(addresses.count),
              hostKeyHash.count == PairInvite.hashBytes,
              addresses.allSatisfy({ PairInvite.parseAddress($0.description) == $0 })
        else { return nil }
        self.addresses = addresses
        self.hostKeyHash = Data(hostKeyHash)
    }

    /// The invite for a host whose window key is `hostPublicKey`, reachable at `addresses`.
    public static func forHostKey(_ hostPublicKey: Data, addresses: [Address]) -> PairInvite? {
        PairInvite(addresses: addresses, hostKeyHash: PairCrypto.sha256(hostPublicKey).prefix(hashBytes))
    }

    public var uri: String {
        PairInvite.prefix + "a=" + addresses.map(\.description).joined(separator: ",") + "&h=" + PairInvite.base64url(hostKeyHash)
    }

    /// Reads an invite, or nil when `text` is not a well-formed one. Members other than `a` and
    /// `h` are ignored so a later version can add some; a repeated `a` or `h` is refused.
    public static func parse(_ text: String) -> PairInvite? {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        // The scheme matches without regard to ASCII case only, as in the Kotlin core.
        let scalars = Array(t.unicodeScalars)
        let want = Array(prefix.unicodeScalars)
        guard scalars.count >= want.count,
              zip(scalars, want).allSatisfy({ asciiLower($0.0) == $0.1 })
        else { return nil }
        let rest = String(String.UnicodeScalarView(scalars.dropFirst(want.count)))
        var a: String?
        var h: String?
        for part in rest.split(separator: "&", omittingEmptySubsequences: false) {
            guard let eq = part.firstIndex(of: "="), eq != part.startIndex else { return nil }
            let value = String(part[part.index(after: eq)...])
            switch part[..<eq] {
            case "a":
                if a != nil { return nil }
                a = value
            case "h":
                if h != nil { return nil }
                h = value
            default:
                break
            }
        }
        guard let hashText = h, let list = a,
              hashText.count == 22, hashText.unicodeScalars.allSatisfy(isBase64url),
              let hash = base64urlDecode(hashText), hash.count == hashBytes,
              base64url(hash) == hashText // one spelling per hash: the unused low bits must be zero
        else { return nil }
        let parts = list.split(separator: ",", omittingEmptySubsequences: false)
        guard parts.count <= maxAddresses else { return nil }
        var addresses: [Address] = []
        for p in parts {
            guard let address = parseAddress(String(p)) else { return nil }
            addresses.append(address)
        }
        return PairInvite(addresses: addresses, hostKeyHash: hash)
    }

    /// `192.168.1.20:49152` or `[fd00::1]:49152`; nil for anything else, names included.
    public static func parseAddress(_ text: String) -> Address? {
        guard let colon = text.lastIndex(of: ":"), colon != text.startIndex else { return nil }
        let hostPart = String(text[..<colon])
        let portPart = String(text[text.index(after: colon)...])
        guard (1 ... 5).contains(portPart.count), portPart.unicodeScalars.allSatisfy(isDigit),
              portPart.first != "0", let port = Int(portPart), (1 ... 65535).contains(port)
        else { return nil }
        let host: String
        if hostPart.hasPrefix("[") && hostPart.hasSuffix("]") && hostPart.count >= 2 {
            let inner = String(hostPart.dropFirst().dropLast())
            guard inner.contains(":"), ipv6Bytes(inner) != nil else { return nil }
            host = inner.lowercased()
        } else {
            guard ipv4Bytes(hostPart) != nil else { return nil }
            host = hostPart
        }
        return Address(host: host, port: UInt16(port))
    }

    /// The bytes of an IP literal without brackets: 4 for a dotted quad, 16 for IPv6. Nil for
    /// anything else, names and zone ids included.
    public static func hostBytes(_ host: String) -> Data? {
        host.contains(":") ? ipv6Bytes(host) : ipv4Bytes(host)
    }

    /// A dotted quad with no leading zeros.
    static func ipv4Bytes(_ text: String) -> Data? {
        let octets = text.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return nil }
        var out = Data()
        for o in octets {
            guard (1 ... 3).contains(o.count), o.unicodeScalars.allSatisfy(isDigit),
                  !(o.count > 1 && o.first == "0"), let v = Int(o), v <= 255
            else { return nil }
            out.append(UInt8(v))
        }
        return out
    }

    /// An IPv6 literal in the text forms of RFC 4291 section 2.2: eight groups of 1 to 4 hex
    /// digits, or fewer with exactly one `::` standing for at least one zero group, and optionally
    /// a dotted quad as the last 32 bits. No zone, no brackets, no white space.
    static func ipv6Bytes(_ text: String) -> Data? {
        let chars = Array(text.utf8)
        let colon = UInt8(ascii: ":")
        let dot = UInt8(ascii: ".")
        guard (2 ... 45).contains(chars.count),
              chars.allSatisfy({ isHexByte($0) || $0 == colon || $0 == dot })
        else { return nil }
        var gap: Int?
        for i in 0 ..< chars.count - 1 where chars[i] == colon && chars[i + 1] == colon {
            if gap != nil { return nil } // a second `::`, overlapping (`:::`) or not
            gap = i
        }
        let words: [Int]
        if let g = gap {
            guard let head = ipv6Words(Array(chars[0 ..< g]), quadAllowed: false),
                  let tail = ipv6Words(Array(chars[(g + 2)...]), quadAllowed: true),
                  head.count + tail.count <= 7
            else { return nil }
            words = head + Array(repeating: 0, count: 8 - head.count - tail.count) + tail
        } else {
            guard let all = ipv6Words(chars, quadAllowed: true), all.count == 8 else { return nil }
            words = all
        }
        var out = Data()
        for w in words {
            out.append(UInt8(w >> 8))
            out.append(UInt8(w & 0xFF))
        }
        return out
    }

    /// The 16-bit words of one side of `::` (or of a whole address without one).
    private static func ipv6Words(_ part: [UInt8], quadAllowed: Bool) -> [Int]? {
        if part.isEmpty { return [] }
        let groups = part.split(separator: UInt8(ascii: ":"), omittingEmptySubsequences: false)
        var out: [Int] = []
        for (i, g) in groups.enumerated() {
            if g.contains(UInt8(ascii: ".")) {
                guard quadAllowed, i == groups.count - 1,
                      let q = ipv4Bytes(String(decoding: g, as: UTF8.self))
                else { return nil }
                let b = [UInt8](q)
                out.append(Int(b[0]) << 8 | Int(b[1]))
                out.append(Int(b[2]) << 8 | Int(b[3]))
            } else {
                guard (1 ... 4).contains(g.count), let v = Int(String(decoding: g, as: UTF8.self), radix: 16) else { return nil }
                out.append(v)
            }
            if out.count > 8 { return nil }
        }
        return out
    }

    static func asciiLower(_ u: Unicode.Scalar) -> Unicode.Scalar {
        ("A" ... "Z").contains(u) ? Unicode.Scalar(u.value + 32)! : u
    }

    static func isDigit(_ u: Unicode.Scalar) -> Bool { ("0" ... "9").contains(u) }

    static func isHex(_ u: Unicode.Scalar) -> Bool { isDigit(u) || ("a" ... "f").contains(u) || ("A" ... "F").contains(u) }

    static func isHexByte(_ b: UInt8) -> Bool { (48 ... 57).contains(b) || (97 ... 102).contains(b) || (65 ... 70).contains(b) }

    static func isBase64url(_ u: Unicode.Scalar) -> Bool {
        isDigit(u) || ("a" ... "z").contains(u) || ("A" ... "Z").contains(u) || u == "-" || u == "_"
    }

    static func base64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func base64urlDecode(_ text: String) -> Data? {
        var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }
}
