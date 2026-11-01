// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// PairPeer.swift
// Which connections a pairing host lets through to phase 1 (docs/PAIRING_PROTOCOL.md, section 1).
// The listener answers on every interface, so the host checks where each connection comes from
// and closes one from outside the local network before reading a byte; such a connection does
// not use up the window. Rule for rule as the Kotlin core's PairPeer.

import Foundation
#if canImport(Darwin)
import Darwin
#endif

public enum PairPeer {

    /// A local network: an interface address and its prefix length.
    public struct Subnet: Equatable, Sendable {
        public let address: Data
        public let prefixLength: Int

        /// Nil unless `address` is 4 or 16 bytes and `prefixLength` fits it.
        public init?(address: Data, prefixLength: Int) {
            guard address.count == 4 || address.count == 16, (0 ... address.count * 8).contains(prefixLength) else { return nil }
            self.address = Data(address)
            self.prefixLength = prefixLength
        }

        /// Whether `peer` (4 or 16 bytes) is in this subnet.
        public func contains(_ peer: Data) -> Bool {
            peer.count == address.count && PairPeer.prefixEquals([UInt8](peer), [UInt8](address), prefixLength)
        }
    }

    /// True when a connection from `peer` (the 4 or 16 bytes of its address) may run phase 1:
    /// loopback, link-local, RFC 1918, unique-local IPv6, or inside one of `subnets` (the host's
    /// own addresses with their prefix lengths). An IPv4-mapped IPv6 address is judged as the
    /// IPv4 address it carries.
    public static func isAllowed(_ peer: Data, subnets: [Subnet] = []) -> Bool {
        guard let a = unmapped(peer) else { return false }
        if isLocalRange(a) { return true }
        return subnets.contains { $0.contains(a) }
    }

    /// The ranges that are local whatever the host's own addresses are.
    public static func isLocalRange(_ peer: Data) -> Bool {
        guard let a = unmapped(peer) else { return false }
        let b = [UInt8](a)
        if b.count == 4 {
            return b[0] == 127 ||                                // 127.0.0.0/8 loopback
                b[0] == 10 ||                                    // 10.0.0.0/8
                (b[0] == 172 && (16 ... 31).contains(b[1])) ||   // 172.16.0.0/12
                (b[0] == 192 && b[1] == 168) ||                  // 192.168.0.0/16
                (b[0] == 169 && b[1] == 254)                     // 169.254.0.0/16 link-local
        }
        return b == loopback6 ||                                 // ::1
            (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) ||           // fe80::/10 link-local
            (b[0] & 0xFE) == 0xFC                                // fc00::/7 unique local
    }

    /// 4 bytes for IPv4 and for an IPv4-mapped IPv6 address, 16 for other IPv6, nil otherwise.
    static func unmapped(_ peer: Data) -> Data? {
        let b = [UInt8](peer)
        switch b.count {
        case 4:
            return Data(b)
        case 16:
            return Array(b[0 ..< 12]) == mappedPrefix ? Data(b[12 ..< 16]) : Data(b)
        default:
            return nil
        }
    }

    static func prefixEquals(_ a: [UInt8], _ b: [UInt8], _ bits: Int) -> Bool {
        let whole = bits / 8
        for i in 0 ..< whole where a[i] != b[i] { return false }
        let rest = bits % 8
        if rest == 0 { return true }
        let mask = UInt8(truncatingIfNeeded: 0xFF << (8 - rest))
        return (a[whole] & mask) == (b[whole] & mask)
    }

    static let loopback6: [UInt8] = Array(repeating: 0, count: 15) + [1]
    static let mappedPrefix: [UInt8] = Array(repeating: 0, count: 10) + [0xFF, 0xFF]

    #if canImport(Darwin)
    /// The subnets of this device's own interfaces that are up, leaving out loopback,
    /// point-to-point links (VPN tunnels) and cellular data (`pdp_ip`).
    public static func interfaceSubnets() -> [Subnet] {
        var out: [Subnet] = []
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return [] }
        defer { freeifaddrs(list) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            let ifa = entry.pointee
            cursor = ifa.ifa_next
            let flags = Int32(bitPattern: ifa.ifa_flags)
            let name = String(cString: ifa.ifa_name)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0, flags & IFF_POINTOPOINT == 0,
                  !name.hasPrefix("pdp_ip"), let addr = ifa.ifa_addr, let mask = ifa.ifa_netmask
            else { continue }
            switch Int32(addr.pointee.sa_family) {
            case AF_INET:
                let a = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { p in withUnsafeBytes(of: p.pointee.sin_addr) { Data($0) } }
                let m = mask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { p in withUnsafeBytes(of: p.pointee.sin_addr) { Data($0) } }
                if let s = Subnet(address: a, prefixLength: prefixLength(of: m)) { out.append(s) }
            case AF_INET6:
                let a = addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { p in withUnsafeBytes(of: p.pointee.sin6_addr) { Data($0) } }
                let m = mask.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { p in withUnsafeBytes(of: p.pointee.sin6_addr) { Data($0) } }
                if let s = Subnet(address: a, prefixLength: prefixLength(of: m)) { out.append(s) }
            default:
                break
            }
        }
        return out
    }

    /// The number of one bits in a netmask.
    static func prefixLength(of mask: Data) -> Int {
        mask.reduce(0) { $0 + $1.nonzeroBitCount }
    }
    #endif
}
