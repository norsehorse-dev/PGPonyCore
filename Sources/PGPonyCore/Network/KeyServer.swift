// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// KeyServer.swift
// PGPony
//
// v8.0.0 Phase C — the multi-keyserver model.
//
// Replaces the single hardcoded keys.openpgp.org assumption with an ordered,
// user-toggleable list. v1 ships exactly two built-in entries:
//
//   1. keys.openpgp.org — default LOOKUP priority (network effect: most keys
//      live there today) and a publish target.
//   2. keys.pgpony.app  — default PUBLISH target. Lookup is OFF by default
//      because the server is new and nearly empty; a lookup there would feel
//      broken. The user can enable it once it fills.
//
// Custom user servers are a stretch goal (not in v1) — two good defaults cover
// ~99% of users and avoid the HKP-compat support burden.
//
// Both servers speak the keys.openpgp.org VKS JSON API, so KeyServerService
// keeps ONE client for both (see keys.pgpony.app's /vks/v1/upload parity).

import Foundation

struct KeyServer: Codable, Identifiable, Equatable {
    var id: UUID
    var name: String            // display + user-facing host label
    var host: String            // clearnet authority, e.g. "keys.openpgp.org"
    var onionHost: String?      // onion authority (no scheme), used under proxy
    var isEnabled: Bool         // master on/off
    var isLookup: Bool          // participates in key lookup
    var isPublish: Bool         // a publish target
    var order: Int              // lookup/publish priority (lower first)
    var isBuiltIn: Bool         // the two defaults: toggle/reorder only, no delete
    // 8.3.0 (planning 6.2): a custom server keeps the scheme and port the
    // user gave (hkp:// maps to http on 11371). Nil on the built-ins and on
    // every entry saved before 8.3.0, which decode as https with no port.
    var scheme: String? = nil
    var port: Int? = nil

    /// Clearnet base, e.g. "https://keys.openpgp.org" or "http://hkp.example:11371".
    var baseURL: String {
        let s = scheme ?? "https"
        if let port { return "\(s)://\(host):\(port)" }
        return "\(s)://\(host)"
    }

    /// Where the entry came from, for a footer line.
    var isCustom: Bool { !isBuiltIn }

    /// True when this server is known to likely reject the given key algorithm,
    /// so the publish UI can warn before uploading (and explain a failure).
    /// Conservative: only keys.openpgp.org is flagged — it's the IETF/RFC-9580
    /// verified-email model with no post-quantum or LibrePGP support, and its
    /// acceptance of the newer v6 packet format is unconfirmed. Reliable there:
    /// RSA and v4 Ed25519+Cv25519. First-party (keys.pgpony.app) and any
    /// user-added server are never flagged — we let the upload result speak.
    func mayNotAccept(_ algorithm: KeyAlgorithm) -> Bool {
        guard host == "keys.openpgp.org" else { return false }
        switch algorithm {
        case .rsa2048, .rsa3072, .rsa4096, .rsa8192, .ed25519:
            return false
        default:
            return true   // v6, PQC (ML-KEM), LibrePGP: unconfirmed / unsupported
        }
    }
}

// MARK: - Built-in servers (stable IDs so persisted state maps across launches)

extension KeyServer {

    static let pgpOrgStableID = UUID(uuidString: "A0000000-0000-4000-8000-000000000001")!
    static let pgponyStableID = UUID(uuidString: "A0000000-0000-4000-8000-000000000002")!

    /// keys.openpgp.org — Hagrid, verified-email model. Has a well-known onion.
    static let openPGPOrg = KeyServer(
        id: pgpOrgStableID,
        name: "keys.openpgp.org",
        host: "keys.openpgp.org",
        onionHost: "zkaan2xfbuxia2wpf7ofnkbz6r5zdbbvxbunvp5g2iebopbfc4iqmbad.onion",
        isEnabled: true,
        isLookup: true,
        isPublish: true,
        order: 0,
        isBuiltIn: true
    )

    /// keys.pgpony.app — first-party, VKS-parity, reachable over the PGPony onion.
    static let pgpony = KeyServer(
        id: pgponyStableID,
        name: "keys.pgpony.app",
        host: "keys.pgpony.app",
        onionHost: "pgponyisur7gxcrfw5ofpjr2sepqul3zgbs66rrd3ughk5qvi4a3t5id.onion",
        isEnabled: true,
        isLookup: false,   // lookup off until it fills — honesty constraint
        isPublish: true,
        order: 1,
        isBuiltIn: true
    )
}

// MARK: - Registry (UserDefaults-backed)

/// Loads/saves the keyserver list. Plain UserDefaults access (thread-safe), so
/// both the async network layer (KeyServerService) and the SwiftUI settings
/// screen can read/write it without actor friction.
enum KeyServerRegistry {

    static let storageKey = "pgpony_keyservers_v1"

    /// The factory list, used on first launch and as a repair fallback.
    static var defaults: [KeyServer] { [.openPGPOrg, .pgpony] }

    /// Current list, order-sorted. Seeds defaults on first run, and repairs a
    /// list that somehow lost a built-in (schema evolution safety).
    static func load() -> [KeyServer] {
        guard let data = UserDefaults.standard.data(forKey: storageKey),
              var list = try? JSONDecoder().decode([KeyServer].self, from: data),
              !list.isEmpty else {
            return defaults
        }
        // Ensure both built-ins survive even if a future migration dropped one.
        for builtIn in defaults where !list.contains(where: { $0.id == builtIn.id }) {
            list.append(builtIn)
        }
        return list.sorted { $0.order < $1.order }
    }

    static func save(_ servers: [KeyServer]) {
        var normalized = servers
        for i in normalized.indices { normalized[i].order = i }
        if let data = try? JSONEncoder().encode(normalized) {
            UserDefaults.standard.set(data, forKey: storageKey)
        }
    }

    /// Enabled lookup servers in priority order.
    static func lookupServers() -> [KeyServer] {
        load().filter { $0.isEnabled && $0.isLookup }.sorted { $0.order < $1.order }
    }

    /// All enabled servers in priority order, regardless of lookup/publish role.
    /// Used by refresh so a revocation propagates no matter which server carries
    /// it — including publish-only servers like keys.pgpony.app that are not in
    /// the lookup set.
    static func enabledServers() -> [KeyServer] {
        load().filter { $0.isEnabled }.sorted { $0.order < $1.order }
    }

    /// Enabled publish targets in priority order.
    static func publishServers() -> [KeyServer] {
        load().filter { $0.isEnabled && $0.isPublish }.sorted { $0.order < $1.order }
    }

    /// Reset to the two factory defaults.
    static func resetToDefaults() {
        save(defaults)
    }

    // MARK: - Custom servers (8.3.0, planning 6.2)

    struct NormalizedServer: Equatable {
        let scheme: String
        let host: String
        let port: Int?
    }

    /// The pure normalizer behind the Add Key Server form. Accepts a bare
    /// host, scheme://host and scheme://host:port; maps hkps:// to https and
    /// hkp:// to http on 11371; keeps http and https with an optional port;
    /// rejects any other scheme, a path or query, credentials, and a dotless
    /// host without an explicit port (a bare word is a typo more often than a
    /// LAN name). Returns nil for anything it will not take.
    static func normalize(_ input: String) -> NormalizedServer? {
        var text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, !text.contains(" ") else { return nil }
        var scheme = "https"
        var impliedPort: Int? = nil
        if let range = text.range(of: "://") {
            let given = text[..<range.lowerBound].lowercased()
            switch given {
            case "https", "hkps": scheme = "https"
            case "http": scheme = "http"
            case "hkp": scheme = "http"; impliedPort = 11371
            default: return nil
            }
            text = String(text[range.upperBound...])
        }
        if text.hasSuffix("/") { text.removeLast() }
        guard !text.isEmpty, !text.contains("/"), !text.contains("?"), !text.contains("@"), !text.contains("#") else { return nil }
        var host = text
        var port: Int? = impliedPort
        if let colon = text.lastIndex(of: ":") {
            let portText = text[text.index(after: colon)...]
            guard let p = Int(portText), (1...65535).contains(p) else { return nil }
            port = p
            host = String(text[..<colon])
        }
        host = host.lowercased()
        guard !host.isEmpty, !host.hasPrefix("."), !host.hasSuffix("."), !host.contains(":") else { return nil }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-.")
        guard host.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return nil }
        if !host.contains("."), port == nil { return nil }
        if scheme == "https", port == 443 { port = nil }
        if scheme == "http", port == 80 { port = nil }
        return NormalizedServer(scheme: scheme, host: host, port: port)
    }

    /// Add a custom server at the end of the list. Returns nil when the URL
    /// does not normalize or the host is already listed.
    @discardableResult
    static func addCustom(name: String, url: String) -> KeyServer? {
        guard let n = normalize(url) else { return nil }
        var list = load()
        guard !list.contains(where: { $0.host == n.host && $0.port == n.port }) else { return nil }
        let label = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let server = KeyServer(
            id: UUID(),
            name: label.isEmpty ? n.host : label,
            host: n.host,
            onionHost: nil,
            isEnabled: true,
            isLookup: true,
            isPublish: true,
            order: list.count,
            isBuiltIn: false,
            scheme: n.scheme,
            port: n.port
        )
        list.append(server)
        save(list)
        return server
    }

    /// Remove a custom server; the built-ins cannot be removed.
    static func removeCustom(id: UUID) {
        let list = load().filter { $0.id != id || $0.isBuiltIn }
        save(list)
    }
}
