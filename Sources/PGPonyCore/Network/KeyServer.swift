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

    /// Clearnet base, e.g. "https://keys.openpgp.org".
    var baseURL: String { "https://\(host)" }

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
        case .rsa2048, .rsa4096, .ed25519:
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
}
