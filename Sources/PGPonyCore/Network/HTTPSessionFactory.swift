// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// HTTPSessionFactory.swift
// PGPony
//
// v8.0.0 Phase C — one place that builds the app's outbound HTTP(S) sessions,
// so keyserver and WKD traffic share the same proxy configuration.
//
// Proxy: off, or a custom SOCKS host:port applied via
// `connectionProxyDictionary`. Platform reality (per the plan): on iOS, Orbot
// runs as a system-wide VPN, so in-app Tor routing is an ADVANCED setting, not
// an Orbot integration. When a proxy is configured we ALWAYS route through it —
// there is no silent direct fallback, so a configured-but-unreachable proxy
// fails the request (fail closed) rather than leaking clearnet.
//
// Onion: when the proxy is active and the onion option is on, keyserver traffic
// can target a server's .onion mirror (see KeyServerService), where the onion
// layer is the transport crypto (no TLS needed).

import Foundation

enum HTTPSessionFactory {

    // MARK: - Proxy settings (advanced) — UserDefaults-backed

    enum Keys {
        static let proxyEnabled    = "pgpony_proxy_enabled"
        static let proxyHost       = "pgpony_proxy_host"
        static let proxyPort       = "pgpony_proxy_port"
        static let onionUnderProxy = "pgpony_proxy_onion"
    }

    static var proxyEnabled: Bool {
        UserDefaults.standard.bool(forKey: Keys.proxyEnabled)
    }
    static var proxyHost: String {
        (UserDefaults.standard.string(forKey: Keys.proxyHost) ?? "").trimmingCharacters(in: .whitespaces)
    }
    static var proxyPort: Int {
        let p = UserDefaults.standard.integer(forKey: Keys.proxyPort)
        return p > 0 ? p : 9050   // Tor/Orbot SOCKS default
    }
    /// Default ON: if you've gone to the trouble of routing through a proxy,
    /// prefer the onion mirror for a server that has one.
    static var onionUnderProxy: Bool {
        UserDefaults.standard.object(forKey: Keys.onionUnderProxy) as? Bool ?? true
    }

    /// True when a usable proxy is configured. All proxied requests fail closed.
    static var proxyActive: Bool {
        proxyEnabled && !proxyHost.isEmpty
    }

    // MARK: - Session

    /// Build a fresh `URLSession` honoring the current proxy settings.
    /// - Parameters:
    ///   - requestTimeout / resourceTimeout: per-purpose timeouts (WKD is short).
    ///   - noCache: never cache (key lookups must be live).
    ///   - minTLS13: require TLS 1.3 (keyservers support it; WKD hits arbitrary
    ///     domains and must NOT force it, or 1.2-only hosts break).
    static func makeSession(
        requestTimeout: TimeInterval = 15,
        resourceTimeout: TimeInterval = 30,
        noCache: Bool = false,
        minTLS13: Bool = false
    ) -> URLSession {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = requestTimeout
        config.timeoutIntervalForResource = resourceTimeout
        if noCache { config.requestCachePolicy = .reloadIgnoringLocalCacheData }
        if minTLS13 { config.tlsMinimumSupportedProtocolVersion = .TLSv13 }
        if proxyActive {
            config.connectionProxyDictionary = socksProxyDictionary()
        }
        // Offline mode: a single blocking interceptor on every session the app
        // builds, so no code path (foreground, background refresh, or the share
        // extension) can reach the network while it is on. It fails each request
        // before a socket is opened. See `OfflineMode` below.
        config.protocolClasses = [OfflineBlockingURLProtocol.self] + (config.protocolClasses ?? [])
        return URLSession(configuration: config)
    }

    /// SOCKS proxy dictionary for `connectionProxyDictionary`.
    ///
    /// The `kCFNetworkProxiesSOCKS*` symbols are macOS-only (marked unavailable
    /// in iOS), so we use the underlying CFNetwork dictionary key strings those
    /// symbols alias — "SOCKSEnable" / "SOCKSProxy" / "SOCKSPort". This is the
    /// standard workaround used by Tor-integrated iOS apps; SOCKS via
    /// `connectionProxyDictionary` is best-effort on iOS (consistent with this
    /// being an advanced, opt-in setting), and we still fail closed.
    static func socksProxyDictionary() -> [AnyHashable: Any] {
        [
            "SOCKSEnable": 1,
            "SOCKSProxy": proxyHost,
            "SOCKSPort": proxyPort,
        ]
    }
}


// MARK: - Offline mode

/// A single switch that takes the whole app off the network.
///
/// Ported from PGPony Android (4.4.0). One persisted flag, off by default,
/// stored in the App Group suite so every process — the app, its background
/// refresh worker, and the share extension — reads the same value. Enforcement
/// is centralized: `HTTPSessionFactory` installs `OfflineBlockingURLProtocol`
/// on every session it builds, so a request fails immediately, before a socket
/// is opened, rather than attempting a connection and timing out.
enum OfflineMode {

    /// Shared with the extension; matches `KeychainService.sharedAccessGroup`.
    static let appGroup = "group.com.pgpony.shared"

    /// The persisted flag's key. Bound directly from Settings via @AppStorage.
    static let key = "pgpony_offline_mode"

    /// The App Group defaults suite, so the flag is one value across processes.
    static var store: UserDefaults {
        UserDefaults(suiteName: appGroup) ?? .standard
    }

    /// Off by default: an existing user's connectivity does not change on update.
    nonisolated static var isOn: Bool {
        get { store.bool(forKey: key) }
        set { store.set(newValue, forKey: key) }
    }

    struct OfflineError: LocalizedError {
        var errorDescription: String? {
            String(localized: "Offline mode is on, so PGPony isn't making any network requests. Turn it off in Settings under Security to look up or publish keys online.")
        }
    }

    /// Fail fast with a clear message at a network entry point. The URLProtocol
    /// below is the actual guarantee; this just produces a nicer error than a
    /// generic request failure when a caller checks up front.
    static func requireOnline() throws {
        if isOn { throw OfflineError() }
    }
}

/// The choke point. Installed on every session `HTTPSessionFactory` builds; when
/// offline mode is on it claims every request and fails it in `startLoading`
/// without opening a connection.
final class OfflineBlockingURLProtocol: URLProtocol {

    override class func canInit(with request: URLRequest) -> Bool {
        // Only intercept while offline; otherwise requests proceed normally.
        OfflineMode.isOn
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        client?.urlProtocol(self, didFailWithError: OfflineMode.OfflineError())
    }

    override func stopLoading() {}
}
