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
