// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// WKDService.swift
// PGPony — v5.0 Phase 3
//
// Web Key Directory (WKD) lookup per draft-koch-openpgp-webkey-service-15.
// Given an email address, computes the canonical WKD URL and fetches the
// public key directly from the user's mail domain. This is preferred over
// keys.openpgp.org because the key is served by the same organization that
// runs the recipient's mail — there is no third-party keyserver in the path.
//
// URL structure:
//   advanced: https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>?l=<localpart>
//   direct:   https://<domain>/.well-known/openpgpkey/hu/<hash>?l=<localpart>
//
// <hash> = zbase32(SHA1(lowercased(localpart)))
//
// The advanced method is tried first; if it fails (DNS, 404, network),
// the direct method is tried as a fallback. The response is binary OpenPGP
// key data — NOT ASCII-armored — so callers must armor before importing.

import Foundation
import CryptoKit

enum WKDError: LocalizedError {
    case invalidEmail
    case notFound
    case networkError(String)
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .invalidEmail:        return "Invalid email address."
        case .notFound:            return "No key found via WKD for this email."
        case .networkError(let m): return "WKD network error: \(m)"
        case .invalidResponse:     return "WKD server returned an invalid response."
        }
    }
}

/// Source of a key returned by lookup — useful for the import preview to show
/// where the key was obtained from, so the user knows how trusted it is.
enum KeyLookupSource: String {
    case wkdAdvanced = "WKD (advanced)"
    case wkdDirect   = "WKD (direct)"
    case hagrid      = "keys.openpgp.org"

    // v5.0 Phase 5.1 — localized display name. Callers should never use
    // rawValue for UI; that's the catalog key, not the translated value.
    // "keys.openpgp.org" stays the same in every language (it's a domain).
    var displayName: String {
        switch self {
        case .wkdAdvanced: return String(localized: "WKD (advanced)")
        case .wkdDirect:   return String(localized: "WKD (direct)")
        case .hagrid:      return String(localized: "keys.openpgp.org")
        }
    }
}

struct WKDLookupResult {
    let armoredKey: String
    let source: KeyLookupSource
}

final class WKDService {

    static let shared = WKDService()

    private let session: URLSession

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 8     // WKD should be fast — short timeout to fall back quickly
        config.timeoutIntervalForResource = 15
        config.requestCachePolicy = .reloadIgnoringLocalCacheData  // never cache key lookups
        self.session = URLSession(configuration: config)
    }

    // =========================================================================
    // MARK: - Public — lookup
    // =========================================================================

    /// Look up a public key by email via Web Key Directory.
    ///
    /// Tries advanced (openpgpkey.<domain>) first, then direct (<domain>).
    /// Returns a result containing the armored key text and which WKD method succeeded.
    /// Throws `WKDError.notFound` if neither method returns a key.
    func lookup(email: String) async throws -> WKDLookupResult {
        guard let (localpart, domain) = parseEmail(email) else {
            throw WKDError.invalidEmail
        }
        let hash = zbase32SHA1(localpart.lowercased())
        let encodedLocalpart = localpart.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? localpart

        // Advanced first
        let advancedURL = "https://openpgpkey.\(domain)/.well-known/openpgpkey/\(domain)/hu/\(hash)?l=\(encodedLocalpart)"
        if let data = await tryFetch(advancedURL), !data.isEmpty {
            let armored = armorBinaryPublicKey(data)
            return WKDLookupResult(armoredKey: armored, source: .wkdAdvanced)
        }

        // Direct fallback
        let directURL = "https://\(domain)/.well-known/openpgpkey/hu/\(hash)?l=\(encodedLocalpart)"
        if let data = await tryFetch(directURL), !data.isEmpty {
            let armored = armorBinaryPublicKey(data)
            return WKDLookupResult(armoredKey: armored, source: .wkdDirect)
        }

        throw WKDError.notFound
    }

    // =========================================================================
    // MARK: - Internals
    // =========================================================================

    /// Parse an email address into (localpart, domain). Returns nil if malformed.
    /// Domain is lowercased; localpart is preserved exactly so that the `l=` query
    /// parameter is sent in the form the user typed it.
    private func parseEmail(_ email: String) -> (String, String)? {
        let trimmed = email.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: "@", maxSplits: 1).map(String.init)
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else { return nil }
        // Sanity: domain must contain at least one dot
        guard parts[1].contains(".") else { return nil }
        return (parts[0], parts[1].lowercased())
    }

    /// Try to fetch from a URL. Returns nil on any error (so caller can fall back).
    private func tryFetch(_ urlString: String) async -> Data? {
        guard let url = URL(string: urlString) else { return nil }
        var request = URLRequest(url: url)
        request.setValue("application/octet-stream", forHTTPHeaderField: "Accept")
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                return nil
            }
            return data
        } catch {
            return nil
        }
    }

    /// Armor binary OpenPGP public-key data so existing importArmoredKey() works.
    private func armorBinaryPublicKey(_ data: Data) -> String {
        // Construct standard ASCII armor by hand to avoid pulling ObjectivePGP into this service.
        // RFC 4880 §6.2: -----BEGIN PGP PUBLIC KEY BLOCK-----, base64 in 64-char lines,
        // a 24-bit CRC line prefixed with '=', then END marker.
        let base64 = data.base64EncodedString()
        var lines: [String] = []
        lines.append("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        lines.append("")
        // Wrap base64 at 64 chars per line
        var i = base64.startIndex
        while i < base64.endIndex {
            let next = base64.index(i, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
            lines.append(String(base64[i..<next]))
            i = next
        }
        // CRC24 per RFC 4880 §6.1
        let crc = crc24(Array(data))
        let crcBytes: [UInt8] = [
            UInt8((crc >> 16) & 0xFF),
            UInt8((crc >>  8) & 0xFF),
            UInt8( crc        & 0xFF)
        ]
        lines.append("=" + Data(crcBytes).base64EncodedString())
        lines.append("-----END PGP PUBLIC KEY BLOCK-----")
        return lines.joined(separator: "\n") + "\n"
    }

    /// CRC-24 from RFC 4880 §6.1. Initial value 0xB704CE, polynomial 0x1864CFB.
    private func crc24(_ bytes: [UInt8]) -> UInt32 {
        var crc: UInt32 = 0xB704CE
        for byte in bytes {
            crc ^= UInt32(byte) << 16
            for _ in 0..<8 {
                crc <<= 1
                if (crc & 0x1000000) != 0 {
                    crc ^= 0x1864CFB
                }
            }
        }
        return crc & 0xFFFFFF
    }

    // -------------------------------------------------------------------------
    // MARK: - z-base32 encoding
    // -------------------------------------------------------------------------

    /// z-base32 alphabet from draft-koch-openpgp-webkey-service §3.1.
    /// Note: this is NOT standard RFC 4648 base32 — the alphabet is different.
    private let zbase32Alphabet: [Character] = Array("ybndrfg8ejkmcpqxot1uwisza345h769")

    /// Compute the WKD localpart hash: zbase32(SHA1(lowercased(localpart))).
    /// The lowercased step is required by the WKD spec to make lookups case-insensitive.
    private func zbase32SHA1(_ localpart: String) -> String {
        let data = Data(localpart.utf8)
        // NOTE: SHA-1 here is REQUIRED by the Web Key Directory spec
        // (draft-koch-openpgp-webkey-service §3.1) — it's how the localpart hash is
        // defined, not a security choice. It's a non-cryptographic identifier hash,
        // not used for authentication or integrity. `Insecure.SHA1` is just CryptoKit's
        // name for the primitive; this usage is correct and interoperable.
        let sha = Insecure.SHA1.hash(data: data)
        return zbase32Encode(Array(sha))
    }

    /// Encode bytes as z-base32. The encoder packs 8-bit input into 5-bit groups,
    /// big-endian, and looks up each group in the z-base32 alphabet. The final
    /// group is padded with zero bits if the input length isn't a multiple of 5 bits.
    /// Output is unpadded (no trailing '=' chars).
    private func zbase32Encode(_ bytes: [UInt8]) -> String {
        var output = ""
        var buffer: UInt64 = 0
        var bitsInBuffer: Int = 0
        for byte in bytes {
            buffer = (buffer << 8) | UInt64(byte)
            bitsInBuffer += 8
            while bitsInBuffer >= 5 {
                bitsInBuffer -= 5
                let idx = Int((buffer >> UInt64(bitsInBuffer)) & 0x1F)
                output.append(zbase32Alphabet[idx])
            }
        }
        if bitsInBuffer > 0 {
            let idx = Int((buffer << UInt64(5 - bitsInBuffer)) & 0x1F)
            output.append(zbase32Alphabet[idx])
        }
        return output
    }
}
