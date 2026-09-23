// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// KeyServerService.swift
// PGPony
//
// VKS JSON client for keyservers (keys.openpgp.org / Hagrid protocol).
// Searching by email and fingerprint, upload, and email-verification requests.
//
// v8.0.0 Phase C — parameterized by `KeyServer` so the ONE VKS client serves
// every enabled server (keys.openpgp.org, keys.pgpony.app, …). Networking flows
// through `HTTPSessionFactory`, so proxy/onion settings apply uniformly. All the
// original single-server entry points are preserved as thin wrappers that default
// to keys.openpgp.org (zero behavior change for existing call sites).

import Foundation

enum KeyServerError: LocalizedError {
    case searchFailed(String)
    case downloadFailed(String)
    case uploadFailed(String)
    case networkError(String)
    case noResults
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .searchFailed(let msg): return String(localized: "Key server search failed: \(msg)")
        case .downloadFailed(let msg): return String(localized: "Key download failed: \(msg)")
        case .uploadFailed(let msg): return String(localized: "Key upload failed: \(msg)")
        case .networkError(let msg): return String(localized: "Network error: \(msg)")
        case .noResults: return String(localized: "No Key Found")
        case .invalidResponse: return String(localized: "Invalid response from key server")
        }
    }
}

struct KeyServerResult: Identifiable {
    let id = UUID()
    let fingerprint: String
    let userID: String
    let creationDate: Date?
    let algorithm: String?
    let keyBits: Int?
}

class KeyServerService {
    static let shared = KeyServerService()

    private init() {}

    // MARK: - Session & base URL

    /// Fresh session honoring current proxy settings. Keyservers all support
    /// TLS 1.3, so we require it (WKD does not — see WKDService).
    private func session() -> URLSession {
        HTTPSessionFactory.makeSession(requestTimeout: 15, resourceTimeout: 30, minTLS13: true)
    }

    /// Authority to use for a given server. Under an active proxy with the onion
    /// option on, we target the server's .onion mirror when it has one (the onion
    /// layer is the transport crypto, so it's plain http://). Otherwise clearnet
    /// https://.
    private func baseURL(for server: KeyServer) -> String {
        if HTTPSessionFactory.proxyActive,
           HTTPSessionFactory.onionUnderProxy,
           let onion = server.onionHost, !onion.isEmpty {
            return "http://\(onion)"
        }
        return server.baseURL
    }

    // MARK: - 8.3.0 (planning 6.2): custom servers, HKP and sanitized errors

    /// "<host>: check your connection" in place of URLSession's description,
    /// which names internal error domains and codes.
    private func connectionError(_ error: Error, on server: KeyServer) -> KeyServerError {
        if let e = error as? KeyServerError { return e }
        if let proxy = error as? HTTPSessionFactory.ProxyUnreachable {
            return .networkError(proxy.localizedDescription)
        }
        if (error as? URLError)?.code == .dataLengthExceedsMaximum {
            return .networkError(String(localized: "\(server.host) sent more data than a key can hold"))
        }
        return .networkError(String(localized: "\(server.host): check your connection"))
    }

    /// True for the transport failures that mean the request never got an
    /// answer, as opposed to an answer we did not like.
    private func isConnectionFailure(_ error: Error) -> Bool {
        if error is KeyServerError || error is HTTPSessionFactory.ProxyUnreachable { return false }
        let ns = error as NSError
        return ns.domain == NSURLErrorDomain
    }

    /// HKP lookup (RFC 4880 draft-shaw-openpgp-hkp): GET /pks/lookup with
    /// op=get and options=mr; the body is the armored key.
    func hkpLookup(_ query: String, on server: KeyServer) async throws -> String {
        try OfflineMode.requireOnline()
        let search = query.hasPrefix("0x") || query.contains("@") ? query : "0x" + query
        let encoded = search.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? search
        guard let url = URL(string: "\(baseURL(for: server))/pks/lookup?op=get&options=mr&search=\(encoded)") else {
            throw KeyServerError.searchFailed("Invalid URL")
        }
        do {
            let (data, response) = try await HTTPSessionFactory.boundedData(session(), from: url)
            guard let http = response as? HTTPURLResponse else { throw KeyServerError.invalidResponse }
            switch http.statusCode {
            case 200:
                guard let armored = String(data: data, encoding: .utf8),
                      armored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") else {
                    throw KeyServerError.noResults
                }
                return armored
            case 404:
                throw KeyServerError.noResults
            default:
                throw KeyServerError.searchFailed("Server returned status \(http.statusCode)")
            }
        } catch {
            throw connectionError(error, on: server)
        }
    }

    /// HKP add: POST /pks/add with keytext=<armored>. One retry on a dropped
    /// connection (Android RC5). No verification tokens exist on HKP, so the
    /// outcome reports nothing to verify.
    func hkpAdd(_ armoredKey: String, on server: KeyServer) async throws -> UploadVerifyOutcome {
        try OfflineMode.requireOnline()
        guard let url = URL(string: "\(baseURL(for: server))/pks/add") else {
            throw KeyServerError.uploadFailed("Invalid URL")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._*")
        let encoded = armoredKey.addingPercentEncoding(withAllowedCharacters: allowed)?
            .replacingOccurrences(of: "%20", with: "+") ?? armoredKey
        request.httpBody = Data("keytext=\(encoded)".utf8)
        var lastError: Error?
        for attempt in 0..<2 {
            do {
                let (data, response) = try await HTTPSessionFactory.boundedData(session(), for: request)
                guard let http = response as? HTTPURLResponse else { throw KeyServerError.invalidResponse }
                guard (200...299).contains(http.statusCode) else {
                    throw KeyServerError.uploadFailed(Self.uploadFailureText(status: http.statusCode, body: data))
                }
                return UploadVerifyOutcome(verificationRequested: [], verificationFailed: [], hadUnverified: false)
            } catch {
                lastError = error
                if attempt == 0, isConnectionFailure(error) { continue }
                throw connectionError(error, on: server)
            }
        }
        throw connectionError(lastError ?? KeyServerError.invalidResponse, on: server)
    }

    // MARK: - Search by Email (per-server)

    /// Search for a public key by email address on a specific server.
    func searchByEmail(_ email: String, on server: KeyServer) async throws -> String {
        try OfflineMode.requireOnline()
        let encodedEmail = email.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? email
        let urlString = "\(baseURL(for: server))/vks/v1/by-email/\(encodedEmail)"

        guard let url = URL(string: urlString) else {
            throw KeyServerError.searchFailed("Invalid URL")
        }

        do {
            let (data, response) = try await HTTPSessionFactory.boundedData(session(), from: url)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw KeyServerError.invalidResponse
            }

            switch httpResponse.statusCode {
            case 200:
                guard let armoredKey = String(data: data, encoding: .utf8) else {
                    throw KeyServerError.invalidResponse
                }
                return armoredKey
            case 404:
                throw KeyServerError.noResults
            default:
                throw KeyServerError.searchFailed("Server returned status \(httpResponse.statusCode)")
            }
        } catch let error as KeyServerError {
            // 8.3.0 (6.2): a custom server may speak HKP only.
            if server.isCustom, case .noResults = error {
                return try await hkpLookup(email, on: server)
            }
            throw error
        } catch {
            if server.isCustom, isConnectionFailure(error) {
                return try await hkpLookup(email, on: server)
            }
            throw connectionError(error, on: server)
        }
    }

    // MARK: - Search by Fingerprint (per-server)

    /// Search for a public key by fingerprint or key ID on a specific server.
    /// keys.openpgp.org accepts a full 40-char fingerprint via /by-fingerprint/
    /// or a 16-char key ID via /by-keyid/. v5.0 Phase 3: we now accept both,
    /// dispatch to the right endpoint, and give a clear error for inputs that
    /// are too short to be either.
    func searchByFingerprint(_ fingerprint: String, on server: KeyServer) async throws -> String {
        try OfflineMode.requireOnline()
        let cleanFingerprint = fingerprint
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "0x", with: "", options: .caseInsensitive)
            .uppercased()

        // Validate length and pick the right endpoint.
        // - 40 hex chars: v4 fingerprint  → /by-fingerprint/
        // - 64 hex chars: v6 fingerprint  → /by-fingerprint/
        // - 16 hex chars: long key ID     → /by-keyid/
        // - anything else: reject before going to the network.
        let endpoint: String
        switch cleanFingerprint.count {
        case 40, 64:
            endpoint = "by-fingerprint"
        case 16:
            endpoint = "by-keyid"
        default:
            throw KeyServerError.searchFailed(
                "Need a full fingerprint (40 hex characters) or a 16-character key ID. \"\(fingerprint)\" is \(cleanFingerprint.count) characters."
            )
        }

        // Reject non-hex input early so we don't get a server 400.
        guard cleanFingerprint.allSatisfy({ $0.isHexDigit }) else {
            throw KeyServerError.searchFailed("Fingerprint must contain only hexadecimal characters (0-9, A-F).")
        }

        let urlString = "\(baseURL(for: server))/vks/v1/\(endpoint)/\(cleanFingerprint)"

        guard let url = URL(string: urlString) else {
            throw KeyServerError.searchFailed("Invalid URL")
        }

        do {
            let (data, response) = try await HTTPSessionFactory.boundedData(session(), from: url)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw KeyServerError.invalidResponse
            }

            switch httpResponse.statusCode {
            case 200:
                guard let armoredKey = String(data: data, encoding: .utf8) else {
                    throw KeyServerError.invalidResponse
                }
                return armoredKey
            case 404:
                throw KeyServerError.noResults
            default:
                throw KeyServerError.searchFailed("Server returned status \(httpResponse.statusCode)")
            }
        } catch let error as KeyServerError {
            // 8.3.0 (6.2): a custom server may speak HKP only.
            if server.isCustom, case .noResults = error {
                return try await hkpLookup(cleanFingerprint, on: server)
            }
            throw error
        } catch {
            if server.isCustom, isConnectionFailure(error) {
                return try await hkpLookup(cleanFingerprint, on: server)
            }
            throw connectionError(error, on: server)
        }
    }

    // MARK: - Upload Public Key (per-server)

    /// Upload a public key to a specific server.
    /// Returns a verification token/status (user must verify their email).
    ///
    /// The Hagrid VKS v1 upload endpoint expects a JSON body, not a form-encoded
    /// one — sending application/x-www-form-urlencoded triggers a 400 response
    /// with the body "expected application/json data".
    /// See https://keys.openpgp.org/about/api for the full spec. keys.pgpony.app
    /// mirrors this endpoint (see OI4b).
    func uploadPublicKey(_ armoredKey: String, to server: KeyServer) async throws -> UploadResult {
        let urlString = "\(baseURL(for: server))/vks/v1/upload"

        guard let url = URL(string: urlString) else {
            throw KeyServerError.uploadFailed("Invalid URL")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        // VKS v1: { "keytext": "<armored key>" }
        let body: [String: Any] = ["keytext": armoredKey]
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        } catch {
            throw KeyServerError.uploadFailed("Could not encode request body: \(error.localizedDescription)")
        }

        do {
            let (data, response) = try await HTTPSessionFactory.boundedData(session(), for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw KeyServerError.invalidResponse
            }

            guard httpResponse.statusCode == 200 else {
                throw KeyServerError.uploadFailed(Self.uploadFailureText(status: httpResponse.statusCode, body: data))
            }

            // Parse JSON response. Hagrid returns:
            //   { "key_fpr": "<hex>", "token": "<opaque>",
            //     "status": { "user@example.com": "unpublished" | "pending"
            //                                    | "revoked"     | "published" } }
            // "unpublished" emails are the ones we need to ask Hagrid to email
            // a verification link to via requestVerification(token:email:).
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let token = json["token"] as? String else {
                throw KeyServerError.invalidResponse
            }

            var unpublishedEmails: [String] = []
            let statusDict = (json["status"] as? [String: String]) ?? [:]
            for (email, emailStatus) in statusDict where emailStatus == "unpublished" {
                unpublishedEmails.append(email)
            }

            return UploadResult(
                token: token,
                requiresVerification: !unpublishedEmails.isEmpty,
                emailsToVerify: unpublishedEmails,
                statusByEmail: statusDict
            )
        } catch let error as KeyServerError {
            throw error
        } catch {
            throw connectionError(error, on: server)
        }
    }

    // MARK: - Request Verification Email (per-server)

    /// Request a verification email for a specific address after upload.
    func requestVerification(token: String, email: String, on server: KeyServer) async throws {
        let urlString = "\(baseURL(for: server))/vks/v1/request-verify"

        guard let url = URL(string: urlString) else {
            throw KeyServerError.uploadFailed("Invalid URL")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: Any] = [
            "token": token,
            "addresses": [email]
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        do {
            let (_, response) = try await HTTPSessionFactory.boundedData(session(), for: request)

            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200 else {
                throw KeyServerError.uploadFailed("Verification request failed")
            }
        } catch let error as KeyServerError {
            throw error
        } catch {
            throw KeyServerError.networkError(error.localizedDescription)
        }
    }

    // MARK: - Upload + Verify (per-server)

    /// Upload a public key AND, for every address the server lists as unpublished,
    /// ask it to email a verification link (POST request-verify).
    ///
    /// Upload errors propagate (the caller surfaces them). A request-verify
    /// failure does NOT throw, because the key already uploaded successfully — it
    /// is reported in the outcome so the UI can tell the user to retry.
    func uploadAndRequestVerification(_ armoredKey: String, to server: KeyServer) async throws -> UploadVerifyOutcome {
        try OfflineMode.requireOnline()
        let result: UploadResult
        do {
            result = try await uploadPublicKey(armoredKey, to: server)
        } catch {
            // 8.3.0 (6.2, Android RC5): a custom server that does not answer
            // the VKS probe, or answers it with a 404 or 405, gets the HKP add
            // instead of an abort. The built-ins speak VKS; their errors stand.
            guard server.isCustom, Self.vksProbeFailed(error) else {
                throw connectionError(error, on: server)
            }
            return try await hkpAdd(armoredKey, on: server)
        }
        guard result.requiresVerification else {
            return UploadVerifyOutcome(verificationRequested: [], verificationFailed: [], hadUnverified: false,
                                       statusByEmail: result.statusByEmail)
        }
        var requested: [String] = []
        var failed: [String] = []
        for email in result.emailsToVerify {
            do {
                try await requestVerification(token: result.token, email: email, on: server)
                requested.append(email)
            } catch {
                failed.append(email)
            }
        }
        return UploadVerifyOutcome(
            verificationRequested: requested,
            verificationFailed: failed,
            hadUnverified: true,
            statusByEmail: result.statusByEmail
        )
    }

    /// The VKS upload failures that mean "this server has no VKS endpoint":
    /// a connection failure, or a 404 / 405 on /vks/v1/upload.
    private static func vksProbeFailed(_ error: Error) -> Bool {
        if let e = error as? KeyServerError {
            if case .uploadFailed(let msg) = e {
                return msg.hasPrefix("Status 404") || msg.hasPrefix("Status 405") || msg.hasPrefix("Status 501")
            }
            if case .networkError = e { return true }
            return false
        }
        return (error as NSError).domain == NSURLErrorDomain
    }

    // MARK: - Cross-server lookup

    /// Search enabled lookup servers in priority order, returning the first hit.
    /// The final "not found" error from the last server is thrown if every server
    /// misses; a network error on one server does not abort the walk.
    func lookupAcrossServers(
        _ query: String,
        by kind: LookupKind
    ) async throws -> String {
        let servers = KeyServerRegistry.lookupServers()
        guard !servers.isEmpty else { throw KeyServerError.noResults }

        var lastError: Error = KeyServerError.noResults
        for server in servers {
            do {
                switch kind {
                case .email:
                    return try await searchByEmail(query, on: server)
                case .fingerprint:
                    return try await searchByFingerprint(query, on: server)
                }
            } catch KeyServerError.noResults {
                lastError = KeyServerError.noResults
                continue
            } catch {
                // Network / server error on this server — remember it but keep
                // trying the others so one flaky server doesn't block a lookup.
                lastError = error
                continue
            }
        }
        throw lastError
    }

    // MARK: - Verification status (on-view poll, OI6)

    /// Where a key stands on one server, from a single on-view poll.
    enum PublicationStatus: String {
        case verified    // served by-email → the address is verified on this server
        case published   // by-fingerprint hit, but not by-email → awaiting verification
        case notFound    // by-fingerprint 404 → the server doesn't have this key
        case unknown     // network/other error → couldn't determine
    }

    /// Poll one server for where a (fingerprint, email) stands.
    ///
    /// Uses the Hagrid guarantee that a key is served *by email* only once that
    /// email is verified — so a by-email hit means "verified", a by-fingerprint
    /// hit without a by-email hit means "published, awaiting verification", and
    /// no fingerprint hit means "not found". Read-only; no traffic beyond the
    /// two lookups, and none in the background.
    func verificationStatus(
        fingerprint: String,
        email: String,
        on server: KeyServer
    ) async -> PublicationStatus {
        let trimmedEmail = email.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedEmail.isEmpty {
            do {
                _ = try await searchByEmail(trimmedEmail, on: server)
                return .verified
            } catch KeyServerError.noResults {
                // Not verified (or no such UID served) — fall through to the
                // fingerprint check to distinguish "published" from "not found".
            } catch {
                return .unknown
            }
        }
        do {
            _ = try await searchByFingerprint(fingerprint, on: server)
            return .published
        } catch KeyServerError.noResults {
            return .notFound
        } catch {
            return .unknown
        }
    }

    enum LookupKind {
        case email
        case fingerprint
    }

    // MARK: - Backward-compatible entry points (single-server, default servers)

    /// Search by email across enabled lookup servers (first hit).
    /// Preserves the original single-argument call site.
    func searchByEmail(_ email: String) async throws -> String {
        try await lookupAcrossServers(email, by: .email)
    }

    /// Search by fingerprint/key ID across enabled lookup servers (first hit).
    /// Preserves the original single-argument call site.
    func searchByFingerprint(_ fingerprint: String) async throws -> String {
        try await lookupAcrossServers(fingerprint, by: .fingerprint)
    }

    // 8.3.0 (planning 3.2): the single-server upload wrappers that targeted
    // keys.openpgp.org alone are gone with the Exchange tab's legacy upload;
    // every upload now goes through PublishSheet, per selected server.
}

// MARK: - Result Types

struct UploadResult {
    let token: String
    let requiresVerification: Bool
    let emailsToVerify: [String]
    /// 8.3.0 (3.3 e): the server's status per address as returned by the
    /// upload ("published", "pending", "unpublished", "revoked").
    var statusByEmail: [String: String] = [:]
}

/// v7.1.0 (Batuhan) — outcome of uploadAndRequestVerification. 8.3.0: the
/// per-address status map rides along so PublishSheet can say what each
/// server did with each address; the keys.openpgp.org-specific summary
/// message retired with the Exchange tab's single-server upload.
struct UploadVerifyOutcome {
    /// Addresses the server was successfully asked to email a verification link to.
    let verificationRequested: [String]
    /// Addresses whose request-verify call failed (the upload still succeeded).
    let verificationFailed: [String]
    /// True when the key had at least one address that needed verification.
    let hadUnverified: Bool
    /// The server's status per address, from the upload response.
    var statusByEmail: [String: String] = [:]
}

// MARK: - Upload failure text (8.3.0, 9.5)

extension KeyServerService {
    /// 8.3.0 (9.5): a VKS server (Hagrid, keys.pgpony.app) answers a rejected
    /// upload with `{"error": "..."}`. Show that sentence; fall back to the
    /// status and a short body only when there is no such field.
    static func uploadFailureText(status: Int, body: Data) -> String {
        if let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
           let message = (json["error"] as? String) ?? (json["message"] as? String),
           !message.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return String(localized: "The server rejected the upload: \(message.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        let text = String(data: body, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if text.isEmpty {
            return String(localized: "The server rejected the upload (status \(status)).")
        }
        return "Status \(status): \(text.prefix(200))"
    }
}
