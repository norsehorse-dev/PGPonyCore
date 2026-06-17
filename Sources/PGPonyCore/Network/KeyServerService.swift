// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// KeyServerService.swift
// PGPony
//
// Integration with keys.openpgp.org via HKP (HTTP Keyserver Protocol)
// Supports searching by email and fingerprint, downloading, and uploading keys.

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
        case .searchFailed(let msg): return "Key server search failed: \(msg)"
        case .downloadFailed(let msg): return "Key download failed: \(msg)"
        case .uploadFailed(let msg): return "Key upload failed: \(msg)"
        case .networkError(let msg): return "Network error: \(msg)"
        case .noResults: return "No keys found"
        case .invalidResponse: return "Invalid response from key server"
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
    
    private let baseURL = "https://keys.openpgp.org"
    private let session: URLSession
    
    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 30
        // TLS 1.3 minimum
        config.tlsMinimumSupportedProtocolVersion = .TLSv13
        self.session = URLSession(configuration: config)
    }
    
    // MARK: - Search by Email
    
    /// Search for a public key by email address
    func searchByEmail(_ email: String) async throws -> String {
        let encodedEmail = email.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? email
        let urlString = "\(baseURL)/vks/v1/by-email/\(encodedEmail)"
        
        guard let url = URL(string: urlString) else {
            throw KeyServerError.searchFailed("Invalid URL")
        }
        
        do {
            let (data, response) = try await session.data(from: url)
            
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
            throw error
        } catch {
            throw KeyServerError.networkError(error.localizedDescription)
        }
    }
    
    // MARK: - Search by Fingerprint
    
    /// Search for a public key by fingerprint or key ID.
    /// keys.openpgp.org accepts a full 40-char fingerprint via /by-fingerprint/
    /// or a 16-char key ID via /by-keyid/. v5.0 Phase 3: we now accept both,
    /// dispatch to the right endpoint, and give a clear error for inputs that
    /// are too short to be either.
    func searchByFingerprint(_ fingerprint: String) async throws -> String {
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

        let urlString = "\(baseURL)/vks/v1/\(endpoint)/\(cleanFingerprint)"

        guard let url = URL(string: urlString) else {
            throw KeyServerError.searchFailed("Invalid URL")
        }
        
        do {
            let (data, response) = try await session.data(from: url)
            
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
            throw error
        } catch {
            throw KeyServerError.networkError(error.localizedDescription)
        }
    }
    
    // MARK: - Upload Public Key
    
    /// Upload a public key to keys.openpgp.org
    /// Returns a verification URL (user must verify their email)
    ///
    /// The Hagrid (keys.openpgp.org) VKS v1 upload endpoint expects a JSON
    /// body, not a form-encoded one — sending application/x-www-form-urlencoded
    /// triggers a 400 response with the body "expected application/json data".
    /// See https://keys.openpgp.org/about/api for the full spec.
    func uploadPublicKey(_ armoredKey: String) async throws -> UploadResult {
        let urlString = "\(baseURL)/vks/v1/upload"
        
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
            let (data, response) = try await session.data(for: request)
            
            guard let httpResponse = response as? HTTPURLResponse else {
                throw KeyServerError.invalidResponse
            }
            
            guard httpResponse.statusCode == 200 else {
                let errorMsg = String(data: data, encoding: .utf8) ?? "Unknown error"
                throw KeyServerError.uploadFailed("Status \(httpResponse.statusCode): \(errorMsg)")
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
            if let statusDict = json["status"] as? [String: String] {
                for (email, emailStatus) in statusDict where emailStatus == "unpublished" {
                    unpublishedEmails.append(email)
                }
            }
            
            return UploadResult(
                token: token,
                requiresVerification: !unpublishedEmails.isEmpty,
                emailsToVerify: unpublishedEmails
            )
        } catch let error as KeyServerError {
            throw error
        } catch {
            throw KeyServerError.networkError(error.localizedDescription)
        }
    }
    
    // MARK: - Request Verification Email
    
    /// Request a verification email for a specific address after upload
    func requestVerification(token: String, email: String) async throws {
        let urlString = "\(baseURL)/vks/v1/request-verify"
        
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
            let (_, response) = try await session.data(for: request)
            
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
}

// MARK: - Result Types

struct UploadResult {
    let token: String
    let requiresVerification: Bool
    let emailsToVerify: [String]
}
