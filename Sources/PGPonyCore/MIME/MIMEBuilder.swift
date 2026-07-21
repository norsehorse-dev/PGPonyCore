// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import Foundation

/// v7.1.x — PGP/MIME *compose* side: the inverse of `MIMEParser`.
///
/// Assembles a `multipart/mixed` entity (an optional text body followed by file
/// attachments) into RFC 2045 / 2046 bytes. Those bytes are what the encrypt
/// path feeds to `smartEncrypt`; the decrypt path parses exactly this shape back
/// into a readable body plus openable attachments, so
/// build → encrypt → decrypt → parse round-trips cleanly.
///
/// Pure and side-effect free, like the parser. Attachments are base64-encoded
/// with RFC 2045 line wrapping; non-ASCII filenames are RFC 2047 B-encoded so
/// `MIMEParser.decodeEncodedWords` restores them on the other side.
///
/// NEW FILE — add to the **PGPony** app target (and tick **PGPonyAction** for the
/// share-extension reuse) in Xcode. Uncheck "Copy items if needed" and add it in
/// place at `Services/MIME/` so there's only one copy on disk.
enum MIMEBuilder {

    /// Build a `multipart/mixed` entity: an optional `text/plain` body part
    /// followed by one part per attachment. The returned bytes include the top
    /// `Content-Type` header, ready to hand to the encryptor.
    static func build(
        plainText: String?,
        attachments: [MIMEAttachment],
        boundary: String = makeBoundary()
    ) -> Data {
        var out = Data()
        func append(_ string: String) { out.append(Data(string.utf8)) }

        append("Content-Type: multipart/mixed; boundary=\"\(boundary)\"\r\n")
        append("\r\n")

        if let body = plainText {
            append("--\(boundary)\r\n")
            append("Content-Type: text/plain; charset=UTF-8\r\n")
            append("Content-Transfer-Encoding: base64\r\n")
            append("\r\n")
            append(base64Wrapped(Data(body.utf8)))
            append("\r\n")
        }

        for attachment in attachments {
            let name = encodeParameterFilename(attachment.filename)
            append("--\(boundary)\r\n")
            append("Content-Type: \(attachment.mimeType); name=\"\(name)\"\r\n")
            append("Content-Transfer-Encoding: base64\r\n")
            append("Content-Disposition: attachment; filename=\"\(name)\"\r\n")
            append("\r\n")
            append(base64Wrapped(attachment.data))
            append("\r\n")
        }

        append("--\(boundary)--\r\n")
        return out
    }

    /// Wrap an ASCII-armored OpenPGP message in an RFC 3156 `multipart/encrypted`
    /// entity — the structure desktop mail clients (Thunderbird, Apple Mail with
    /// GPG, etc.) expect for an encrypted email with attachments.
    ///
    /// Full compose pipeline:
    ///   inner = build(plainText:attachments:)        // multipart/mixed
    ///   armored = <encrypt inner to recipients>      // -----BEGIN PGP MESSAGE-----
    ///   envelope = encryptedEnvelope(armoredCiphertext: armored)
    ///
    /// The result is two parts: an `application/pgp-encrypted` "Version: 1"
    /// control part, then the armored ciphertext as `application/octet-stream`.
    static func encryptedEnvelope(
        armoredCiphertext: String,
        boundary: String = makeBoundary()
    ) -> Data {
        var out = Data()
        func append(_ string: String) { out.append(Data(string.utf8)) }

        append("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\r\n")
        append(" boundary=\"\(boundary)\"\r\n")
        append("\r\n")

        // Part 1 — PGP/MIME version identification (RFC 3156 §4).
        append("--\(boundary)\r\n")
        append("Content-Type: application/pgp-encrypted\r\n")
        append("Content-Description: PGP/MIME version identification\r\n")
        append("\r\n")
        append("Version: 1\r\n")

        // Part 2 — the armored ciphertext.
        append("--\(boundary)\r\n")
        append("Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n")
        append("Content-Description: OpenPGP encrypted message\r\n")
        append("Content-Disposition: inline; filename=\"encrypted.asc\"\r\n")
        append("\r\n")
        let normalized = armoredCiphertext
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\n", with: "\r\n")
        append(normalized)
        if !normalized.hasSuffix("\r\n") { append("\r\n") }

        append("--\(boundary)--\r\n")
        return out
    }

    /// A boundary token that won't collide with base64 or ordinary text.
    static func makeBoundary() -> String {
        "----=_PGPony_" + UUID().uuidString.replacingOccurrences(of: "-", with: "")
    }

    /// base64 with RFC 2045 76-character lines and CRLF separators.
    static func base64Wrapped(_ data: Data) -> String {
        let encoded = data.base64EncodedString()
        var lines: [Substring] = []
        var index = encoded.startIndex
        while index < encoded.endIndex {
            let end = encoded.index(index, offsetBy: 76, limitedBy: encoded.endIndex) ?? encoded.endIndex
            lines.append(encoded[index..<end])
            index = end
        }
        return lines.joined(separator: "\r\n")
    }

    /// Keep an ASCII filename verbatim; RFC 2047 B-encode anything with
    /// non-ASCII characters or a quote so it survives the quoted parameter and
    /// the parser can decode it back.
    static func encodeParameterFilename(_ filename: String) -> String {
        let needsEncoding = filename.unicodeScalars.contains { $0.value > 127 }
            || filename.contains("\"")
        guard needsEncoding else { return filename }
        let encoded = Data(filename.utf8).base64EncodedString()
        return "=?UTF-8?B?\(encoded)?="
    }

    // MARK: - RFC 3156 outer envelope

    /// Wrap an OpenPGP armored message in the RFC 3156 `multipart/encrypted`
    /// control structure: an `application/pgp-encrypted` version part plus an
    /// `application/octet-stream` part carrying the ciphertext. This is the
    /// interoperable form desktop mail clients (Thunderbird, etc.) expect for an
    /// encrypted email; the bytes are a complete MIME entity ready to drop into a
    /// message. The plain inline option is just `armoredCiphertext` on its own,
    /// so it needs no builder.
    static func wrapEncrypted(
        armoredCiphertext: String,
        boundary: String = makeBoundary()
    ) -> Data {
        var out = Data()
        func append(_ string: String) { out.append(Data(string.utf8)) }

        append("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\r\n")
        append(" boundary=\"\(boundary)\"\r\n")
        append("\r\n")

        // Part 1 — version identification.
        append("--\(boundary)\r\n")
        append("Content-Type: application/pgp-encrypted\r\n")
        append("Content-Description: PGP/MIME version identification\r\n")
        append("\r\n")
        append("Version: 1")
        append("\r\n")

        // Part 2 — the armored ciphertext.
        append("--\(boundary)\r\n")
        append("Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n")
        append("Content-Description: OpenPGP encrypted message\r\n")
        append("Content-Disposition: inline; filename=\"encrypted.asc\"\r\n")
        append("\r\n")
        append(normalizedArmor(armoredCiphertext))
        append("\r\n")

        append("--\(boundary)--\r\n")
        return out
    }

    /// Normalise armored text to CRLF line endings and trim a single trailing
    /// newline, since the envelope adds the part's own terminating CRLF.
    private static func normalizedArmor(_ text: String) -> String {
        var normalized = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        if normalized.hasSuffix("\n") { normalized.removeLast() }
        return normalized.replacingOccurrences(of: "\n", with: "\r\n")
    }
}
