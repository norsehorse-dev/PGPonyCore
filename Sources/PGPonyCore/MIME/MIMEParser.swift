// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import Foundation

/// A tolerant, side-effect-free MIME parser for **already-decrypted** PGP/MIME
/// bytes. It never throws and never touches the network or crypto; it only ever
/// runs on plaintext that the decrypt path already produced.
///
/// Design goals (same spirit as `PassEntryParser`):
/// - Deterministic and unit-testable: same bytes in, same tree out.
/// - Tolerant of real-world MIME: CRLF or LF line endings, folded headers,
///   base64 / quoted-printable / 7bit / 8bit / binary transfer encodings.
/// - Conservative detection: `parseMultipart` returns a structured message only
///   when the top entity is a genuine multipart whose boundary actually delimits
///   parts. For inline PGP and ordinary plain text it returns `nil`, so the
///   decrypt view falls back to its existing single-`Text` rendering unchanged.
///
/// NEW FILE — add to the **PGPony** app target (and tick **PGPonyAction**) in Xcode.
enum MIMEParser {

    // MARK: - Public entry points

    /// Parse any bytes into a MIME entity tree. A non-MIME / plain-text input
    /// becomes a single `text/plain` leaf holding the whole input.
    static func parse(_ data: Data) -> MIMEEntity {
        parseEntity(Array(data))
    }

    /// Structured-detection entry point used by the decrypt view.
    ///
    /// Returns a `MIMEMessage` only when the top entity is a real multipart with
    /// at least one delimited part. Otherwise returns `nil` and the caller keeps
    /// its existing plain-text behaviour. This is the guarantee that inline PGP
    /// and normal messages never change.
    static func parseMultipart(_ data: Data) -> MIMEMessage? {
        let root = parseEntity(Array(data))
        guard root.contentType.isMultipart,
              case .multipart(let parts) = root.content,
              !parts.isEmpty else {
            return nil
        }
        return MIMEMessage(root: root)
    }

    // MARK: - Entity parsing

    private static func parseEntity(_ bytes: [UInt8]) -> MIMEEntity {
        let (headerBytes, bodyBytes) = splitHeadersAndBody(bytes)
        let headers = parseHeaders(headerBytes)

        let contentType = parseContentType(value(of: "content-type", in: headers))
        let transferEncoding = MIMETransferEncoding(
            headerValue: value(of: "content-transfer-encoding", in: headers)
        )
        let disposition = parseDisposition(value(of: "content-disposition", in: headers))
        let contentID = value(of: "content-id", in: headers)?
            .trimmingCharacters(in: CharacterSet(charactersIn: "<> "))

        let content: MIMEContent
        if contentType.isMultipart, let boundary = contentType.boundary, !boundary.isEmpty {
            let parts = splitMultipartBody(bodyBytes, boundary: boundary)
            content = .multipart(parts.map { parseEntity($0) })
        } else {
            content = .leaf(Data(transferDecode(bodyBytes, encoding: transferEncoding)))
        }

        return MIMEEntity(
            headers: headers,
            contentType: contentType,
            transferEncoding: transferEncoding,
            disposition: disposition,
            contentID: contentID,
            content: content
        )
    }

    // MARK: - Header / body split

    /// Split at the first blank line (LF LF or CRLF CRLF). If nothing before it
    /// parses as a header, the whole input is treated as the body — so decrypted
    /// plain text and inline-PGP plaintext are never mistaken for a header block.
    static func splitHeadersAndBody(_ bytes: [UInt8]) -> (header: [UInt8], body: [UInt8]) {
        let n = bytes.count
        var i = 0
        while i < n {
            guard let lf = nextIndex(of: 0x0A, in: bytes, from: i) else { break }
            let after = lf + 1
            // Blank line directly after this one?  "\n\n"
            if after < n, bytes[after] == 0x0A {
                let header = trimTrailingCR(Array(bytes[0..<lf]))
                return looksLikeHeaderBlock(header)
                    ? (header, Array(bytes[(after + 1)..<n]))
                    : ([], bytes)
            }
            // "\n\r\n"
            if after + 1 < n, bytes[after] == 0x0D, bytes[after + 1] == 0x0A {
                let header = trimTrailingCR(Array(bytes[0..<lf]))
                return looksLikeHeaderBlock(header)
                    ? (header, Array(bytes[(after + 2)..<n]))
                    : ([], bytes)
            }
            i = lf + 1
        }
        // No blank line: it's all headers only if it parses as headers.
        return looksLikeHeaderBlock(bytes) ? (bytes, []) : ([], bytes)
    }

    private static func nextIndex(of byte: UInt8, in bytes: [UInt8], from start: Int) -> Int? {
        var i = start
        while i < bytes.count {
            if bytes[i] == byte { return i }
            i += 1
        }
        return nil
    }

    private static func trimTrailingCR(_ bytes: [UInt8]) -> [UInt8] {
        bytes.last == 0x0D ? Array(bytes.dropLast()) : bytes
    }

    /// A byte block looks like headers if its first non-continuation line is a
    /// valid `Field-Name:` line.
    private static func looksLikeHeaderBlock(_ bytes: [UInt8]) -> Bool {
        guard !bytes.isEmpty else { return false }
        // First line up to LF.
        var end = 0
        while end < bytes.count && bytes[end] != 0x0A { end += 1 }
        let first = Array(bytes[0..<end])
        guard let colon = first.firstIndex(of: 0x3A), colon > 0 else { return false }
        // Field name chars: printable ASCII except space and colon (RFC 5322).
        for b in first[0..<colon] {
            if b <= 0x20 || b >= 0x7F || b == 0x3A { return false }
        }
        return true
    }

    // MARK: - Header parsing (with unfolding)

    static func parseHeaders(_ bytes: [UInt8]) -> [MIMEHeader] {
        guard !bytes.isEmpty else { return [] }
        let text = String(decoding: bytes, as: UTF8.self)
        let normalized = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        let rawLines = normalized.components(separatedBy: "\n")

        // Unfold: a line starting with space/tab continues the previous one.
        var unfolded: [String] = []
        for line in rawLines {
            if let first = line.first, (first == " " || first == "\t"), !unfolded.isEmpty {
                unfolded[unfolded.count - 1] += " " + line.trimmingCharacters(in: .whitespaces)
            } else {
                unfolded.append(line)
            }
        }

        var headers: [MIMEHeader] = []
        for line in unfolded {
            if line.isEmpty { continue }
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if !name.isEmpty {
                headers.append(MIMEHeader(name: name, value: value))
            }
        }
        return headers
    }

    private static func value(of name: String, in headers: [MIMEHeader]) -> String? {
        headers.first { $0.name.lowercased() == name }?.value
    }

    // MARK: - Content-Type / parameters

    static func parseContentType(_ raw: String?) -> MIMEContentType {
        guard let raw, !raw.isEmpty else { return .defaultType }
        let (mediaType, params) = parseValueWithParameters(raw)
        let slash = mediaType.firstIndex(of: "/")
        let type: String
        let subtype: String
        if let slash {
            type = String(mediaType[..<slash]).lowercased()
            subtype = String(mediaType[mediaType.index(after: slash)...]).lowercased()
        } else {
            type = mediaType.lowercased()
            subtype = ""
        }
        return MIMEContentType(type: type, subtype: subtype, parameters: params)
    }

    private static func parseDisposition(_ raw: String?) -> MIMEDisposition {
        guard let raw, !raw.isEmpty else { return .none }
        let (kind, params) = parseValueWithParameters(raw)
        return MIMEDisposition(kind: kind.lowercased(), filename: params["filename"])
    }

    /// Parse `token; key=value; key="quoted; value"` into the leading token and a
    /// lowercased-key parameter map. Handles quoted strings and RFC 2231
    /// `name*0`/`name*1` continuations and `name*=charset'lang'pct-encoded`.
    static func parseValueWithParameters(_ raw: String) -> (value: String, params: [String: String]) {
        var segments: [String] = []
        var current = ""
        var inQuotes = false
        for ch in raw {
            if ch == "\"" { inQuotes.toggle(); current.append(ch); continue }
            if ch == ";" && !inQuotes { segments.append(current); current = ""; continue }
            current.append(ch)
        }
        segments.append(current)

        let value = segments.first?.trimmingCharacters(in: .whitespaces) ?? ""

        // Collect raw params first, then reassemble 2231 continuations.
        var raws: [(key: String, value: String, extended: Bool)] = []
        for seg in segments.dropFirst() {
            let trimmed = seg.trimmingCharacters(in: .whitespaces)
            guard let eq = trimmed.firstIndex(of: "=") else { continue }
            var key = String(trimmed[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
            var v = String(trimmed[trimmed.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            if v.hasPrefix("\"") && v.hasSuffix("\"") && v.count >= 2 {
                v = String(v.dropFirst().dropLast())
            }
            let extended = key.hasSuffix("*")
            if extended { key.removeLast() }
            raws.append((key, v, extended))
        }

        // Group by base name, stripping a trailing `*<n>` continuation index.
        var grouped: [String: [(order: Int, value: String, extended: Bool)]] = [:]
        for r in raws {
            var base = r.key
            var order = 0
            if let star = base.lastIndex(of: "*"),
               let idx = Int(base[base.index(after: star)...]) {
                order = idx
                base = String(base[..<star])
            }
            grouped[base, default: []].append((order, r.value, r.extended))
        }

        var params: [String: String] = [:]
        for (base, pieces) in grouped {
            let ordered = pieces.sorted { $0.order < $1.order }
            let joined = ordered.map { $0.value }.joined()
            if ordered.contains(where: { $0.extended }) {
                params[base] = decodeRFC2231ExtendedValue(joined)
            } else {
                params[base] = joined
            }
        }
        return (value, params)
    }

    /// Decode an RFC 2231 extended value: `charset'lang'percent%20encoded`.
    private static func decodeRFC2231ExtendedValue(_ raw: String) -> String {
        let parts = raw.components(separatedBy: "'")
        let charset: String
        let encoded: String
        if parts.count >= 3 {
            charset = parts[0]
            encoded = parts[2...].joined(separator: "'")
        } else {
            charset = "utf-8"
            encoded = raw
        }
        var bytes: [UInt8] = []
        let scalars = Array(encoded.unicodeScalars)
        var i = 0
        while i < scalars.count {
            if scalars[i] == "%", i + 2 < scalars.count,
               let hi = hexValue(scalars[i + 1]), let lo = hexValue(scalars[i + 2]) {
                bytes.append(UInt8(hi * 16 + lo)); i += 3
            } else {
                bytes.append(contentsOf: Array(String(scalars[i]).utf8)); i += 1
            }
        }
        return decodeText(bytes, charset: charset)
    }

    // MARK: - Multipart body splitting (byte level)

    /// Split a multipart body on its `--boundary` delimiter lines, returning each
    /// part's raw bytes (headers + body, before recursion). Preamble before the
    /// first delimiter and the epilogue after the closing delimiter are dropped.
    /// The CRLF immediately preceding a delimiter belongs to the delimiter and is
    /// stripped from the part (RFC 2046 §5.1.1).
    static func splitMultipartBody(_ body: [UInt8], boundary: String) -> [[UInt8]] {
        let marker: [UInt8] = [0x2D, 0x2D] + Array(boundary.utf8) // "--boundary"
        let n = body.count

        struct Delim { let lineStart: Int; let contentStart: Int; let isClose: Bool }
        var delims: [Delim] = []

        var i = 0
        while i < n {
            let atLineStart = (i == 0) || (body[i - 1] == 0x0A)
            if atLineStart && matches(body, at: i, marker) {
                var j = i + marker.count
                var isClose = false
                if j + 1 < n, body[j] == 0x2D, body[j + 1] == 0x2D {
                    isClose = true
                    j += 2
                }
                // Allow trailing whitespace before the line break.
                while j < n, body[j] == 0x20 || body[j] == 0x09 || body[j] == 0x0D { j += 1 }
                if j >= n || body[j] == 0x0A {
                    let contentStart = (j < n) ? j + 1 : n
                    delims.append(Delim(lineStart: i, contentStart: contentStart, isClose: isClose))
                    i = contentStart
                    continue
                }
            }
            while i < n && body[i] != 0x0A { i += 1 }
            i += 1
        }

        var parts: [[UInt8]] = []
        for k in 0..<delims.count {
            if delims[k].isClose { break }
            let start = delims[k].contentStart
            let end = (k + 1 < delims.count) ? delims[k + 1].lineStart : n
            guard start <= end else { continue }
            var slice = Array(body[start..<end])
            // Strip the one trailing CRLF / LF that precedes the next delimiter.
            if slice.last == 0x0A {
                slice.removeLast()
                if slice.last == 0x0D { slice.removeLast() }
            }
            parts.append(slice)
        }
        return parts
    }

    private static func matches(_ body: [UInt8], at index: Int, _ needle: [UInt8]) -> Bool {
        guard index + needle.count <= body.count else { return false }
        for k in 0..<needle.count where body[index + k] != needle[k] { return false }
        return true
    }

    // MARK: - Transfer decoding

    static func transferDecode(_ bytes: [UInt8], encoding: MIMETransferEncoding) -> [UInt8] {
        switch encoding {
        case .base64:           return decodeBase64(bytes)
        case .quotedPrintable:  return decodeQuotedPrintable(bytes)
        case .sevenBit, .eightBit, .binary, .other:
            return bytes
        }
    }

    static func decodeBase64(_ bytes: [UInt8]) -> [UInt8] {
        // Keep only base64 alphabet characters, then decode.
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".utf8)
        let filtered = bytes.filter { allowed.contains($0) }
        guard let data = Data(base64Encoded: Data(filtered), options: .ignoreUnknownCharacters) else {
            return []
        }
        return Array(data)
    }

    static func decodeQuotedPrintable(_ bytes: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        let n = bytes.count
        var i = 0
        while i < n {
            let c = bytes[i]
            if c == 0x3D { // '='
                if i + 1 < n, bytes[i + 1] == 0x0A { i += 2; continue }            // =\n soft break
                if i + 2 < n, bytes[i + 1] == 0x0D, bytes[i + 2] == 0x0A { i += 3; continue } // =\r\n
                if i + 2 < n,
                   let hi = hexValue(bytes[i + 1]), let lo = hexValue(bytes[i + 2]) {
                    out.append(UInt8(hi * 16 + lo)); i += 3; continue
                }
                out.append(c); i += 1 // stray '='
            } else {
                out.append(c); i += 1
            }
        }
        return out
    }

    // MARK: - Text decoding

    static func decodeText(_ bytes: [UInt8], charset: String?) -> String {
        let encoding = stringEncoding(for: charset)
        if let s = String(bytes: bytes, encoding: encoding) { return s }
        if let s = String(bytes: bytes, encoding: .utf8) { return s }
        if let s = String(bytes: bytes, encoding: .isoLatin1) { return s }
        return String(decoding: bytes, as: UTF8.self) // lossy last resort
    }

    private static func stringEncoding(for charset: String?) -> String.Encoding {
        switch (charset ?? "utf-8").lowercased() {
        case "utf-8", "utf8":                       return .utf8
        case "us-ascii", "ascii":                   return .ascii
        case "iso-8859-1", "latin1", "iso8859-1":   return .isoLatin1
        case "iso-8859-15":                         return .isoLatin1
        case "windows-1252", "cp1252":              return .windowsCP1252
        case "utf-16", "utf16":                     return .utf16
        default:                                    return .utf8
        }
    }

    // MARK: - RFC 3676 format=flowed

    /// Join soft-wrapped `format=flowed` lines back into readable paragraphs.
    /// A line ending in a space is a soft break (continues onto the next line);
    /// a line with no trailing space is a hard break. One leading space is
    /// "unstuffed". The `-- ` signature separator is treated as a hard line.
    static func applyFormatFlowed(_ text: String, delSp: Bool) -> String {
        let normalized = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        let lines = normalized.components(separatedBy: "\n")

        var result = ""
        for (index, original) in lines.enumerated() {
            var line = original
            if line.hasPrefix(" ") { line.removeFirst() } // space-stuffing

            let isFlowed = line.hasSuffix(" ") && line != "-- "
            if isFlowed && delSp { line.removeLast() }

            result += line
            if !isFlowed {
                if index != lines.count - 1 { result += "\n" } // hard break
            }
            // soft break: no separator; the next line continues this one.
        }
        return result
    }

    // MARK: - RFC 2047 encoded-words (header / filename decoding)

    /// Decode any `=?charset?B?...?=` / `=?charset?Q?...?=` encoded-words in a
    /// header value (used for filenames). Surrounding text is left untouched.
    static func decodeEncodedWords(_ input: String) -> String {
        guard input.contains("=?") else { return input }
        var result = ""
        let chars = Array(input)
        var i = 0
        while i < chars.count {
            if chars[i] == "=", i + 1 < chars.count, chars[i + 1] == "?",
               let decoded = decodeEncodedWord(chars, start: i) {
                result += decoded.text
                i = decoded.nextIndex
            } else {
                result.append(chars[i]); i += 1
            }
        }
        return result
    }

    private static func decodeEncodedWord(
        _ chars: [Character], start: Int
    ) -> (text: String, nextIndex: Int)? {
        // A word is  =?charset?encoding?encoded-text?=  . Encoded-text never
        // contains a literal '?' (B is base64; Q encodes '?' as =3F), so we can
        // scan for the closing "?=" and split the inner run on '?'.
        var i = start + 2 // skip "=?"
        var inner = ""
        var end = -1
        while i < chars.count {
            if chars[i] == "?", i + 1 < chars.count, chars[i + 1] == "=" {
                end = i + 2 // index just past the closing "?="
                break
            }
            inner.append(chars[i]); i += 1
        }
        guard end != -1 else { return nil }

        let parts = inner
            .split(separator: "?", maxSplits: 2, omittingEmptySubsequences: false)
            .map(String.init)
        guard parts.count == 3 else { return nil }

        let charset = parts[0]
        let mode = parts[1].uppercased()
        let encoded = parts[2]
        let bytes: [UInt8]
        if mode == "B" {
            bytes = decodeBase64(Array(encoded.utf8))
        } else if mode == "Q" {
            bytes = decodeQEncoding(encoded)
        } else {
            return nil
        }
        return (decodeText(bytes, charset: charset), end)
    }

    /// RFC 2047 "Q" encoding: like quoted-printable but `_` means space.
    private static func decodeQEncoding(_ s: String) -> [UInt8] {
        var bytes: [UInt8] = []
        let scalars = Array(s.unicodeScalars)
        var i = 0
        while i < scalars.count {
            let c = scalars[i]
            if c == "_" {
                bytes.append(0x20); i += 1
            } else if c == "=", i + 2 < scalars.count,
                      let hi = hexValue(scalars[i + 1]), let lo = hexValue(scalars[i + 2]) {
                bytes.append(UInt8(hi * 16 + lo)); i += 3
            } else {
                bytes.append(contentsOf: Array(String(c).utf8)); i += 1
            }
        }
        return bytes
    }

    // MARK: - Hex helpers

    private static func hexValue(_ b: UInt8) -> Int? {
        switch b {
        case 0x30...0x39: return Int(b - 0x30)
        case 0x41...0x46: return Int(b - 0x41 + 10)
        case 0x61...0x66: return Int(b - 0x61 + 10)
        default:          return nil
        }
    }

    private static func hexValue(_ s: Unicode.Scalar) -> Int? {
        guard s.isASCII else { return nil }
        return hexValue(UInt8(s.value))
    }

    // MARK: - RFC 3156 envelope extraction (decrypt side)

    /// If `data` is an RFC 3156 `multipart/encrypted` message (an encrypted
    /// .eml, with or without leading email headers), return the armored OpenPGP
    /// block from its ciphertext part so it can be decrypted like an inline
    /// message. Returns nil when the input isn't such an envelope, so callers
    /// fall back to treating it as plain inline ciphertext.
    static func pgpMIMEEncryptedPayload(in data: Data) -> String? {
        let root = parse(data)
        guard root.contentType.mimeType == "multipart/encrypted" else { return nil }
        guard case .multipart(let parts) = root.content else { return nil }

        func armoredLeaf(_ entity: MIMEEntity) -> String? {
            guard case .leaf(let bytes) = entity.content else { return nil }
            let text = String(decoding: bytes, as: UTF8.self)
            return text.contains("-----BEGIN PGP MESSAGE-----") ? text : nil
        }

        // RFC 3156 carries the ciphertext in the application/octet-stream part;
        // prefer it, but fall back to any part that holds an armored block.
        if let octet = parts.first(where: { $0.contentType.mimeType == "application/octet-stream" }),
           let text = armoredLeaf(octet) {
            return text
        }
        return parts.compactMap(armoredLeaf).first
    }
}
