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

    // MARK: - v8.2.0 §3b streaming build

    /// A streaming attachment source: metadata plus a file URL whose bytes are
    /// read and base64-encoded incrementally, never held whole in memory. The
    /// compose path stages each picked file to such a reference (§3a).
    struct StreamingAttachment {
        let filename: String
        let mimeType: String
        let url: URL
    }

    /// §3b — the streaming counterpart to `build`. Writes the same
    /// `multipart/mixed` entity to `output`, but each attachment's bytes are
    /// read from its file and base64-encoded in bounded chunks straight to
    /// disk, so neither an attachment nor the assembled MIME is ever a whole
    /// `Data`. The output is byte-identical to `build` for the same inputs
    /// (locked by MIMEBuilderStreamingTests), so the encrypt/decrypt/parse
    /// round trip is unchanged; only the memory profile is. The body part stays
    /// in memory because a typed message body is small; only attachments stream.
    static func buildStreaming(
        plainText: String?,
        attachments: [StreamingAttachment],
        to output: URL,
        boundary: String = makeBoundary()
    ) throws {
        FileManager.default.createFile(atPath: output.path, contents: nil)
        let handle = try FileHandle(forWritingTo: output)
        defer { try? handle.close() }
        func write(_ string: String) throws { try handle.write(contentsOf: Data(string.utf8)) }

        try write("Content-Type: multipart/mixed; boundary=\"\(boundary)\"\r\n")
        try write("\r\n")

        if let body = plainText {
            try write("--\(boundary)\r\n")
            try write("Content-Type: text/plain; charset=UTF-8\r\n")
            try write("Content-Transfer-Encoding: base64\r\n")
            try write("\r\n")
            try write(base64Wrapped(Data(body.utf8)))
            try write("\r\n")
        }

        for attachment in attachments {
            let name = encodeParameterFilename(attachment.filename)
            try write("--\(boundary)\r\n")
            try write("Content-Type: \(attachment.mimeType); name=\"\(name)\"\r\n")
            try write("Content-Transfer-Encoding: base64\r\n")
            try write("Content-Disposition: attachment; filename=\"\(name)\"\r\n")
            try write("\r\n")
            try streamBase64Wrapped(from: attachment.url, to: handle)
            try write("\r\n")
        }

        try write("--\(boundary)--\r\n")
    }

    /// Stream a file's bytes as RFC 2045 base64 into `output`: 76-character
    /// lines separated by CRLF with NO trailing CRLF (the caller adds the part
    /// terminator, exactly like `base64Wrapped`). The file is read in bounded
    /// chunks and processed in 57-byte units (57 input bytes = 76 base64 chars,
    /// and 57 is a multiple of 3 so no intermediate padding is produced);
    /// padding appears only on the final short unit. Peak memory is one chunk,
    /// independent of file size. Empty input writes nothing, matching
    /// `base64Wrapped(Data())`.
    private static func streamBase64Wrapped(from url: URL, to output: FileHandle) throws {
        let input = try FileHandle(forReadingFrom: url)
        defer { try? input.close() }

        let lineBytes = 57                    // 57 input bytes -> one 76-char line
        let chunkBytes = lineBytes * 3000     // 171000, a multiple of 3 (no padding)
        let crlf = Data("\r\n".utf8)
        var carry = Data()
        var firstLine = true

        // Batch a whole read's lines into one write. A write per line is a
        // syscall; a large attachment has millions, which dominated the build.
        func encode(_ block: Data, into out: inout Data) {
            if firstLine { firstLine = false } else { out.append(crlf) }
            out.append(Data(block.base64EncodedString().utf8))
        }

        while let chunk = try input.read(upToCount: chunkBytes), !chunk.isEmpty {
            carry.append(chunk)
            var out = Data()
            var offset = 0
            while carry.count - offset >= lineBytes {
                encode(carry.subdata(in: offset..<(offset + lineBytes)), into: &out)
                offset += lineBytes
            }
            if offset > 0 { carry = carry.subdata(in: offset..<carry.count) }
            if !out.isEmpty { try output.write(contentsOf: out) }
        }
        if !carry.isEmpty {
            var out = Data()
            encode(carry, into: &out)   // final, padded, line
            try output.write(contentsOf: out)
        }
    }

    /// §3f — write the RFC 3156 `multipart/encrypted` envelope for a large
    /// result to `output`, streaming the armored ciphertext (from the binary
    /// OpenPGP message at `binaryMessageURL`) straight into part 2 so the whole
    /// armored message is never in memory. The interoperable email form for a
    /// large encrypted bundle; the same structure `wrapEncrypted` produces from
    /// an in-memory armored string, built here without one.
    static func streamEncryptedEnvelope(
        binaryMessageAt binaryMessageURL: URL,
        to output: URL,
        boundary: String = makeBoundary(),
        progress: ((Int) -> Void)? = nil
    ) throws {
        FileManager.default.createFile(atPath: output.path, contents: nil)
        let handle = try FileHandle(forWritingTo: output)
        defer { try? handle.close() }
        func w(_ s: String) throws { try handle.write(contentsOf: Data(s.utf8)) }

        try w("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\r\n")
        try w(" boundary=\"\(boundary)\"\r\n\r\n")

        // Part 1 — version identification.
        try w("--\(boundary)\r\n")
        try w("Content-Type: application/pgp-encrypted\r\n")
        try w("Content-Description: PGP/MIME version identification\r\n\r\n")
        try w("Version: 1\r\n")

        // Part 2 — the armored ciphertext, streamed from disk.
        try w("--\(boundary)\r\n")
        try w("Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n")
        try w("Content-Description: OpenPGP encrypted message\r\n")
        try w("Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n")
        try OpenPGPPacketBuilder.streamArmoredMessage(binaryAt: binaryMessageURL, to: handle, lineEnding: "\r\n", progress: progress)

        try w("--\(boundary)--\r\n")
    }

    // MARK: - v8.2.0 §3 streaming bundle extract

    /// One file recovered from a decrypted `multipart/mixed` bundle: its bytes
    /// already written to `url`, with the name and type carried by the part.
    struct ExtractedFile {
        let url: URL
        let filename: String
        let mimeType: String
    }

    /// The streaming inverse of `buildStreaming`: a decrypted bundle's parts,
    /// each attachment decoded to its own file on disk, plus any small text body.
    struct ExtractedBundle {
        /// True when the input was a `multipart/mixed` entity we could walk. When
        /// false the caller keeps its plain single-file behaviour (the decrypted
        /// bytes were not a bundle, e.g. an ordinary message or a foreign MIME).
        var isBundle: Bool
        var textBody: String?
        var files: [ExtractedFile]
    }

    /// Walk a decrypted `multipart/mixed` document at `input` and stream each
    /// attachment part's base64 body out to its own file in `directory`, never
    /// holding an attachment whole. This is the decrypt-side counterpart to
    /// `buildStreaming`: a large bundle (a 300 MB disk image, say) encrypted with
    /// the streaming compose path is recovered here as the real file it carried,
    /// not the raw envelope text. The optional `text/plain` body part (a typed
    /// message) is small by construction and returned as a String.
    ///
    /// Non-bundle input returns `isBundle: false` and no files, so the caller can
    /// fall back to presenting the decrypted bytes directly. Base64 is decoded a
    /// large multiple-of-4 prefix at a time (armor/MIME body lines are 76 chars,
    /// a multiple of 4, so a prefix decodes cleanly; padding only ever lands on a
    /// part's final line, flushed when the part closes), the same technique the
    /// streaming de-armor uses, so a huge attachment decodes without stalling.
    static func streamingExtractBundle(fileAt input: URL, toDirectory directory: URL, progress: ((Int) -> Void)? = nil) throws -> ExtractedBundle {
        let handle = try FileHandle(forReadingFrom: input)
        defer { try? handle.close() }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        // Pull boundary="..." (or boundary=token) out of a Content-Type value.
        func boundary(from headerValue: String) -> String? {
            guard let r = headerValue.range(of: "boundary=") else { return nil }
            var v = String(headerValue[r.upperBound...]).trimmingCharacters(in: .whitespaces)
            if v.hasPrefix("\"") {
                v.removeFirst()
                if let end = v.firstIndex(of: "\"") { v = String(v[..<end]) }
            } else if let end = v.firstIndex(where: { $0 == ";" || $0 == " " }) {
                v = String(v[..<end])
            }
            return v.isEmpty ? nil : v
        }

        // Decode our own RFC 2047 B-word filename form; leave anything else as is.
        func decodeFilename(_ raw: String) -> String {
            let s = raw.trimmingCharacters(in: .whitespaces)
            guard s.hasPrefix("=?UTF-8?B?"), s.hasSuffix("?=") else { return s }
            let inner = String(s.dropFirst("=?UTF-8?B?".count).dropLast(2))
            if let d = Data(base64Encoded: inner), let decoded = String(data: d, encoding: .utf8) {
                return decoded
            }
            return s
        }

        // filename="..." or name="..." from a header value.
        func quotedParam(_ key: String, in value: String) -> String? {
            guard let r = value.range(of: key + "=") else { return nil }
            var v = String(value[r.upperBound...]).trimmingCharacters(in: .whitespaces)
            if v.hasPrefix("\"") {
                v.removeFirst()
                if let end = v.firstIndex(of: "\"") { v = String(v[..<end]) }
            } else if let end = v.firstIndex(where: { $0 == ";" }) {
                v = String(v[..<end])
            }
            return v
        }

        enum Phase { case topHeaders, betweenParts, partHeaders, partBody }
        var phase: Phase = .topHeaders
        var top: String?                      // top-level Content-Type accumulator
        var mixedBoundary: String?
        var stop = false                      // set once nothing more can be recovered
        var result = ExtractedBundle(isBundle: false, textBody: nil, files: [])

        // Per-part state.
        var partContentType = ""
        var partFilename: String?
        var partIsText = false
        var partOut: FileHandle?
        var partURL: URL?
        var textAcc = Data()                  // base64 body bytes for a text part
        var b64 = Data()                      // base64 body bytes for a file part
        var fileIndex = 0

        func flushDecode(force: Bool) throws {
            let full = force ? b64.count : (b64.count - b64.count % 4)
            guard full > 0 else { return }
            if let decoded = Data(base64Encoded: b64.prefix(full)) {
                try partOut?.write(contentsOf: decoded)
            }
            b64.removeFirst(full)
        }

        func closePart() throws {
            if partIsText {
                // The body part streamed into a scratch file we don't need; the
                // small text is decoded from the accumulated base64 instead.
                try? partOut?.close()
                if let u = partURL { try? FileManager.default.removeItem(at: u) }
                if let d = Data(base64Encoded: textAcc), let s = String(data: d, encoding: .utf8) {
                    result.textBody = s
                }
            } else if let out = partOut, let url = partURL {
                try flushDecode(force: true)
                try? out.close()
                let name = partFilename.map(decodeFilename) ?? "attachment-\(fileIndex)"
                let type = partContentType.isEmpty ? "application/octet-stream" : partContentType
                // Give the recovered bytes their real filename as the last path
                // component (in a per-part subfolder to avoid collisions), so
                // Share and Save to Files suggest the correct name and extension
                // instead of the UUID scratch name it streamed into.
                let safe = name.replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "\u{0}", with: "_")
                let subdir = directory.appendingPathComponent("f\(fileIndex)", isDirectory: true)
                try? FileManager.default.createDirectory(at: subdir, withIntermediateDirectories: true)
                let finalURL = subdir.appendingPathComponent(safe.isEmpty ? "attachment-\(fileIndex)" : safe)
                do {
                    if FileManager.default.fileExists(atPath: finalURL.path) {
                        try FileManager.default.removeItem(at: finalURL)
                    }
                    try FileManager.default.moveItem(at: url, to: finalURL)
                    result.files.append(ExtractedFile(url: finalURL, filename: name, mimeType: type))
                } catch {
                    // Rename failed: keep the scratch file so no data is lost.
                    result.files.append(ExtractedFile(url: url, filename: name, mimeType: type))
                }
            }
            partOut = nil; partURL = nil; partFilename = nil
            partContentType = ""; partIsText = false
            textAcc.removeAll(keepingCapacity: true); b64.removeAll(keepingCapacity: true)
        }

        func beginPart() throws {
            partContentType = ""; partFilename = nil; partIsText = false
            textAcc.removeAll(keepingCapacity: true); b64.removeAll(keepingCapacity: true)
            fileIndex += 1
            let url = directory.appendingPathComponent("part-\(fileIndex)-\(UUID().uuidString)")
            FileManager.default.createFile(atPath: url.path, contents: nil)
            partURL = url
            partOut = try FileHandle(forWritingTo: url)
        }

        func addPartHeader(_ line: String) {
            let lower = line.lowercased()
            if lower.hasPrefix("content-type:") {
                let value = String(line.dropFirst("content-type:".count)).trimmingCharacters(in: .whitespaces)
                partContentType = value.split(separator: ";").first.map(String.init)?
                    .trimmingCharacters(in: .whitespaces) ?? value
                if partFilename == nil, let n = quotedParam("name", in: value) { partFilename = n }
            } else if lower.hasPrefix("content-disposition:") {
                let value = String(line.dropFirst("content-disposition:".count))
                if let n = quotedParam("filename", in: value) { partFilename = n }
            }
        }

        func process(line: String) throws {
            switch phase {
            case .topHeaders:
                if line.isEmpty {
                    // Headers done. If there was no multipart/mixed boundary this
                    // is not a bundle; stop and let the caller fall back.
                    if let ct = top, ct.lowercased().contains("multipart/mixed"),
                       let b = boundary(from: ct) {
                        mixedBoundary = b
                        result.isBundle = true
                        phase = .betweenParts
                    } else {
                        // Not a bundle: stop now instead of scanning the whole
                        // (possibly huge) decrypted file for parts that aren't there.
                        stop = true
                    }
                } else if line.first == " " || line.first == "\t" {
                    top = (top ?? "") + line          // folded header continuation
                } else if top == nil, line.lowercased().hasPrefix("content-type:") {
                    top = String(line.dropFirst("content-type:".count)).trimmingCharacters(in: .whitespaces)
                }
            case .betweenParts:
                guard let b = mixedBoundary else { return }
                if line == "--\(b)" { try beginPart(); phase = .partHeaders }
            case .partHeaders:
                if line.isEmpty {
                    partIsText = (partFilename == nil) && partContentType.lowercased().hasPrefix("text/")
                    phase = .partBody
                } else {
                    addPartHeader(line)
                }
            case .partBody:
                guard let b = mixedBoundary else { return }
                if line == "--\(b)" {
                    try closePart(); try beginPart(); phase = .partHeaders
                } else if line == "--\(b)--" {
                    try closePart(); phase = .betweenParts
                    stop = true            // closing delimiter: epilogue holds nothing
                } else if partIsText {
                    textAcc.append(contentsOf: Array(line.utf8))
                } else {
                    b64.append(contentsOf: Array(line.utf8))
                    if b64.count >= 4 * 1024 * 1024 { try flushDecode(force: false) }
                }
            }
        }

        // Line-oriented streaming read: split on LF, strip a trailing CR, carry a
        // partial final line across chunk reads.
        var carry = [UInt8]()
        let chunkBytes = 1024 * 1024
        var readTotal = 0
        while let chunk = try handle.read(upToCount: chunkBytes), !chunk.isEmpty {
            readTotal += chunk.count
            carry.append(contentsOf: chunk)
            var lineStart = 0
            while let nl = carry[lineStart...].firstIndex(of: 0x0A) {
                var end = nl
                if end > lineStart, carry[end - 1] == 0x0D { end -= 1 }
                try process(line: String(decoding: carry[lineStart..<end], as: UTF8.self))
                lineStart = nl + 1
                if stop { break }
            }
            if lineStart > 0 { carry.removeFirst(lineStart) }
            progress?(readTotal)
            // Our bundle header is tiny; if the top-level Content-Type has not
            // resolved within 64 KB this is not a PGPony bundle, so stop scanning
            // rather than reading a large non-bundle payload to its end.
            if phase == .topHeaders, readTotal > 64 * 1024 { stop = true }
            if stop { break }
        }
        if !stop, !carry.isEmpty {
            var end = carry.endIndex
            if end > carry.startIndex, carry[end - 1] == 0x0D { end -= 1 }
            try process(line: String(decoding: carry[carry.startIndex..<end], as: UTF8.self))
        }
        // A truncated final part (no closing delimiter) still yields its file.
        if phase == .partBody { try closePart() }

        return result
    }
}
