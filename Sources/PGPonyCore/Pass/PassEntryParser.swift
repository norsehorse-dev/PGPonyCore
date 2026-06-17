// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import Foundation

/// Phase C — parses the decrypted plaintext of a `pass` entry into structured
/// content. Convention: line 1 is the password; subsequent lines are freeform,
/// often `key: value` metadata.
///
/// Tolerant by design — never throws, never crashes:
/// - Normalises CRLF/CR to LF and accepts a missing trailing newline.
/// - Splits a `key: value` line on the FIRST colon only, so values may contain
///   further colons (e.g. `note: see 12:30`).
/// - Keeps bare URL lines (e.g. `https://example.com`) as freeform rather than
///   misreading the scheme colon as a `key: value` separator.
/// - Detects an `otpauth://` line and surfaces it read-only (no code generation).
/// - Blank lines are dropped; unrecognised lines are preserved in `extraLines`.
///
/// NEW FILE — add to the **PGPony** app target in Xcode.
enum PassEntryParser {

    static func parse(_ text: String) -> PassEntryContent {
        let normalized = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        let lines = normalized.components(separatedBy: "\n")

        let password = lines.first ?? ""

        var fields: [PassField] = []
        var extraLines: [String] = []
        var otpauth: String? = nil

        for line in lines.dropFirst() {
            if line.isEmpty { continue }

            if line.lowercased().hasPrefix("otpauth://") {
                if otpauth == nil {
                    otpauth = line.trimmingCharacters(in: .whitespaces)
                }
                continue
            }

            if let colon = line.firstIndex(of: ":") {
                let valuePart = line[line.index(after: colon)...]   // untrimmed
                let key = line[..<colon].trimmingCharacters(in: .whitespaces)
                // A bare URL ("scheme://…") has "//" right after its first colon —
                // that's not a metadata separator, so treat the line as freeform.
                if !valuePart.hasPrefix("//") && !key.isEmpty {
                    let value = valuePart.trimmingCharacters(in: .whitespaces)
                    fields.append(PassField(key: key, value: value))
                    continue
                }
            }

            extraLines.append(line)
        }

        return PassEntryContent(
            password: password,
            fields: fields,
            otpauth: otpauth,
            extraLines: extraLines,
            raw: text
        )
    }
}
