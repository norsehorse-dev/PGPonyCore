// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import Foundation

/// Pure value types describing the parsed content of a `pass` entry.
///
/// Extracted into `PGPonyCore` from the app's `PassModels` so `PassEntryParser`
/// has a self-contained, dependency-free output type. The app's storage/browse
/// types (`PassStoreRef`, `PassNode`) intentionally stay app-side — they carry
/// security-scoped bookmark data and are not part of the auditable crypto core.

/// One metadata line parsed from an entry, conventionally `key: value`.
public struct PassField: Identifiable, Equatable {
    public let id = UUID()
    public let key: String
    public let value: String

    public init(key: String, value: String) {
        self.key = key
        self.value = value
    }

    public static func == (lhs: PassField, rhs: PassField) -> Bool {
        lhs.key == rhs.key && lhs.value == rhs.value
    }
}

/// The decrypted + parsed content of a single entry. Held only while the entry
/// view is on screen, then dropped.
public struct PassEntryContent: Equatable {
    public let password: String        // line 1 by convention (may be empty)
    public let fields: [PassField]     // recognised `key: value` metadata lines
    public let otpauth: String?        // detected `otpauth://` URI — displayed, NOT generated
    public let extraLines: [String]    // freeform lines that aren't `key: value`
    public let raw: String             // full decrypted text (kept only while viewing)

    public init(password: String, fields: [PassField], otpauth: String?, extraLines: [String], raw: String) {
        self.password = password
        self.fields = fields
        self.otpauth = otpauth
        self.extraLines = extraLines
        self.raw = raw
    }
}
