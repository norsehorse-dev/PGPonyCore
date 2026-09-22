// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// UserIDFormat.swift
// PGPonyCore
//
// CORE SEAM: in the app this is PGPKeyModel.composeUserID, on the SwiftData
// model. The key generators need only the formatting rule, so the core keeps
// the rule on its own.

import Foundation

enum UserIDFormat {
    /// "Name <email>", "Name" (8.3.0, planning 6.1: an email-less key), or
    /// "<email>". Both blank gives an empty User ID; callers validate first.
    static func compose(name: String, email: String) -> String {
        let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let e = email.trimmingCharacters(in: .whitespacesAndNewlines)
        switch (n.isEmpty, e.isEmpty) {
        case (false, false): return "\(n) <\(e)>"
        case (false, true): return n
        case (true, false): return "<\(e)>"
        case (true, true): return ""
        }
    }
}
