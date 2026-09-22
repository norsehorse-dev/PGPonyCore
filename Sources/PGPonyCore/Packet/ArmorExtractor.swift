// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// ArmorExtractor.swift
// PGPony
//
// 8.3.0 (6.5, Android 4.5.0 item 19): pull the armored OpenPGP block(s) out
// of noisy input. A key pasted from a web page, a mail body or a chat
// arrives wrapped in page text, signatures, quoted replies and the like;
// before this, ImportKeyView handed the whole text to the parsers, which
// then failed on the noise around the key instead of reading the key.
//
// Rules, the same as Android's ArmorExtractor:
//   - a block runs from "-----BEGIN PGP <TYPE>-----" to the "-----END PGP
//     <TYPE>-----" of the SAME type (an END of another type inside a block
//     does not close it; an unmatched BEGIN is not a block);
//   - key blocks (PUBLIC KEY BLOCK, PRIVATE KEY BLOCK) are preferred: when
//     the input holds at least one, only the key blocks are returned and a
//     stray detached signature or message is dropped;
//   - when no block is a key, every block is returned, in order, so a
//     message pasted into the import screen still reaches the parser that
//     will name what it is;
//   - no block at all: nil, and the caller says "no key data" instead of
//     "not a valid key";
//   - a clean .asc (one block, nothing around it) passes through byte for
//     byte, so nothing that imported before imports differently.

import Foundation

enum ArmorExtractor {

    struct Block: Equatable {
        /// The armor type between "-----BEGIN PGP " and "-----", e.g.
        /// "PUBLIC KEY BLOCK".
        let type: String
        /// The block text, BEGIN line through END line inclusive, with the
        /// original line endings normalized to "\n".
        let text: String

        var isKey: Bool { type == "PUBLIC KEY BLOCK" || type == "PRIVATE KEY BLOCK" }
    }

    /// Every well-formed armored block in `text`, in order of appearance.
    static func blocks(in text: String) -> [Block] {
        let lines = text.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .components(separatedBy: "\n")
        var found: [Block] = []
        var openType: String? = nil
        var openLines: [String] = []

        for rawLine in lines {
            // A stray BOM or surrounding whitespace on the marker line is
            // noise, not part of the marker.
            let line = rawLine.trimmingCharacters(in: .whitespaces)
                .replacingOccurrences(of: "\u{FEFF}", with: "")
            if openType == nil {
                if let type = markerType(line, prefix: "-----BEGIN PGP ") {
                    openType = type
                    openLines = [line]
                }
                continue
            }
            openLines.append(line)
            if let type = markerType(line, prefix: "-----END PGP "), type == openType {
                found.append(Block(type: type, text: openLines.joined(separator: "\n")))
                openType = nil
                openLines = []
            } else if let type = markerType(line, prefix: "-----BEGIN PGP "), type != openType {
                // A new block opened before the current one closed: the
                // current one was never a block. Start over on the new one.
                openType = type
                openLines = [line]
            }
        }
        return found
    }

    /// The text to hand the key parsers: the key blocks when there are any,
    /// else every block, joined by a blank line; nil when there is none.
    static func extract(from text: String) -> String? {
        let all = blocks(in: text)
        guard !all.isEmpty else { return nil }
        let keys = all.filter(\.isKey)
        let chosen = keys.isEmpty ? all : keys
        // A single clean block is returned as the user gave it, so a byte
        // exact .asc stays byte exact.
        if chosen.count == 1, all.count == 1, text.trimmingCharacters(in: .whitespacesAndNewlines) == chosen[0].text {
            return text
        }
        return chosen.map(\.text).joined(separator: "\n\n") + "\n"
    }

    /// True when `text` is already exactly one armored block with nothing
    /// around it, in which case extraction changes nothing.
    static func isCleanSingleBlock(_ text: String) -> Bool {
        let all = blocks(in: text)
        return all.count == 1 && text.trimmingCharacters(in: .whitespacesAndNewlines) == all[0].text
    }

    private static func markerType(_ line: String, prefix: String) -> String? {
        guard line.hasPrefix(prefix), line.hasSuffix("-----") else { return nil }
        let inner = line.dropFirst(prefix.count).dropLast(5)
        let type = String(inner).trimmingCharacters(in: .whitespaces)
        guard !type.isEmpty, type.allSatisfy({ $0.isUppercase || $0 == " " || $0.isNumber || $0 == "," }) else { return nil }
        return type
    }
}
