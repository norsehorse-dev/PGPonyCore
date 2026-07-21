// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// BackupCode.swift
// PGPony
//
// v8.0.0 Phase A — the passphrase behind an encrypted full-keyring backup.
//
// The backup container (see BackupService) is a single armored gpg -c message:
// AES-256, iterated-salted S2K, passphrase = the backup code generated here.
// There is no other secret — lose the code and the backup is unrecoverable, so
// the generation/display/confirmation flow (Phase B) treats it accordingly.
//
// Open Item 1 resolution (planning doc §6.1): "same entropy class, own
// grouping." OpenKeychain migrants get a familiar VISUAL language — grouped
// uppercase alphanumeric blocks — WITHOUT implying a compatible file format
// (only Android's OpenKeychain importer offers that, not this container). So:
//
//   • 120 bits of entropy from SecRandomCopyBytes (defense-in-depth: the file
//     is user-controlled, unlike the Keychain-backed keys themselves).
//   • Crockford base32 alphabet (0-9 A-Z minus I L O U) — unambiguous to read
//     aloud and to type; 15 bytes → exactly 24 symbols, no padding.
//   • PGPony grouping: 4 groups of 6, hyphen-separated  →  ABCDEF-GHJKMN-…
//     (distinct from OpenKeychain's own block shape on purpose).
//
// The S2K passphrase is the canonical form: the 24 symbols, uppercased, with
// the hyphens removed. `normalize(_:)` reproduces it from any user entry —
// lowercase, spaces, and the classic look-alike substitutions (O→0, I/L→1,
// U→V) all fold back to the same passphrase, so a hand-typed code still opens
// the file. The generator only ever emits canonical symbols, so a generated
// code is already in canonical form.

import Foundation
import Security

enum BackupCodeError: LocalizedError {
    case randomGenerationFailed
    case emptyInput
    case invalidCharacter(Character)
    case wrongLength(Int)

    var errorDescription: String? {
        switch self {
        case .randomGenerationFailed:
            return String(localized: "Could not generate a secure backup code.")
        case .emptyInput:
            return String(localized: "Enter your backup code.")
        case .invalidCharacter(let c):
            return String(localized: "“\(String(c))” isn’t part of a backup code.")
        case .wrongLength(let n):
            return String(localized: "A backup code has 24 characters; this one has \(n).")
        }
    }
}

enum BackupCode {

    // MARK: - Parameters

    /// Entropy drawn from the CSPRNG. 15 bytes = 120 bits and, at 5 bits per
    /// base32 symbol, encodes to exactly 24 symbols with no padding.
    static let entropyByteCount = 15

    /// Symbols in a canonical (hyphen-free) code.
    static let symbolCount = 24

    /// Symbols per display group.
    static let groupSize = 6

    /// Crockford base32 encode alphabet: digits then A–Z omitting I, L, O, U.
    /// Index i (0…31) maps to the symbol for the 5-bit value i.
    static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    // MARK: - Generation

    /// A fresh random backup code in display form (`ABCDEF-GHJKMN-PQRST0-…`).
    /// Throws only if the system CSPRNG is unavailable.
    static func generate() throws -> String {
        var bytes = [UInt8](repeating: 0, count: entropyByteCount)
        guard SecRandomCopyBytes(kSecRandomDefault, entropyByteCount, &bytes) == errSecSuccess else {
            throw BackupCodeError.randomGenerationFailed
        }
        return format(encodeBase32(bytes))
    }

    // MARK: - Canonicalization

    /// Fold any user entry to the canonical passphrase: 24 uppercase Crockford
    /// symbols, no hyphens. Applies the look-alike substitutions before
    /// validating, so `o`/`O`→`0`, `i`/`l`→`1`, `u`→`V`. Whitespace and hyphens
    /// are ignored. Throws on an out-of-alphabet character or a wrong length —
    /// callers surface these to help the user correct a typo.
    static func normalize(_ input: String) throws -> String {
        var out = ""
        out.reserveCapacity(symbolCount)
        for raw in input {
            if raw == "-" || raw.isWhitespace { continue }
            let up = Character(raw.uppercased())
            let folded: Character
            switch up {
            case "O": folded = "0"
            case "I", "L": folded = "1"
            case "U": folded = "V"
            default: folded = up
            }
            guard alphabet.contains(folded) else {
                throw BackupCodeError.invalidCharacter(raw)
            }
            out.append(folded)
        }
        guard !out.isEmpty else { throw BackupCodeError.emptyInput }
        guard out.count == symbolCount else { throw BackupCodeError.wrongLength(out.count) }
        return out
    }

    /// The S2K passphrase for `input` — `normalize(_:)` by another name, for
    /// call sites that read better as "the passphrase behind this code."
    static func passphrase(from input: String) throws -> String {
        try normalize(input)
    }

    /// True when `input` normalizes to a well-formed code. Non-throwing helper
    /// for live field validation in the UI.
    static func isValid(_ input: String) -> Bool {
        (try? normalize(input)) != nil
    }

    // MARK: - Display formatting

    /// Insert group hyphens into a canonical (or partial) hyphen-free string.
    /// Used both to present a generated code and to reformat the entry field as
    /// the user types. Non-symbol characters are dropped first.
    static func format(_ canonical: String) -> String {
        let symbols = canonical.filter { $0 != "-" && !$0.isWhitespace }
        var groups: [String] = []
        var current = ""
        for ch in symbols {
            current.append(ch)
            if current.count == groupSize {
                groups.append(current)
                current = ""
            }
        }
        if !current.isEmpty { groups.append(current) }
        return groups.joined(separator: "-")
    }

    // MARK: - Base32 (Crockford, big-endian bitstream)

    /// Encode bytes as Crockford base32, MSB-first. For a byte count that is a
    /// multiple of 5 (our 15) the output has no leftover bits and needs no
    /// padding; the general path zero-pads the final partial symbol.
    static func encodeBase32(_ bytes: [UInt8]) -> String {
        var out = ""
        var buffer = 0
        var bitsInBuffer = 0
        for byte in bytes {
            buffer = (buffer << 8) | Int(byte)
            bitsInBuffer += 8
            while bitsInBuffer >= 5 {
                bitsInBuffer -= 5
                let index = (buffer >> bitsInBuffer) & 0x1F
                out.append(alphabet[index])
            }
        }
        if bitsInBuffer > 0 {
            let index = (buffer << (5 - bitsInBuffer)) & 0x1F
            out.append(alphabet[index])
        }
        return out
    }
}
