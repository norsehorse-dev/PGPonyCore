// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// V6InteropDiagnostic.swift
// PGPony — v5.0 Phase 2b interop debugging
//
// Pure diagnostic: reads an ASCII-armored OpenPGP key blob (from clipboard),
// parses out v6 primary key + cert/binding signatures, reconstructs what
// PGPony's signing code would have hashed for each signature, computes SHA-512,
// and compares the first 2 bytes against the digest prefix that the source
// implementation actually stored in the signature packet.
//
// If our reconstructed digest prefix matches the stored prefix, our hash input
// construction matches the source implementation's, and the bug is elsewhere
// (e.g. Ed25519 signing input encoding). If it does not match, we have isolated
// the bug to the bytes we are hashing — and we can print both lengths and the
// first/last 64 bytes to see exactly where they diverge.

import Foundation
import CryptoKit
import CommonCrypto

enum V6Diag {

    // ------------------------------------------------------------------ Public

    /// Run the diagnostic on a clipboard-pasted armored OpenPGP blob.
    /// Prints findings to the console.
    static func runOnPasteboard(_ armored: String) {
        pgpDebugLog("==============================================")
        pgpDebugLog("V6 INTEROP DIAGNOSTIC")
        pgpDebugLog("==============================================")

        // Dearmor
        let bytes: [UInt8]
        do {
            bytes = try dearmor(armored)
        } catch {
            pgpDebugLog("DIAG: failed to dearmor input: \(error.localizedDescription)")
            return
        }
        pgpDebugLog("DIAG: dearmored \(bytes.count) bytes")

        // Walk packets
        let packets: [Packet]
        do {
            packets = try parsePackets(bytes)
        } catch {
            pgpDebugLog("DIAG: failed to parse packets: \(error.localizedDescription)")
            return
        }
        pgpDebugLog("DIAG: parsed \(packets.count) packets")
        for (i, p) in packets.enumerated() {
            pgpDebugLog("  [\(i)] tag=\(p.tag) bodyLen=\(p.body.count)")
        }

        // Find primary key packet (tag 6 public, OR tag 5 secret — public body sits at start of secret)
        guard let primaryIdx = packets.firstIndex(where: { $0.tag == 6 || $0.tag == 5 }) else {
            pgpDebugLog("DIAG: no public-key (tag 6) or secret-key (tag 5) packet found")
            return
        }
        let primary = packets[primaryIdx]
        guard primary.body.first == 6 else {
            pgpDebugLog("DIAG: primary key is not v6 (version byte = \(primary.body.first ?? 0))")
            return
        }
        // Extract just the public-key body (everything up through key material —
        // secret material follows for tag 5). For v6 Ed25519: 1+4+1+4+32 = 42 bytes.
        // For v6 X25519 it's also 42. Determine by reading algo + keyMatLen.
        let primaryBody: [UInt8]
        if primary.tag == 6 {
            primaryBody = primary.body
        } else {
            // Tag 5 (secret). Find end of public-key portion: 1(ver) + 4(time) + 1(algo) + 4(keyMatLen) + keyMatLen
            guard primary.body.count >= 10 else {
                pgpDebugLog("DIAG: tag 5 primary too short to extract public body")
                return
            }
            let kml = (Int(primary.body[6]) << 24) | (Int(primary.body[7]) << 16) |
                      (Int(primary.body[8]) << 8) | Int(primary.body[9])
            let pubEnd = 10 + kml
            guard pubEnd <= primary.body.count else {
                pgpDebugLog("DIAG: tag 5 primary truncated (keyMatLen=\(kml), body=\(primary.body.count))")
                return
            }
            primaryBody = Array(primary.body[0..<pubEnd])
        }
        pgpDebugLog("DIAG: primary v6 key body (public portion): \(primaryBody.count) bytes")
        let fp = computeV6Fingerprint(packetBody: primaryBody)
        pgpDebugLog("DIAG: computed v6 fingerprint: \(hex(fp))")

        // Find first signature packet (tag 2)
        guard let sigIdx = packets.firstIndex(where: { $0.tag == 2 }) else {
            pgpDebugLog("DIAG: no signature packet (tag 2) found")
            return
        }
        let sigPacket = packets[sigIdx]
        pgpDebugLog("DIAG: found first signature packet at index \(sigIdx)")

        // Parse the v6 sig packet
        let parsed: ParsedV6Sig
        do {
            parsed = try parseV6Sig(sigPacket.body)
        } catch {
            pgpDebugLog("DIAG: failed to parse v6 sig: \(error.localizedDescription)")
            return
        }
        pgpDebugLog("DIAG: sig version=\(parsed.version) type=0x\(String(format: "%02x", parsed.sigType)) pubAlgo=\(parsed.pubAlgo) hashAlgo=\(parsed.hashAlgo)")
        pgpDebugLog("DIAG: hashedSPs=\(parsed.hashedSubpackets.count)B unhashedSPs=\(parsed.unhashedSubpackets.count)B")
        pgpDebugLog("DIAG: stored digest prefix: \(hex(parsed.digestPrefix))")
        pgpDebugLog("DIAG: salt(\(parsed.salt.count)B): \(hex(parsed.salt))")
        pgpDebugLog("DIAG: sigBytes len: \(parsed.sigData.count)")
        pgpDebugLog("DIAG: rawHashedPortion: \(parsed.rawHashedPortion.count)B")
        pgpDebugLog("DIAG: rawHashedPortion hex first 48B: \(hex(Array(parsed.rawHashedPortion.prefix(48))))")

        guard parsed.version == 6 else {
            pgpDebugLog("DIAG: sig is v\(parsed.version), not v6 — wrong test target")
            return
        }
        guard parsed.hashAlgo == 10 else {
            pgpDebugLog("DIAG: sig uses hashAlgo \(parsed.hashAlgo), expected 10 (SHA-512)")
            return
        }

        // Determine document chunks based on sig type
        let documentHashChunks: [UInt8]
        switch parsed.sigType {
        case 0x1F:
            // DirectKey: just the primary key
            documentHashChunks = wrapV6Key(primaryBody)
            pgpDebugLog("DIAG: building DirectKey document chunks (primary only)")

        case 0x10, 0x11, 0x12, 0x13:
            // Certification: primary + user ID. Find the user ID packet immediately before the sig.
            guard let uidIdx = packets[..<sigIdx].lastIndex(where: { $0.tag == 13 }) else {
                pgpDebugLog("DIAG: certification sig but no user ID packet before it")
                return
            }
            let uid = packets[uidIdx].body
            pgpDebugLog("DIAG: building Certification document chunks (primary + uid: \"\(String(decoding: uid, as: UTF8.self))\")")
            documentHashChunks = wrapV6Key(primaryBody) + wrapUserID(uid)

        case 0x18:
            // Subkey Binding: primary + subkey. Find subkey (tag 14 public OR tag 7 secret) before the sig.
            guard let subIdx = packets[..<sigIdx].lastIndex(where: { $0.tag == 14 || $0.tag == 7 }) else {
                pgpDebugLog("DIAG: subkey-binding sig but no subkey packet before it")
                return
            }
            let subPacket = packets[subIdx]
            let subBody: [UInt8]
            if subPacket.tag == 14 {
                subBody = subPacket.body
            } else {
                // tag 7: extract public portion (same layout as primary tag 5)
                guard subPacket.body.count >= 10 else {
                    pgpDebugLog("DIAG: tag 7 subkey too short")
                    return
                }
                let kml = (Int(subPacket.body[6]) << 24) | (Int(subPacket.body[7]) << 16) |
                          (Int(subPacket.body[8]) << 8) | Int(subPacket.body[9])
                let pubEnd = 10 + kml
                guard pubEnd <= subPacket.body.count else {
                    pgpDebugLog("DIAG: tag 7 subkey truncated")
                    return
                }
                subBody = Array(subPacket.body[0..<pubEnd])
            }
            pgpDebugLog("DIAG: building SubkeyBinding document chunks (primary + subkey body \(subBody.count)B)")
            documentHashChunks = wrapV6Key(primaryBody) + wrapV6Key(subBody)

        default:
            pgpDebugLog("DIAG: unsupported sig type 0x\(String(format: "%02x", parsed.sigType)) for this diagnostic")
            return
        }

        pgpDebugLog("DIAG: documentHashChunks: \(documentHashChunks.count)B")
        pgpDebugLog("DIAG: documentHashChunks first 64B: \(hex(Array(documentHashChunks.prefix(64))))")

        // Reconstruct hash input using OUR construction
        var hashInput = Data()
        hashInput.append(contentsOf: parsed.salt)
        hashInput.append(contentsOf: documentHashChunks)
        hashInput.append(contentsOf: parsed.rawHashedPortion)
        let totalHashed = UInt32(parsed.rawHashedPortion.count)
        hashInput.append(0x06)
        hashInput.append(0xFF)
        hashInput.append(UInt8((totalHashed >> 24) & 0xFF))
        hashInput.append(UInt8((totalHashed >> 16) & 0xFF))
        hashInput.append(UInt8((totalHashed >>  8) & 0xFF))
        hashInput.append(UInt8( totalHashed        & 0xFF))

        pgpDebugLog("DIAG: reconstructed hash input total = \(hashInput.count)B")
        let hashInputArr = Array(hashInput)
        pgpDebugLog("DIAG: hashInput first 96B: \(hex(Array(hashInputArr.prefix(96))))")
        pgpDebugLog("DIAG: hashInput last 32B:  \(hex(Array(hashInputArr.suffix(32))))")

        // Compute SHA-512
        let digest = SHA512.hash(data: hashInput)
        let digestBytes = Array(digest)
        let myPrefix = Array(digestBytes.prefix(2))
        pgpDebugLog("DIAG: our computed digest first 2 bytes: \(hex(myPrefix))")
        pgpDebugLog("DIAG: source stored digest prefix:       \(hex(parsed.digestPrefix))")

        if myPrefix == parsed.digestPrefix {
            pgpDebugLog("DIAG: ✅ DIGEST PREFIX MATCH — our hash input matches the source implementation")
            pgpDebugLog("DIAG:    The bug must be in something else (e.g. Ed25519 sign/verify, key bytes).")
        } else {
            pgpDebugLog("DIAG: ❌ DIGEST PREFIX MISMATCH — our hash input differs from the source.")
            pgpDebugLog("DIAG:    Comparing constructed vs. expected bytes will pinpoint the bug.")
        }

        // Bonus: try a few common variants quickly — maybe one matches
        pgpDebugLog("DIAG: trying variant hash inputs to look for a match...")
        tryVariant("no salt", input: Data(documentHashChunks) + Data(parsed.rawHashedPortion) + v6Trailer(rawHashed: parsed.rawHashedPortion), expected: parsed.digestPrefix)
        tryVariant("salt at end (before trailer)", input: Data(documentHashChunks) + Data(parsed.rawHashedPortion) + Data(parsed.salt) + v6Trailer(rawHashed: parsed.rawHashedPortion), expected: parsed.digestPrefix)
        var v1in = Data(parsed.salt); v1in.append(Data(documentHashChunks)); v1in.append(Data(parsed.rawHashedPortion))
        v1in.append(v6Trailer(count: UInt32(parsed.salt.count + documentHashChunks.count + parsed.rawHashedPortion.count)))
        tryVariant("trailer count = full hashInput-trailer length", input: v1in, expected: parsed.digestPrefix)
        tryVariant("no salt + count = full", input: Data(documentHashChunks) + Data(parsed.rawHashedPortion) + v6Trailer(count: UInt32(documentHashChunks.count + parsed.rawHashedPortion.count)), expected: parsed.digestPrefix)
        tryVariant("salt at start, trailer 0x04 0xFF + 4-byte count (v4 style)", input: Data(parsed.salt) + Data(documentHashChunks) + Data(parsed.rawHashedPortion) + v4Trailer(rawHashed: parsed.rawHashedPortion), expected: parsed.digestPrefix)
        tryVariant("v4-style key wrap (0x99 + 2-byte len) for v6 key body", input: {
            // re-wrap primary key with v4 prefix
            var alt: [UInt8] = []
            alt.append(0x99)
            let l = UInt16(primaryBody.count)
            alt.append(UInt8(l >> 8))
            alt.append(UInt8(l & 0xFF))
            alt.append(contentsOf: primaryBody)
            // for cert sig, also add uid; for binding, also add subkey; here we just test directkey-ish
            return Data(parsed.salt) + Data(alt) + Data(parsed.rawHashedPortion) + v6Trailer(rawHashed: parsed.rawHashedPortion)
        }(), expected: parsed.digestPrefix)
        tryVariant("trailer count = just hashedSubpackets length",
                   input: Data(parsed.salt) + Data(documentHashChunks) + Data(parsed.rawHashedPortion) + v6Trailer(count: UInt32(parsed.hashedSubpackets.count)),
                   expected: parsed.digestPrefix)
        tryVariant("doc chunks order: rawHashed BEFORE document",
                   input: Data(parsed.salt) + Data(parsed.rawHashedPortion) + Data(documentHashChunks) + v6Trailer(rawHashed: parsed.rawHashedPortion),
                   expected: parsed.digestPrefix)
        tryVariant("salt + raw (no document at all)",
                   input: Data(parsed.salt) + Data(parsed.rawHashedPortion) + v6Trailer(rawHashed: parsed.rawHashedPortion),
                   expected: parsed.digestPrefix)
        tryVariant("doc + raw (no salt, no trailer)",
                   input: Data(documentHashChunks) + Data(parsed.rawHashedPortion),
                   expected: parsed.digestPrefix)
        tryVariant("salt + doc + raw (no trailer)",
                   input: Data(parsed.salt) + Data(documentHashChunks) + Data(parsed.rawHashedPortion),
                   expected: parsed.digestPrefix)
        tryVariant("HKDF-style: hash salt first then continue",
                   input: {
                       // Use salt as a separate hash prefix, then continue with doc + raw + trailer
                       var h = SHA512()
                       h.update(data: Data(parsed.salt))
                       h.update(data: Data(documentHashChunks))
                       h.update(data: Data(parsed.rawHashedPortion))
                       h.update(data: v6Trailer(rawHashed: parsed.rawHashedPortion))
                       _ = h.finalize()
                       // (just shows that successive updates equal contiguous data, no actual difference)
                       return Data(parsed.salt) + Data(documentHashChunks) + Data(parsed.rawHashedPortion) + v6Trailer(rawHashed: parsed.rawHashedPortion)
                   }(),
                   expected: parsed.digestPrefix)
        var v2in = Data(parsed.salt); v2in.append(Data(documentHashChunks)); v2in.append(Data(parsed.rawHashedPortion))
        v2in.append(v6Trailer(count: UInt32(parsed.salt.count + documentHashChunks.count + parsed.rawHashedPortion.count + 10)))
        tryVariant("trailer count = total hashed including trailer (10 extra)",
                   input: v2in,
                   expected: parsed.digestPrefix)
        // Specifically for DirectKey: maybe no document chunk at all
        if parsed.sigType == 0x1F {
            tryVariant("DirectKey: salt + raw + trailer (no key in hash)",
                       input: Data(parsed.salt) + Data(parsed.rawHashedPortion) + v6Trailer(rawHashed: parsed.rawHashedPortion),
                       expected: parsed.digestPrefix)
            tryVariant("DirectKey: primary key BODY without 0x9B wrap",
                       input: Data(parsed.salt) + Data(primaryBody) + Data(parsed.rawHashedPortion) + v6Trailer(rawHashed: parsed.rawHashedPortion),
                       expected: parsed.digestPrefix)
        }

        // ---- BRUTE FORCE: try every reasonable combination of fragments ----
        pgpDebugLog("DIAG: BRUTE FORCE — trying combinatorial arrangements...")
        let fragments: [(String, [UInt8])] = [
            ("salt", parsed.salt),
            ("docChunks", documentHashChunks),
            ("primaryBody", primaryBody),
            ("rawHashed", parsed.rawHashedPortion),
            ("hashedSPs", parsed.hashedSubpackets),
            ("v6Trailer", Array(v6Trailer(rawHashed: parsed.rawHashedPortion))),
            ("v6TrailerHashedSPs", Array(v6Trailer(count: UInt32(parsed.hashedSubpackets.count)))),
            ("0x9B+lenPrimary", {
                var x: [UInt8] = [0x9B]
                let l = UInt32(primaryBody.count)
                x.append(UInt8(l >> 24)); x.append(UInt8(l >> 16))
                x.append(UInt8(l >> 8)); x.append(UInt8(l & 0xFF))
                return x
            }()),
        ]
        // Try all 1, 2, 3, 4 element ordered combinations
        bruteForce(fragments: fragments, target: parsed.digestPrefix, maxLen: 4)
        pgpDebugLog("DIAG: ...brute force done")

        pgpDebugLog("==============================================")
    }

    // ------------------------------------------------------------------ Helpers

    private static func tryVariant(_ name: String, input: Data, expected: [UInt8]) {
        let d = SHA512.hash(data: input)
        let p = Array(d.prefix(2))
        let ok = p == expected ? "✅ MATCH" : "  "
        pgpDebugLog("DIAG variant [\(name)] → \(hex(p))  \(ok)")
    }

    /// Try every ordered combination of 1..maxLen fragments. Print any matches found.
    private static func bruteForce(fragments: [(String, [UInt8])], target: [UInt8], maxLen: Int) {
        var matchCount = 0
        func recurse(picked: [Int], depth: Int) {
            if depth > 0 {
                var buf = Data()
                var labels: [String] = []
                for i in picked {
                    buf.append(contentsOf: fragments[i].1)
                    labels.append(fragments[i].0)
                }
                let d = SHA512.hash(data: buf)
                let p = Array(d.prefix(2))
                if p == target {
                    pgpDebugLog("DIAG ✅ BRUTE-FORCE MATCH: \(labels.joined(separator: " + ")) → \(hex(p))")
                    matchCount += 1
                }
            }
            if depth >= maxLen { return }
            for i in 0..<fragments.count {
                recurse(picked: picked + [i], depth: depth + 1)
            }
        }
        recurse(picked: [], depth: 0)
        if matchCount == 0 {
            pgpDebugLog("DIAG: no brute-force match found in \(fragments.count) fragments x up to \(maxLen) deep")
        }
    }

    private static func v6Trailer(rawHashed: [UInt8]) -> Data {
        return v6Trailer(count: UInt32(rawHashed.count))
    }
    private static func v6Trailer(count: UInt32) -> Data {
        var out = Data()
        out.append(0x06)
        out.append(0xFF)
        out.append(UInt8((count >> 24) & 0xFF))
        out.append(UInt8((count >> 16) & 0xFF))
        out.append(UInt8((count >>  8) & 0xFF))
        out.append(UInt8( count        & 0xFF))
        return out
    }
    private static func v4Trailer(rawHashed: [UInt8]) -> Data {
        var out = Data()
        out.append(0x04)
        out.append(0xFF)
        let count = UInt32(rawHashed.count)
        out.append(UInt8((count >> 24) & 0xFF))
        out.append(UInt8((count >> 16) & 0xFF))
        out.append(UInt8((count >>  8) & 0xFF))
        out.append(UInt8( count        & 0xFF))
        return out
    }

    private static func wrapV6Key(_ body: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        out.append(0x9B)
        let l = UInt32(body.count)
        out.append(UInt8((l >> 24) & 0xFF))
        out.append(UInt8((l >> 16) & 0xFF))
        out.append(UInt8((l >>  8) & 0xFF))
        out.append(UInt8( l        & 0xFF))
        out.append(contentsOf: body)
        return out
    }

    private static func wrapUserID(_ body: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        out.append(0xB4)
        let l = UInt32(body.count)
        out.append(UInt8((l >> 24) & 0xFF))
        out.append(UInt8((l >> 16) & 0xFF))
        out.append(UInt8((l >>  8) & 0xFF))
        out.append(UInt8( l        & 0xFF))
        out.append(contentsOf: body)
        return out
    }

    // ------------------------------------------------------------------ v6 fingerprint

    private static func computeV6Fingerprint(packetBody: [UInt8]) -> [UInt8] {
        var input: [UInt8] = []
        input.append(0x9B)
        let l = UInt32(packetBody.count)
        input.append(UInt8((l >> 24) & 0xFF))
        input.append(UInt8((l >> 16) & 0xFF))
        input.append(UInt8((l >>  8) & 0xFF))
        input.append(UInt8( l        & 0xFF))
        input.append(contentsOf: packetBody)
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256(input, CC_LONG(input.count), &hash)
        return hash
    }

    // ------------------------------------------------------------------ v6 sig parsing

    private struct ParsedV6Sig {
        let version: UInt8
        let sigType: UInt8
        let pubAlgo: UInt8
        let hashAlgo: UInt8
        let hashedSubpackets: [UInt8]
        let unhashedSubpackets: [UInt8]
        let digestPrefix: [UInt8]   // 2 bytes
        let salt: [UInt8]
        let sigData: [UInt8]
        let rawHashedPortion: [UInt8]  // body[0..<end of hashed subpackets]
    }

    private enum V6DiagError: Error { case truncated(String) }

    private static func parseV6Sig(_ body: [UInt8]) throws -> ParsedV6Sig {
        var off = 0
        func need(_ n: Int, _ what: String) throws {
            guard off + n <= body.count else { throw V6DiagError.truncated(what) }
        }

        try need(4, "header")
        let version = body[off]; off += 1
        let sigType = body[off]; off += 1
        let pubAlgo = body[off]; off += 1
        let hashAlgo = body[off]; off += 1

        try need(4, "hashed len")
        let hashedLen = (Int(body[off]) << 24) | (Int(body[off+1]) << 16) |
                        (Int(body[off+2]) << 8) | Int(body[off+3])
        off += 4
        try need(hashedLen, "hashed subpackets")
        let hashed = Array(body[off..<(off + hashedLen)])
        off += hashedLen

        let raw = Array(body[0..<off])  // version..end of hashed subpackets

        try need(4, "unhashed len")
        let unhashedLen = (Int(body[off]) << 24) | (Int(body[off+1]) << 16) |
                          (Int(body[off+2]) << 8) | Int(body[off+3])
        off += 4
        try need(unhashedLen, "unhashed subpackets")
        let unhashed = Array(body[off..<(off + unhashedLen)])
        off += unhashedLen

        try need(2, "digest prefix")
        let prefix = Array(body[off..<(off + 2)])
        off += 2

        try need(1, "salt len")
        let saltLen = Int(body[off]); off += 1
        try need(saltLen, "salt")
        let salt = Array(body[off..<(off + saltLen)])
        off += saltLen

        let sig = Array(body[off..<body.count])

        return ParsedV6Sig(
            version: version, sigType: sigType, pubAlgo: pubAlgo, hashAlgo: hashAlgo,
            hashedSubpackets: hashed, unhashedSubpackets: unhashed,
            digestPrefix: prefix, salt: salt, sigData: sig,
            rawHashedPortion: raw
        )
    }

    // ------------------------------------------------------------------ Packet stream parsing

    private struct Packet { let tag: UInt8; let body: [UInt8] }

    private static func parsePackets(_ bytes: [UInt8]) throws -> [Packet] {
        var out: [Packet] = []
        var off = 0
        while off < bytes.count {
            try parseOnePacket(bytes, off: &off, into: &out)
        }
        return out
    }

    private static func parseOnePacket(_ bytes: [UInt8], off: inout Int, into out: inout [Packet]) throws {
        guard off < bytes.count else { return }
        let hdr = bytes[off]; off += 1
        guard (hdr & 0x80) != 0 else { throw V6DiagError.truncated("missing packet hdr bit") }
        let newFormat = (hdr & 0x40) != 0
        let tag: UInt8
        var bodyLen: Int

        if newFormat {
            tag = hdr & 0x3F
            guard off < bytes.count else { throw V6DiagError.truncated("len byte 1") }
            let b1 = Int(bytes[off]); off += 1
            if b1 < 192 {
                bodyLen = b1
            } else if b1 < 224 {
                guard off < bytes.count else { throw V6DiagError.truncated("len byte 2") }
                bodyLen = ((b1 - 192) << 8) + Int(bytes[off]) + 192
                off += 1
            } else if b1 == 0xFF {
                guard off + 4 <= bytes.count else { throw V6DiagError.truncated("5-byte len") }
                bodyLen = (Int(bytes[off]) << 24) | (Int(bytes[off+1]) << 16) |
                          (Int(bytes[off+2]) << 8) | Int(bytes[off+3])
                off += 4
            } else {
                // Partial body length — not expected in keys we test
                throw V6DiagError.truncated("partial body length not supported here")
            }
        } else {
            tag = (hdr >> 2) & 0x0F
            let lenType = hdr & 0x03
            switch lenType {
            case 0:
                guard off < bytes.count else { throw V6DiagError.truncated("legacy len 1") }
                bodyLen = Int(bytes[off]); off += 1
            case 1:
                guard off + 2 <= bytes.count else { throw V6DiagError.truncated("legacy len 2") }
                bodyLen = (Int(bytes[off]) << 8) | Int(bytes[off+1])
                off += 2
            case 2:
                guard off + 4 <= bytes.count else { throw V6DiagError.truncated("legacy len 4") }
                bodyLen = (Int(bytes[off]) << 24) | (Int(bytes[off+1]) << 16) |
                          (Int(bytes[off+2]) << 8) | Int(bytes[off+3])
                off += 4
            default:
                throw V6DiagError.truncated("legacy indeterminate length not supported")
            }
        }

        guard off + bodyLen <= bytes.count else { throw V6DiagError.truncated("body bytes for tag \(tag)") }
        let body = Array(bytes[off..<(off + bodyLen)])
        off += bodyLen
        out.append(Packet(tag: tag, body: body))
    }

    // ------------------------------------------------------------------ Dearmor + hex

    private static func dearmor(_ armored: String) throws -> [UInt8] {
        let normalized = armored.replacingOccurrences(of: "\r\n", with: "\n")
        let lines = normalized.components(separatedBy: "\n")
        var inBody = false, headersDone = false
        var b64 = ""
        for line in lines {
            let t = line.trimmingCharacters(in: .whitespaces)
            if !inBody {
                if t.hasPrefix("-----BEGIN PGP") { inBody = true }
                continue
            }
            if t.hasPrefix("-----END PGP") { break }
            if t.hasPrefix("=") { continue }       // CRC line
            if t.isEmpty { headersDone = true; continue }
            if !headersDone, t.contains(":") { continue }
            headersDone = true
            b64.append(t)
        }
        guard let data = Data(base64Encoded: b64) else {
            throw NSError(domain: "V6Diag", code: 1, userInfo: [NSLocalizedDescriptionKey: "base64 decode failed"])
        }
        return Array(data)
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined(separator: " ")
    }
}
