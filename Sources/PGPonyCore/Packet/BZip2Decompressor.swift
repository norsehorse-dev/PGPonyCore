// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// BZip2Decompressor.swift
// PGPony
//
// v8.1.1 — a tester's PC (GnuPG 2.5.17) produced OpenPGP messages compressed
// with BZip2 (RFC 4880 compression algorithm 3). PGPony had never implemented
// it — Apple's Compression framework covers LZFSE/ZLIB/LZ4/LZMA/Brotli but not
// BZip2, so there's no system API to lean on here, unlike the ZIP/ZLIB paths
// in OpenPGPPacketParser which call into Compression via zlibDecompress.
//
// This is a from-scratch decoder for the standard bzip2 stream format: a
// Huffman-coded stream of MTF ranks and RLE2 run symbols, an inverse
// Burrows-Wheeler transform, and inverse RLE1. It was validated before
// porting to Swift by running the equivalent algorithm in Python against
// Python's own `bz2` module (libbz2, the reference implementation) across
// empty/tiny/huge/random/highly-repetitive/full-alphabet/multi-block inputs,
// and against a real GnuPG-produced `--compress-algo BZIP2` packet.
//
// Decompression only — PGPony has no reason to ever produce BZip2 output,
// so there is no encoder here.

import Foundation

enum BZip2Error: Error, LocalizedError {
    case invalidHeader
    case invalidBlockHeader
    case randomizedBlockUnsupported
    case invalidHuffmanTable
    case truncatedStream

    var errorDescription: String? {
        switch self {
        case .invalidHeader: return "Not a valid BZip2 stream"
        case .invalidBlockHeader: return "Invalid BZip2 block header"
        case .randomizedBlockUnsupported: return "Deprecated randomized BZip2 blocks are not supported"
        case .invalidHuffmanTable: return "Invalid BZip2 Huffman table"
        case .truncatedStream: return "BZip2 stream ended unexpectedly"
        }
    }
}

enum BZip2Decompressor {

    /// Decompress a complete bzip2 stream — the standard `.bz2` container:
    /// "BZh" + block-size digit, one or more compressed blocks, then the
    /// end-of-stream marker — to its original bytes.
    static func decompress(
        _ input: [UInt8],
        limit: Int = SecurityLimits.maxInMemoryPlaintextBytes
    ) throws -> [UInt8] {
        var bits = BitReader(input)

        guard try bits.readBits(8) == UInt32(UInt8(ascii: "B")),
              try bits.readBits(8) == UInt32(UInt8(ascii: "Z")),
              try bits.readBits(8) == UInt32(UInt8(ascii: "h")) else {
            throw BZip2Error.invalidHeader
        }
        let level = try bits.readBits(8)
        guard level >= UInt32(UInt8(ascii: "1")), level <= UInt32(UInt8(ascii: "9")) else {
            throw BZip2Error.invalidHeader
        }
        let blockSize100k = Int(level - UInt32(UInt8(ascii: "0")))
        let maxBlockBytes = blockSize100k * 100_000

        var output: [UInt8] = []

        while true {
            let hi = try bits.readBits(24)
            let lo = try bits.readBits(24)
            let magic = (UInt64(hi) << 24) | UInt64(lo)

            if magic == 0x1772_4538_5090 {
                _ = try bits.readBits(32)   // combined stream CRC — not verified
                break
            }
            guard magic == 0x3141_5926_5359 else {
                throw BZip2Error.invalidBlockHeader
            }

            let block = try decodeBlock(&bits, maxBlockBytes: maxBlockBytes)
            // 8.3.0 hardening (finding 2): same ceiling as the zlib path.
            guard output.count + block.count <= limit else {
                throw SecurityLimitError.exceeded("compressed data inflates past \(limit >> 20) MiB")
            }
            output.append(contentsOf: block)
        }

        return output
    }

    // MARK: - Block decoding

    private static func decodeBlock(_ bits: inout BitReader, maxBlockBytes: Int) throws -> [UInt8] {
        _ = try bits.readBits(32)          // block CRC — not verified (best-effort decoder)
        let randomized = try bits.readBits(1)
        guard randomized == 0 else { throw BZip2Error.randomizedBlockUnsupported }
        let origPtr = Int(try bits.readBits(24))

        // --- Symbol map: which of the 256 byte values actually appear ---
        var used = [Bool](repeating: false, count: 256)
        let usedGroups = try bits.readBits(16)
        for g in 0..<16 {
            guard (usedGroups & (UInt32(1) << (15 - g))) != 0 else { continue }
            let bitsForGroup = try bits.readBits(16)
            for b in 0..<16 {
                if (bitsForGroup & (UInt32(1) << (15 - b))) != 0 {
                    used[g * 16 + b] = true
                }
            }
        }
        var seqToUnseq: [UInt8] = []
        seqToUnseq.reserveCapacity(256)
        for i in 0..<256 where used[i] { seqToUnseq.append(UInt8(i)) }
        let symCount = seqToUnseq.count
        guard symCount > 0 else { throw BZip2Error.invalidBlockHeader }
        let alphaSize = symCount + 2   // RUNA(0), RUNB(1), symCount-1 MTF values, EOB

        // --- Huffman tables (2–6 groups), selected per 50-symbol run ---
        let nGroups = Int(try bits.readBits(3))
        guard (2...6).contains(nGroups) else { throw BZip2Error.invalidHuffmanTable }
        let nSelectors = Int(try bits.readBits(15))

        var selectorsMTF = [Int](repeating: 0, count: nSelectors)
        for i in 0..<nSelectors {
            var j = 0
            while try bits.readBits(1) == 1 {
                j += 1
                guard j < nGroups else { throw BZip2Error.invalidHuffmanTable }
            }
            selectorsMTF[i] = j
        }
        var mtfGroups = Array(0..<nGroups)
        var selectors = [Int](repeating: 0, count: nSelectors)
        for i in 0..<nSelectors {
            let j = selectorsMTF[i]
            let v = mtfGroups[j]
            mtfGroups.remove(at: j)
            mtfGroups.insert(v, at: 0)
            selectors[i] = v
        }

        // --- Each group's canonical code lengths, delta-encoded ---
        var tables: [HuffmanTable] = []
        tables.reserveCapacity(nGroups)
        for _ in 0..<nGroups {
            var lengths = [Int](repeating: 0, count: alphaSize)
            var curr = Int(try bits.readBits(5))
            for s in 0..<alphaSize {
                while true {
                    guard (1...20).contains(curr) else { throw BZip2Error.invalidHuffmanTable }
                    if try bits.readBits(1) == 0 { break }
                    if try bits.readBits(1) == 0 { curr += 1 } else { curr -= 1 }
                }
                lengths[s] = curr
            }
            tables.append(try HuffmanTable(lengths: lengths))
        }

        // --- Decode the Huffman-coded MTF-rank / RLE2 symbol stream ---
        var mtfSymbols = Array(0..<symCount)
        var bwt = [UInt8]()
        bwt.reserveCapacity(min(maxBlockBytes, 1 << 20))

        var groupPos = 0
        var groupIdx = -1
        var table = tables[0]

        var runLength = 0
        var runBit = 0

        while true {
            if groupPos == 0 {
                groupIdx += 1
                guard groupIdx < nSelectors else { throw BZip2Error.invalidHuffmanTable }
                groupPos = 50
                table = tables[selectors[groupIdx]]
            }
            groupPos -= 1

            let sym = try table.decode(&bits)

            if sym <= 1 {
                // RUNA (0) / RUNB (1): bijective base-2 run-length encoding of
                // a run of the byte currently at the front of the MTF list.
                runLength += (sym == 0 ? 1 : 2) << runBit
                runBit += 1
                guard bwt.count + runLength <= maxBlockBytes else { throw BZip2Error.invalidBlockHeader }
                continue
            }

            if runLength > 0 {
                let b = seqToUnseq[mtfSymbols[0]]
                bwt.append(contentsOf: repeatElement(b, count: runLength))
                runLength = 0
                runBit = 0
            }

            if sym == alphaSize - 1 { break }   // EOB

            guard bwt.count < maxBlockBytes else { throw BZip2Error.invalidBlockHeader }
            let mtfIndex = sym - 1
            let v = mtfSymbols[mtfIndex]
            mtfSymbols.remove(at: mtfIndex)
            mtfSymbols.insert(v, at: 0)
            bwt.append(seqToUnseq[v])
        }

        // --- Inverse Burrows-Wheeler transform ---
        let n = bwt.count
        var count = [Int](repeating: 0, count: 256)
        for b in bwt { count[Int(b)] += 1 }
        var base = [Int](repeating: 0, count: 256)
        var total = 0
        for c in 0..<256 { base[c] = total; total += count[c] }

        var next = [Int](repeating: 0, count: n)
        var running = base
        for i in 0..<n {
            let c = Int(bwt[i])
            next[running[c]] = i
            running[c] += 1
        }

        guard origPtr < n || n == 0 else { throw BZip2Error.invalidBlockHeader }
        var decodedBWT = [UInt8](repeating: 0, count: n)
        if n > 0 {
            var row = next[origPtr]
            for i in 0..<n {
                decodedBWT[i] = bwt[row]
                row = next[row]
            }
        }

        // --- Inverse RLE1: 4 identical bytes are followed by a count byte
        // (0–251) of additional repeats. ---
        var result = [UInt8]()
        result.reserveCapacity(n)
        var i = 0
        while i < n {
            let b = decodedBWT[i]
            var run = 1
            while i + run < n, run < 4, decodedBWT[i + run] == b { run += 1 }
            result.append(contentsOf: repeatElement(b, count: run))
            i += run
            if run == 4 {
                guard i < n else { throw BZip2Error.truncatedStream }
                let extra = Int(decodedBWT[i])
                result.append(contentsOf: repeatElement(b, count: extra))
                i += 1
            }
        }

        return result
    }
}

/// MSB-first bit reader over a byte array — bzip2 packs fields (and Huffman
/// codes) big-endian at the bit level, unlike DEFLATE's LSB-first streams.
private struct BitReader {
    private let data: [UInt8]
    private var bytePos = 0
    private var bitPos = 0   // 0...7, next bit to read within data[bytePos], MSB first

    init(_ data: [UInt8]) {
        self.data = data
    }

    mutating func readBits(_ n: Int) throws -> UInt32 {
        var v: UInt32 = 0
        for _ in 0..<n {
            guard bytePos < data.count else { throw BZip2Error.truncatedStream }
            let bit = (data[bytePos] >> (7 - bitPos)) & 1
            v = (v << 1) | UInt32(bit)
            bitPos += 1
            if bitPos == 8 { bitPos = 0; bytePos += 1 }
        }
        return v
    }

    mutating func readBit() throws -> UInt32 {
        try readBits(1)
    }
}

/// Canonical Huffman decode table for one bzip2 code-length group. Decodes
/// one bit at a time against a (length, code) → symbol map — simple and easy
/// to verify against the reference algorithm; bzip2 code lengths are capped
/// at 20 bits so the per-symbol cost is bounded.
private struct HuffmanTable {
    private var codeToSymbol: [Int32: Int] = [:]
    private let maxLen: Int

    init(lengths: [Int]) throws {
        guard let maxL = lengths.max(), maxL > 0 else { throw BZip2Error.invalidHuffmanTable }
        maxLen = maxL
        let order = (0..<lengths.count).sorted { a, b in
            lengths[a] != lengths[b] ? lengths[a] < lengths[b] : a < b
        }
        var code: Int32 = 0
        var prevLen = 0
        for s in order {
            let l = lengths[s]
            code <<= Int32(l - prevLen)
            codeToSymbol[Self.key(length: l, code: code)] = s
            code += 1
            prevLen = l
        }
    }

    private static func key(length: Int, code: Int32) -> Int32 {
        (Int32(length) << 24) | code
    }

    func decode(_ bits: inout BitReader) throws -> Int {
        var code: Int32 = 0
        for l in 1...maxLen {
            code = (code << 1) | Int32(try bits.readBit())
            if let sym = codeToSymbol[Self.key(length: l, code: code)] {
                return sym
            }
        }
        throw BZip2Error.invalidHuffmanTable
    }
}
