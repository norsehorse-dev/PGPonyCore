// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CardCommandChainTests.swift
// PGPonyTests
//
// HW-R1: tests for OpenPGPCardService.commandChainBlocks — the pure planner that
// splits an oversized command data field into ISO 7816-4 command-chaining blocks.
//
// Short APDUs cap the data field at 255 bytes, so any command with a larger data
// field (the motivating case is RSA-4096 PSO:DECIPHER, whose input is 513 bytes:
// one 0x00 padding-indicator byte plus a 512-byte ciphertext block) must be sent
// as a chain. Intermediate blocks carry CLA 0x10; the final block carries CLA
// 0x00. These tests pin the block sizing, the CLA assignment, and lossless
// reassembly without any NFC hardware.

import XCTest
@testable import PGPonyCore

final class CardCommandChainTests: XCTestCase {

    // MARK: - Helpers

    /// Bytes 0,1,2,...,n-1 mod 256, so reassembly can be checked exactly.
    private func ramp(_ n: Int) -> [UInt8] {
        (0..<n).map { UInt8($0 & 0xFF) }
    }

    /// Invariants every plan must satisfy regardless of input size.
    private func assertWellFormed(_ blocks: [OpenPGPCardService.CommandChainBlock],
                                  original: [UInt8],
                                  file: StaticString = #file, line: UInt = #line) {
        XCTAssertFalse(blocks.isEmpty, "a plan always has at least one block", file: file, line: line)

        // Exactly one terminal block, and it is the last element.
        let lastFlags = blocks.map { $0.isLast }
        XCTAssertEqual(lastFlags.filter { $0 }.count, 1, "exactly one isLast block", file: file, line: line)
        XCTAssertTrue(blocks.last?.isLast == true, "the final block is the terminal one", file: file, line: line)

        // CLA invariant: intermediates 0x10, terminal 0x00.
        for block in blocks {
            XCTAssertEqual(block.cla, block.isLast ? 0x00 : 0x10,
                           "CLA must be 0x10 for intermediate blocks and 0x00 for the last",
                           file: file, line: line)
        }

        // Lossless: concatenated block data reproduces the input exactly.
        let reassembled = blocks.flatMap { $0.data }
        XCTAssertEqual(reassembled, original, "blocks must reassemble to the original data", file: file, line: line)
    }

    // MARK: - Single-block (no chaining needed)

    func testEmptyDataYieldsSingleEmptyFinalBlock() {
        let blocks = OpenPGPCardService.commandChainBlocks(data: [])
        XCTAssertEqual(blocks.count, 1)
        XCTAssertEqual(blocks[0].cla, 0x00)
        XCTAssertTrue(blocks[0].isLast)
        XCTAssertTrue(blocks[0].data.isEmpty)
    }

    func testOneByteIsASingleFinalBlock() {
        let data = ramp(1)
        let blocks = OpenPGPCardService.commandChainBlocks(data: data)
        XCTAssertEqual(blocks.count, 1)
        XCTAssertEqual(blocks[0].cla, 0x00)
        XCTAssertTrue(blocks[0].isLast)
        assertWellFormed(blocks, original: data)
    }

    func testExactly255FitsInOneBlock() {
        let data = ramp(255)
        let blocks = OpenPGPCardService.commandChainBlocks(data: data)
        XCTAssertEqual(blocks.count, 1)
        XCTAssertEqual(blocks[0].data.count, 255)
        XCTAssertEqual(blocks[0].cla, 0x00)
        XCTAssertTrue(blocks[0].isLast)
        assertWellFormed(blocks, original: data)
    }

    // MARK: - Boundary just past one block

    func test256SplitsInto255Plus1() {
        let data = ramp(256)
        let blocks = OpenPGPCardService.commandChainBlocks(data: data)
        XCTAssertEqual(blocks.count, 2)
        XCTAssertEqual(blocks[0].data.count, 255)
        XCTAssertEqual(blocks[0].cla, 0x10)
        XCTAssertFalse(blocks[0].isLast)
        XCTAssertEqual(blocks[1].data.count, 1)
        XCTAssertEqual(blocks[1].cla, 0x00)
        XCTAssertTrue(blocks[1].isLast)
        assertWellFormed(blocks, original: data)
    }

    // MARK: - RSA decrypt input sizes (the reason HW-R1 exists)

    func testRSA4096DecryptInput513SplitsInto255_255_3() {
        // 0x00 padding-indicator byte + 512-byte ciphertext block.
        let data = [UInt8(0x00)] + ramp(512)
        XCTAssertEqual(data.count, 513)
        let blocks = OpenPGPCardService.commandChainBlocks(data: data)
        XCTAssertEqual(blocks.map { $0.data.count }, [255, 255, 3])
        XCTAssertEqual(blocks.map { $0.cla }, [0x10, 0x10, 0x00])
        XCTAssertEqual(blocks.map { $0.isLast }, [false, false, true])
        assertWellFormed(blocks, original: data)
    }

    func testRSA3072DecryptInput385SplitsInto255Plus130() {
        // RSA-3072 modulus is 384 bytes; PSO:DECIPHER input is 0x00 + 384.
        let data = [UInt8(0x00)] + ramp(384)
        XCTAssertEqual(data.count, 385)
        let blocks = OpenPGPCardService.commandChainBlocks(data: data)
        XCTAssertEqual(blocks.map { $0.data.count }, [255, 130])
        XCTAssertEqual(blocks.map { $0.cla }, [0x10, 0x00])
        assertWellFormed(blocks, original: data)
    }

    func testRSA2048DecryptInput257SplitsInto255Plus2() {
        // RSA-2048 modulus is 256 bytes; PSO:DECIPHER input is 0x00 + 256.
        let data = [UInt8(0x00)] + ramp(256)
        XCTAssertEqual(data.count, 257)
        let blocks = OpenPGPCardService.commandChainBlocks(data: data)
        XCTAssertEqual(blocks.map { $0.data.count }, [255, 2])
        XCTAssertEqual(blocks.map { $0.cla }, [0x10, 0x00])
        assertWellFormed(blocks, original: data)
    }

    // MARK: - Exact multiple of the block size

    func testExactMultipleOfMaxBlockHasNoEmptyTail() {
        let data = ramp(510) // 2 * 255
        let blocks = OpenPGPCardService.commandChainBlocks(data: data)
        XCTAssertEqual(blocks.count, 2, "an exact multiple must not produce a trailing empty block")
        XCTAssertEqual(blocks.map { $0.data.count }, [255, 255])
        XCTAssertEqual(blocks.map { $0.cla }, [0x10, 0x00])
        XCTAssertEqual(blocks.map { $0.isLast }, [false, true])
        assertWellFormed(blocks, original: data)
    }

    // MARK: - Custom maxBlock (chunking logic in isolation)

    func testCustomMaxBlockChunksEvenly() {
        let data = ramp(10)
        let blocks = OpenPGPCardService.commandChainBlocks(data: data, maxBlock: 4)
        XCTAssertEqual(blocks.map { $0.data.count }, [4, 4, 2])
        XCTAssertEqual(blocks.map { $0.cla }, [0x10, 0x10, 0x00])
        assertWellFormed(blocks, original: data)
    }

    func testMaxBlockOfOneProducesOneBlockPerByte() {
        let data = ramp(5)
        let blocks = OpenPGPCardService.commandChainBlocks(data: data, maxBlock: 1)
        XCTAssertEqual(blocks.count, 5)
        XCTAssertEqual(blocks.map { $0.cla }, [0x10, 0x10, 0x10, 0x10, 0x00])
        assertWellFormed(blocks, original: data)
    }

    // MARK: - SW2 → Le mapping (HW-R2.1)

    func testLeFromSW2TreatsZeroAs256() {
        // 0x61 00 / 0x6C 00 mean "256 bytes", not zero. RSA-4096's 512-byte
        // response is the first thing to drive this path.
        XCTAssertEqual(OpenPGPCardService.leFromSW2(0x00), 256)
        XCTAssertEqual(OpenPGPCardService.leFromSW2(0x01), 1)
        XCTAssertEqual(OpenPGPCardService.leFromSW2(0xFF), 255)
    }
}
