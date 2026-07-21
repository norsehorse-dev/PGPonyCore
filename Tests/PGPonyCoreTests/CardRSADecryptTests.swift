// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CardRSADecryptTests.swift
// PGPonyTests
//
// HW-R3: RSA decryption on the card (PSO:DECIPHER).
//   - commandChainBlocks for the RSA-4096 decrypt input (513 bytes: a 0x00
//     padding-indicator byte + a 512-byte cryptogram) must split into chained
//     blocks, since it exceeds the 255-byte short-APDU data limit.
//   - parseCardSessionKeyBlock validates the 2-byte checksum the card returns
//     alongside the unpadded session key.
//
// The card transform itself and the SEIPD decrypt are validated on device by a
// gpg --encrypt → app-decrypt round-trip.

import XCTest
@testable import PGPonyCore

final class CardRSADecryptTests: XCTestCase {

    // MARK: - Command chaining for the 513-byte RSA-4096 decrypt input

    func testRSA4096DecryptInputChainsIntoThreeBlocks() {
        // 0x00 indicator + 512-byte cryptogram = 513 bytes.
        let input = [UInt8](repeating: 0xAB, count: 513)
        let blocks = OpenPGPCardService.commandChainBlocks(data: input)

        XCTAssertEqual(blocks.count, 3)
        XCTAssertEqual(blocks[0].data.count, 255)
        XCTAssertEqual(blocks[1].data.count, 255)
        XCTAssertEqual(blocks[2].data.count, 3)

        // Intermediate blocks carry CLA 0x10; the final block CLA 0x00.
        XCTAssertEqual(blocks[0].cla, 0x10); XCTAssertFalse(blocks[0].isLast)
        XCTAssertEqual(blocks[1].cla, 0x10); XCTAssertFalse(blocks[1].isLast)
        XCTAssertEqual(blocks[2].cla, 0x00); XCTAssertTrue(blocks[2].isLast)

        // Reassembling the blocks reproduces the input.
        let reassembled = blocks.flatMap { $0.data }
        XCTAssertEqual(reassembled, input)
    }

    func testRSA2048DecryptInputFitsButSpansTwoBlocks() {
        // RSA-2048: 0x00 + 256-byte cryptogram = 257 bytes → still over 255.
        let input = [UInt8](repeating: 0x11, count: 257)
        let blocks = OpenPGPCardService.commandChainBlocks(data: input)
        XCTAssertEqual(blocks.count, 2)
        XCTAssertEqual(blocks[0].cla, 0x10)
        XCTAssertEqual(blocks[1].cla, 0x00)
        XCTAssertEqual(blocks[1].data.count, 2)
    }

    // MARK: - Session-key block parsing (card PSO:DECIPHER output)

    func testParseCardSessionKeyBlockValid() throws {
        // AES-256 (algo 9), 32-byte key, checksum = sum of key bytes.
        let key = [UInt8](repeating: 0x01, count: 32)   // sum = 32 = 0x0020
        let block: [UInt8] = [9] + key + [0x00, 0x20]
        let result = try OpenPGPPacketParser.parseCardSessionKeyBlock(block)
        XCTAssertEqual(result.algorithmID, 9)
        XCTAssertEqual(result.sessionKey, key)
    }

    func testParseCardSessionKeyBlockAES128() throws {
        // AES-128 (algo 7), 16-byte key all 0x02 → sum = 32 = 0x0020.
        let key = [UInt8](repeating: 0x02, count: 16)
        let block: [UInt8] = [7] + key + [0x00, 0x20]
        let result = try OpenPGPPacketParser.parseCardSessionKeyBlock(block)
        XCTAssertEqual(result.algorithmID, 7)
        XCTAssertEqual(result.sessionKey, key)
    }

    func testParseCardSessionKeyBlockChecksumMismatchThrows() {
        let key = [UInt8](repeating: 0x01, count: 32)
        let block: [UInt8] = [9] + key + [0x00, 0x21]   // wrong checksum
        XCTAssertThrowsError(try OpenPGPPacketParser.parseCardSessionKeyBlock(block))
    }

    func testParseCardSessionKeyBlockTooShortThrows() {
        XCTAssertThrowsError(try OpenPGPPacketParser.parseCardSessionKeyBlock([9, 0x01, 0x00]))
    }

    func testParseCardSessionKeyBlockChecksumWrapsMod65536() throws {
        // Two 0xFF bytes sum to 0x01FE; a single key byte 0xFF sums to 0x00FF.
        let key: [UInt8] = [0xFF, 0xFF]
        let block: [UInt8] = [9] + key + [0x01, 0xFE]
        let result = try OpenPGPPacketParser.parseCardSessionKeyBlock(block)
        XCTAssertEqual(result.sessionKey, key)
    }

    // MARK: - PSO:DECIPHER command data (0x00 indicator + length-correct cryptogram)

    func testRSADecipherCommandDataPrependsIndicatorAndFullLength() {
        // Full-length cryptogram (no leading zero): 0x00 indicator + 512 bytes.
        let cryptogram = [UInt8](repeating: 0x80, count: 512)
        let cmd = OpenPGPCardService.rsaDecipherCommandData(cryptogram: cryptogram, modulusLength: 512)
        XCTAssertEqual(cmd.count, 513)
        XCTAssertEqual(cmd.first, 0x00)
        XCTAssertEqual(Array(cmd[1...]), cryptogram)
    }

    func testRSADecipherCommandDataLeftPadsShortCryptogram() {
        // MPI dropped 3 leading zero bytes → pad back out to the modulus length.
        let cryptogram = [UInt8](repeating: 0x42, count: 509)
        let cmd = OpenPGPCardService.rsaDecipherCommandData(cryptogram: cryptogram, modulusLength: 512)
        XCTAssertEqual(cmd.count, 513)
        XCTAssertEqual(cmd.first, 0x00)                 // indicator
        XCTAssertEqual(Array(cmd[1...3]), [0, 0, 0])    // zero padding
        XCTAssertEqual(Array(cmd[4...]), cryptogram)    // original bytes follow
    }
}
