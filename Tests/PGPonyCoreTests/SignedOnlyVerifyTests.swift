// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// SignedOnlyVerifyTests.swift
// PGPonyTests
//
// §5.6.10 — recognizing a signed-but-NOT-encrypted message so it can be
// verified in place instead of erroring in the decryptor. These pin the new
// packet-level detection (OpenPGPPacketParser.signedMessageParts): it must see
// through gpg's default ZIP compression to the inline one-pass signature, and
// it must REFUSE anything that carries an encryption packet so a real
// ciphertext still routes to decryption.

import XCTest
@testable import PGPonyCore

final class SignedOnlyVerifyTests: XCTestCase {

    /// A real gpg inline-signed (not encrypted, not clear-signed) message,
    /// dearmored. gpg ZIP-compresses by default, so the top level is a single
    /// tag-8 packet wrapping one-pass(4) || literal(11) || signature(2). The
    /// signed content is "Hello signed world.\nSecond line.\n".
    private let gpgEdSignedBase64 =
        "owGbwMvMwCU2u5mVOcr6jD7jGr0k9tzidL2SipKs7soQj9ScnHyF4sz0vNQUhfL8opwUPa7g1OT8vBSFnMy8VD2ujlIWBjEuBlkxRRY74y1c114tefcr9IouzDxWJpApDFycAjAR0SyGf1oTF3xpK/9WeVp+zx6v/Zf/7N8otW8qQ94WLttfcZk8D+IZGZbFVvAF+jbkdYh9mnZ/hVef/tL1u6YZPzl7keni3Hn7RLkA"

    func testExtractsInlineSignedThroughCompression() throws {
        let data = Data(base64Encoded: gpgEdSignedBase64)!
        let parts = try XCTUnwrap(
            OpenPGPPacketParser.signedMessageParts([UInt8](data)),
            "a compressed inline-signed message must be recognized as signed-only")
        XCTAssertEqual(parts.sigPacket.tag, 2, "extracted signature must be a tag-2 packet")
        XCTAssertEqual(String(decoding: parts.literal, as: UTF8.self),
                       "Hello signed world.\nSecond line.\n",
                       "extracted literal content must be the signed message")
    }

    /// A literal packet with no signature is not a verify-in-place candidate.
    func testLiteralWithoutSignatureIsNotSignedOnly() {
        let content = Array("hello".utf8)
        // Literal packet body: format 'b', 0-length filename, 4-byte date, content.
        let litBody: [UInt8] = [0x62, 0x00, 0, 0, 0, 0] + content
        let litPacket: [UInt8] = [0xCB, UInt8(litBody.count)] + litBody   // new-format tag 11
        XCTAssertNil(OpenPGPPacketParser.signedMessageParts(litPacket))
    }

    /// A message that carries an encryption packet must NOT be treated as
    /// signed-only, even if a signature and literal are also present — it has to
    /// keep routing to the decryptor.
    func testEncryptionPacketIsRejected() {
        let pkesk: [UInt8] = [0xC1, 0x02, 0x03, 0x00]                     // tag 1 (PKESK) stub
        let content = Array("hi".utf8)
        let litBody: [UInt8] = [0x62, 0x00, 0, 0, 0, 0] + content
        let litPacket: [UInt8] = [0xCB, UInt8(litBody.count)] + litBody   // tag 11
        let sigPacket: [UInt8] = [0xC2, 0x02, 0x04, 0x00]                 // tag 2 stub
        let combined = pkesk + litPacket + sigPacket
        XCTAssertNil(OpenPGPPacketParser.signedMessageParts(combined),
                     "an encryption packet must veto the signed-only classification")
    }
}
