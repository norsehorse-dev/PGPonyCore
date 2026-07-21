// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// MIMEBuilderTests
//
// Phase 1 of the PGP/MIME compose side. `MIMEBuilder` assembles a
// multipart/mixed body + attachments; these tests build a message and parse it
// straight back with `MIMEParser`, asserting the body text and every attachment
// (filename, MIME type, exact bytes) survive the round trip. Because the builder
// and parser are inverses, a passing round trip exercises both at once.

import XCTest
@testable import PGPonyCore

final class MIMEBuilderTests: XCTestCase {

    func testRoundTrip_bodyAndTwoAttachments() throws {
        let body = "Hello NorseHorse,\r\nTwo files attached.\r\n"
        let csv = Data("a,b,c\r\n1,2,3\r\n4,5,6\r\n".utf8)
        let binary = Data((0..<300).map { UInt8($0 % 256) })

        let built = MIMEBuilder.build(
            plainText: body,
            attachments: [
                MIMEAttachment(filename: "report.csv", mimeType: "text/csv", data: csv),
                MIMEAttachment(filename: "résumé.png", mimeType: "image/png", data: binary)
            ]
        )

        let message = try XCTUnwrap(MIMEParser.parseMultipart(built))
        let p = message.presentation

        XCTAssertEqual(p.plainText, body, "body should survive the base64 round trip exactly")
        XCTAssertEqual(p.attachments.count, 2)

        let report = try XCTUnwrap(p.attachments.first { $0.filename == "report.csv" })
        XCTAssertEqual(report.mimeType, "text/csv")
        XCTAssertEqual(report.data, csv, "attachment bytes must be byte-identical")

        // The non-ASCII filename is RFC 2047 encoded on the way out and decoded
        // on the way back in.
        let resume = try XCTUnwrap(p.attachments.first { $0.filename == "résumé.png" })
        XCTAssertEqual(resume.mimeType, "image/png")
        XCTAssertEqual(resume.data, binary)
    }

    func testRoundTrip_attachmentsOnly() throws {
        let blob = Data((0..<512).map { UInt8(($0 * 7) % 256) })
        let built = MIMEBuilder.build(
            plainText: nil,
            attachments: [MIMEAttachment(filename: "blob.bin", mimeType: "application/octet-stream", data: blob)]
        )

        let message = try XCTUnwrap(MIMEParser.parseMultipart(built))
        let p = message.presentation

        XCTAssertNil(p.plainText)
        XCTAssertEqual(p.attachments.count, 1)
        XCTAssertEqual(p.attachments.first?.filename, "blob.bin")
        XCTAssertEqual(p.attachments.first?.data, blob)
    }

    func testRoundTrip_bodyOnly() throws {
        let body = "Just a note, no files.\r\n"
        let built = MIMEBuilder.build(plainText: body, attachments: [])

        let message = try XCTUnwrap(MIMEParser.parseMultipart(built))
        let p = message.presentation

        XCTAssertEqual(p.plainText, body)
        XCTAssertEqual(p.attachments.count, 0)
    }

    func testFilenameEncoding_asciiUntouched() {
        XCTAssertEqual(MIMEBuilder.encodeParameterFilename("report.csv"), "report.csv")
    }

    func testFilenameEncoding_nonASCIIEncoded() {
        let encoded = MIMEBuilder.encodeParameterFilename("résumé.png")
        XCTAssertTrue(encoded.hasPrefix("=?UTF-8?B?"))
        XCTAssertTrue(encoded.hasSuffix("?="))
        XCTAssertEqual(MIMEParser.decodeEncodedWords(encoded), "résumé.png")
    }

    func testBase64Wrapping_under76PerLine() {
        let wrapped = MIMEBuilder.base64Wrapped(Data(repeating: 0x41, count: 600))
        for line in wrapped.components(separatedBy: "\r\n") {
            XCTAssertLessThanOrEqual(line.count, 76)
        }
    }

    // MARK: - RFC 3156 envelope

    func testEnvelope_rfc3156Structure() throws {
        let armored = "-----BEGIN PGP MESSAGE-----\r\n\r\nwcBMA1234abcdEFGH==\r\n-----END PGP MESSAGE-----\r\n"
        let envelope = MIMEBuilder.wrapEncrypted(armoredCiphertext: armored)

        let root = MIMEParser.parse(envelope)
        XCTAssertEqual(root.contentType.mimeType, "multipart/encrypted")
        XCTAssertEqual(root.contentType.parameters["protocol"], "application/pgp-encrypted")

        guard case .multipart(let parts) = root.content else {
            return XCTFail("envelope should be multipart")
        }
        XCTAssertEqual(parts.count, 2)

        XCTAssertEqual(parts[0].contentType.mimeType, "application/pgp-encrypted")
        if case .leaf(let versionData) = parts[0].content {
            XCTAssertEqual(String(decoding: versionData, as: UTF8.self), "Version: 1")
        } else {
            XCTFail("version part should be a leaf")
        }

        XCTAssertEqual(parts[1].contentType.mimeType, "application/octet-stream")
        if case .leaf(let cipherData) = parts[1].content {
            let text = String(decoding: cipherData, as: UTF8.self)
            XCTAssertTrue(text.contains("-----BEGIN PGP MESSAGE-----"))
            XCTAssertTrue(text.contains("-----END PGP MESSAGE-----"))
        } else {
            XCTFail("ciphertext part should be a leaf")
        }
    }

    // MARK: - RFC 3156 envelope extraction (decrypt side)

    func testEnvelope_payloadExtractionRoundTrips() {
        let armored = "-----BEGIN PGP MESSAGE-----\r\n\r\nwcBMA1234abcdEFGH==\r\n-----END PGP MESSAGE-----\r\n"
        let envelope = MIMEBuilder.wrapEncrypted(armoredCiphertext: armored)
        let extracted = MIMEParser.pgpMIMEEncryptedPayload(in: envelope)
        XCTAssertNotNil(extracted)
        XCTAssertTrue(extracted?.contains("-----BEGIN PGP MESSAGE-----") ?? false)
        XCTAssertTrue(extracted?.contains("-----END PGP MESSAGE-----") ?? false)
        XCTAssertTrue(extracted?.contains("wcBMA1234abcdEFGH==") ?? false)
    }

    func testEnvelope_extractionFromFullEmail() {
        // A real encrypted .eml carries message headers before the
        // multipart/encrypted Content-Type; extraction must still find the block.
        let armored = "-----BEGIN PGP MESSAGE-----\r\n\r\nwcBMAdeadbeef==\r\n-----END PGP MESSAGE-----\r\n"
        let envelope = MIMEBuilder.wrapEncrypted(armoredCiphertext: armored)
        var eml = Data("From: a@example.com\r\nTo: b@example.com\r\nSubject: test\r\n".utf8)
        eml.append(envelope)
        let extracted = MIMEParser.pgpMIMEEncryptedPayload(in: eml)
        XCTAssertNotNil(extracted)
        XCTAssertTrue(extracted?.contains("wcBMAdeadbeef==") ?? false)
    }

    func testEnvelope_nonEnvelopeReturnsNil() {
        XCTAssertNil(MIMEParser.pgpMIMEEncryptedPayload(in: Data("just some text".utf8)))
        let inline = "-----BEGIN PGP MESSAGE-----\r\n\r\nwcBMAxx==\r\n-----END PGP MESSAGE-----\r\n"
        XCTAssertNil(
            MIMEParser.pgpMIMEEncryptedPayload(in: Data(inline.utf8)),
            "a bare inline block is not a multipart/encrypted envelope"
        )
    }
}
