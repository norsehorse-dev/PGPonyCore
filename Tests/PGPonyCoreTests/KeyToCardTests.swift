// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// KeyToCardTests.swift
// PGPony
//
// 8.4.0 build 6 (Android 4.7.0 items 13, 54, 55): the pure half of Move to
// Hardware Key (KeyToCard). The import data layout follows the OpenPGP card
// 3.4 spec (4.4.3.12, Extended Header List) and gpg's scdaemon:
// 4D { CRT 00, 7F48 { tag len ... }, 5F48 { values } }. Port of Android's
// KeyToCardTest; keys are made here with CryptoKit and the Security framework
// instead of Bouncy Castle.
//
// Ported from the app's KeyToCardTests.swift. The tests there that need the app's
// storage, models or secret-key unlock stay in the app.

import Foundation
import CryptoKit
import Security
import XCTest
@testable import PGPonyCore

@MainActor
final class KeyToCardTests: XCTestCase {

    // MARK: - Helpers

    private let created: UInt32 = 1_760_000_000

    private func hex(_ b: [UInt8]) -> String { KeyToCard.hex(b) }

    /// An OpenPGP MPI: 2-octet bit length, then the value without leading zeros.
    private func mpi(_ value: [UInt8]) -> [UInt8] {
        let start = value.firstIndex { $0 != 0 } ?? value.count
        let v = Array(value[start...])
        let bits = KeyToCard.bitLength(v)
        return [UInt8((bits >> 8) & 0xFF), UInt8(bits & 0xFF)] + v
    }

    private func checksum(_ b: [UInt8]) -> [UInt8] {
        let s = b.reduce(UInt16(0)) { $0 &+ UInt16($1) }
        return [UInt8((s >> 8) & 0xFF), UInt8(s & 0xFF)]
    }

    /// An unprotected v4 secret packet body: public part, usage 0, the
    /// secret MPIs and their checksum.
    private func unprotectedSecret(publicBody: [UInt8], secret: [UInt8]) -> [UInt8] {
        publicBody + [0] + secret + checksum(secret)
    }

    /// RSA private key from the Security framework: (n, e, d, p, q, dP, dQ, qInv),
    /// read from its PKCS#1 RSAPrivateKey DER.
    private func securityFrameworkRSA(bits: Int) throws -> [[UInt8]] {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: bits,
        ]
        var error: Unmanaged<CFError>?
        let key = try XCTUnwrap(SecKeyCreateRandomKey(attributes as CFDictionary, &error))
        let der = Array(try XCTUnwrap(SecKeyCopyExternalRepresentation(key, &error) as Data?))
        var o = 0
        func length() -> Int {
            let first = Int(der[o]); o += 1
            guard first & 0x80 != 0 else { return first }
            var n = 0
            for _ in 0..<(first & 0x7F) { n = n << 8 | Int(der[o]); o += 1 }
            return n
        }
        XCTAssertEqual(der[o], 0x30); o += 1
        _ = length()
        var ints: [[UInt8]] = []
        while o < der.count {
            XCTAssertEqual(der[o], 0x02); o += 1
            let n = length()
            ints.append(Array(der[o..<(o + n)]))
            o += n
        }
        XCTAssertEqual(ints.count, 9)
        return Array(ints.dropFirst())   // drop the version
    }

    private func big(_ b: [UInt8]) -> BigNum { BigNum(bytes: b) }

    // MARK: - BER lengths and the Extended Header List

    func testBERLengthsUseOneTwoOrThreeOctets() {
        XCTAssertEqual(KeyToCard.berLength(0), [0x00])
        XCTAssertEqual(KeyToCard.berLength(127), [0x7F])
        XCTAssertEqual(KeyToCard.berLength(128), [0x81, 0x80])
        XCTAssertEqual(KeyToCard.berLength(255), [0x81, 0xFF])
        XCTAssertEqual(KeyToCard.berLength(256), [0x82, 0x01, 0x00])
        XCTAssertEqual(KeyToCard.berLength(1029), [0x82, 0x04, 0x05])
        XCTAssertNil(KeyToCard.berLength(0x10000))
    }

    func testAnECImportIs4DTheCRTTheTemplateAndTheValue() throws {
        let secret = (1...32).map { UInt8($0) }
        let ehl = try KeyToCard.extendedHeaderList(slot: .decryption, parts: KeyToCard.ecParts(secret))
        XCTAssertEqual(hex(ehl), "4D2A" + "B800" + "7F48" + "02" + "9220" + "5F48" + "20" + hex(secret))
        let sig = try KeyToCard.extendedHeaderList(slot: .signature, parts: KeyToCard.ecParts(secret))
        XCTAssertEqual(Array(sig[2..<4]), [0xB6, 0x00])
        let auth = try KeyToCard.extendedHeaderList(slot: .authentication, parts: KeyToCard.ecParts(secret))
        XCTAssertEqual(Array(auth[2..<4]), [0xA4, 0x00])
    }

    // MARK: - RSA

    func testTextbookRSAPartsInEveryFormat() throws {
        // p = 61, q = 53, n = 3233, e = 17, d = 2753 (the PKCS#1 textbook key).
        // OpenPGP's u is 1/p mod q = 20; the card wants 1/q mod p = 38.
        let e: [UInt8] = [0x11], p: [UInt8] = [61], q: [UInt8] = [53], d: [UInt8] = [0x0A, 0xC1], u: [UInt8] = [20]

        let standard = try KeyToCard.rsaParts(e: e, p: p, q: q, d: d, u: u, nBits: 16, eBits: 17, format: 0x00)
        XCTAssertEqual(standard.map(\.tag), [0x91, 0x92, 0x93])
        XCTAssertEqual(standard.map(\.value), [[0x00, 0x00, 0x11], [61], [53]])

        let crt = try KeyToCard.rsaParts(e: e, p: p, q: q, d: d, u: u, nBits: 16, eBits: 17, format: KeyToCard.rsaFormatCRT)
        XCTAssertEqual(crt.map(\.tag), [0x91, 0x92, 0x93, 0x94, 0x95, 0x96])
        XCTAssertEqual(crt[3].value, [38], "1/q mod p")
        XCTAssertEqual(crt[4].value, [53], "d mod (p-1)")
        XCTAssertEqual(crt[5].value, [49], "d mod (q-1)")

        let withModulus = try KeyToCard.rsaParts(e: e, p: p, q: q, d: d, u: u, nBits: 16, eBits: 17, format: 0x03)
        XCTAssertEqual(withModulus.map(\.tag), [0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97])
        XCTAssertEqual(withModulus.last?.value, [0x0C, 0xA1], "n = 3233")
        let standardWithModulus = try KeyToCard.rsaParts(e: e, p: p, q: q, d: d, u: u, nBits: 16, eBits: 17, format: 0x01)
        XCTAssertEqual(standardWithModulus.map(\.tag), [0x91, 0x92, 0x93, 0x97])

        // The same key with p and q the other way round: u = 1/53 mod 61 = 38,
        // and the card's 1/q mod p is then 1/61 mod 53 = 20.
        let swapped = try KeyToCard.rsaParts(e: e, p: q, q: p, d: d, u: [38], nBits: 16, eBits: 17, format: KeyToCard.rsaFormatCRT)
        XCTAssertEqual(swapped[3].value, [20])
        XCTAssertEqual(swapped[4].value, [49])
        XCTAssertEqual(swapped[5].value, [53])

        let ehl = try KeyToCard.extendedHeaderList(slot: .signature, parts: crt)
        XCTAssertEqual(hex(Array(ehl.prefix(4))), "4D" + hex([UInt8(ehl.count - 2)]) + "B600")
        XCTAssertEqual(hex(Array(ehl[4..<22])), "7F48" + "0C" + "9103" + "9201" + "9301" + "9401" + "9501" + "9601" + "5F48" + "08")
        XCTAssertEqual(Array(ehl.suffix(8)), [0x00, 0x00, 0x11, 61, 53, 38, 53, 49])
    }

    func testBigNumDivisionAndMultiplication() {
        let a = big(Array(SHA512.hash(data: Data("dividend".utf8))) + Array(SHA256.hash(data: Data("more".utf8))))
        let b = big(Array(SHA256.hash(data: Data("divisor".utf8))) + [0x01, 0x02, 0x03])
        let (q, r) = BigNum.divMod(a, b)
        XCTAssertEqual(q * b + r, a)
        XCTAssertLessThan(BigNum.compare(r, b), 0)
        let small = BigNum.divMod(big([0x01, 0x00, 0x00, 0x00, 0x00]), big([0x07]))
        XCTAssertEqual(small.quotient * big([0x07]) + small.remainder, big([0x01, 0x00, 0x00, 0x00, 0x00]))
        XCTAssertEqual(BigNum.modPow(BigNum(3), BigNum(200), BigNum(1_000_003)), BigNum.divMod(BigNum.modPow(BigNum(9), BigNum(100), BigNum(1_000_003)), BigNum(1_000_003)).remainder)
        XCTAssertEqual(big([0x00, 0x00, 0x12, 0x34]).bytes(), [0x12, 0x34])
    }

    // MARK: - Attributes

    func testRSAAttributesAre01NBitsEBitsFormat() {
        XCTAssertEqual(hex(KeyToCard.attributes(kind: .rsa, rsaBits: 2048, eBits: 17, rsaFormat: 0)), "010800001100")
        XCTAssertEqual(hex(KeyToCard.attributes(kind: .rsa, rsaBits: 4096, eBits: 17, rsaFormat: 2)), "011000001102")
        XCTAssertEqual(KeyToCard.rsaFormat(of: KeyToCard.attributes(kind: .rsa, rsaBits: 4096, eBits: 17, rsaFormat: 2)), 2)
        XCTAssertNil(KeyToCard.rsaFormat(of: KeyToCard.attributes(kind: .ed25519)))
        XCTAssertEqual(hex(KeyToCard.attributes(kind: .ed25519)), "162B06010401DA470F01")
        XCTAssertEqual(hex(KeyToCard.attributes(kind: .cv25519)), "122B060104019755010501")
    }

    func testAttributesAlreadyOnTheSlotAreNotWrittenAgain() {
        let ed = KeyToCard.attributes(kind: .ed25519)
        XCTAssertTrue(KeyToCard.sameAttributes(current: ed, wanted: ed))
        XCTAssertTrue(KeyToCard.sameAttributes(current: ed + [0xFF], wanted: ed))
        XCTAssertFalse(KeyToCard.sameAttributes(current: nil, wanted: ed))
        XCTAssertFalse(KeyToCard.sameAttributes(current: KeyToCard.attributes(kind: .cv25519), wanted: ed))
        let rsa = KeyToCard.attributes(kind: .rsa, rsaBits: 2048, eBits: 32, rsaFormat: 0)
        XCTAssertFalse(KeyToCard.sameAttributes(current: rsa + [0], wanted: rsa))
        XCTAssertEqual(KeyToCard.rsaExponentBits(of: rsa), 32)
        XCTAssertNil(KeyToCard.rsaExponentBits(of: ed))
    }

    // MARK: - Slots and choices

    func testSlotsTakeTheKeysGPGWouldPutThere() {
        XCTAssertTrue(KeyToCard.fitsSlot(kind: .ed25519, slot: .signature, canSign: false, canEncrypt: false, canAuthenticate: false, primaryCanCertify: true))
        XCTAssertFalse(KeyToCard.fitsSlot(kind: .ed25519, slot: .signature, canSign: false, canEncrypt: false, canAuthenticate: false))
        XCTAssertTrue(KeyToCard.fitsSlot(kind: .ed25519, slot: .signature, canSign: true, canEncrypt: false, canAuthenticate: false))
        XCTAssertFalse(KeyToCard.fitsSlot(kind: .ed25519, slot: .decryption, canSign: true, canEncrypt: false, canAuthenticate: false))
        XCTAssertTrue(KeyToCard.fitsSlot(kind: .cv25519, slot: .decryption, canSign: false, canEncrypt: true, canAuthenticate: false))
        XCTAssertFalse(KeyToCard.fitsSlot(kind: .cv25519, slot: .authentication, canSign: false, canEncrypt: false, canAuthenticate: true))
        XCTAssertTrue(KeyToCard.fitsSlot(kind: .rsa, slot: .authentication, canSign: false, canEncrypt: false, canAuthenticate: true))
        XCTAssertFalse(KeyToCard.fitsSlot(kind: .rsa, slot: .signature, canSign: false, canEncrypt: true, canAuthenticate: false))
    }

    func testV6AndRFC9580KeysAreRefusedWithTheReason() throws {
        let v4Native = [4] + KeyToCard.be32(created) + [27] + [UInt8](repeating: 7, count: 32)
        XCTAssertEqual(KeyToCard.keyPacket(body: v4Native)?.eligibility, .refused(.rfc9580))
        let v4MLKEM = [4] + KeyToCard.be32(created) + [35] + [UInt8](repeating: 7, count: 32 + 1184)
        XCTAssertEqual(KeyToCard.keyPacket(body: v4MLKEM)?.eligibility, .refused(.postQuantum))
        let material = [UInt8](repeating: 9, count: 32)
        let v6 = [6] + KeyToCard.be32(created) + [27] + KeyToCard.be32(UInt32(material.count)) + material
        let packet = try XCTUnwrap(KeyToCard.keyPacket(body: v6))
        XCTAssertEqual(packet.eligibility, .refused(.v6))
        XCTAssertEqual(packet.fingerprint.count, 32)
    }
}
