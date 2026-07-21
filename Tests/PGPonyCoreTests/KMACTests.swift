// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// KMACTests.swift
// PGPony — Phase F (PQC), LibrePGP support. Tests the Keccak/cSHAKE/KMAC core.
//
// KMAC256 vectors come from a NIST-validated implementation (pycryptodome); the
// SHA3-256 vector cross-checks the Keccak-f[1600] permutation. LibrePGP-KMAC
// vectors use GnuPG's exact key/customization ("OpenPGPCompositeKeyDerivationFunction"
// / "KDF"), so a pass means our KMAC256 matches what gpg computes.

import XCTest
@testable import PGPonyCore

final class KMACTests: XCTestCase {

    private func bytes(_ hex: String) -> [UInt8] {
        var out = [UInt8](); var i = hex.startIndex
        while i < hex.endIndex { let n = hex.index(i, offsetBy: 2); out.append(UInt8(hex[i..<n], radix: 16)!); i = n }
        return out
    }
    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    // Keccak permutation sanity: SHA3-256 of 0x00..0x31.
    func testSHA3_256() {
        let out = Keccak.sha3_256(bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"))
        XCTAssertEqual(hex(out), "57fa0a179b510246b3f8d195acb103cdc86d8315588325ef536c47fff2772658")
    }

    // Standard KMAC256, NIST-style sample (empty customization, 512-bit output).
    func testKMAC256Standard() {
        let out = Keccak.kmac256(key: bytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"),
                                 data: bytes("00010203"),
                                 outLen: 64,
                                 customization: [])
        XCTAssertEqual(hex(out), "2ebd1622de2de44174e3477206060d7f64489a639b7545649132317609fa214f4c8ac90630fb4c757fba074b15186fe452ae71b6a1e443bf54059e090c11ae20")
    }

    // LibrePGP KMAC256: GnuPG's key + "KDF" customization, 256-bit output.
    func testLibrePGPKMAC256() {
        let key = Array("OpenPGPCompositeKeyDerivationFunction".utf8)
        let custom = Array("KDF".utf8)
        let vectors: [(input: String, expected: String)] = [
        (input: "", expected: "8ffb97bd1a5a5ec8af9f39d2613eafce4f6bb7c9d9ed743f8f8526a38667ac90"),
        (input: "03", expected: "6438fda7c4d4b6c123bc76e85fc89335cc2876058a4c344d1d82800f0b7dc89f"),
        (input: "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc", expected: "725b420b682f50fc5146915b927c1a606af271589b4198f1ac08d019cf75abac"),
        (input: "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4", expected: "c688bc76343b7b1a4985993b581ab21f7bb593a34406140ea35f922df6668885"),
        (input: "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d74", expected: "68f4c1a39e7cea53d631283439edbe125a7e07539050033c7a5862cb678fe800"),
        (input: "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8", expected: "561be64887317357c2ecf677817223252750cac78839d535d9618462cf9d26d8"),
        ]
        for v in vectors {
            let out = Keccak.kmac256(key: key, data: bytes(v.input), outLen: 32, customization: custom)
            XCTAssertEqual(hex(out), v.expected, "KMAC mismatch for input len \(v.input.count/2)")
        }
    }
}
