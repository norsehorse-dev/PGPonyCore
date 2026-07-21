// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// LibrePGPCombinerTests.swift
// PGPony — Phase F (PQC), LibrePGP. KAT for the GnuPG composite KEM combiner.
//
// Expected KEK computed independently (pycryptodome KMAC256) using GnuPG's exact
// framing (key "OpenPGPCompositeKeyDerivationFunction", custom "KDF", counter
// 00000001, ECC-first ordering, fixedInfo = sessionKeyAlgo ‖ v5 fingerprint).

import XCTest
@testable import PGPonyCore

final class LibrePGPCombinerTests: XCTestCase {

    private func hx(_ s: String) -> [UInt8] {
        let c = s.filter { $0.isHexDigit }; var o = [UInt8](); var i = c.startIndex
        while i < c.endIndex { let n = c.index(i, offsetBy: 2); o.append(UInt8(c[i..<n], radix: 16)!); i = n }
        return o
    }
    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    func testLibrePGPCombinerKAT() {
        let eccShared  = hx("0104070a0d101316191c1f2225282b2e3134373a3d404346494c4f5255585b5e")
        let eccCT      = hx("02070c11161b20252a2f34393e43484d52575c61666b70757a7f84898e93989d")
        let mlkemShared = hx("030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc")
        let mlkemCT    = hx("""
040f1a25303b46515c67727d88939ea9b4bfcad5e0ebf6010c17222d38434e59646f7a85909b
a6b1bcc7d2dde8f3fe09141f2a35404b56616c77828d98a3aeb9c4cfdae5f0fb06111c27323d
48535e69747f8a95a0abb6c1ccd7e2edf8030e19242f3a45505b66717c87929da8b3bec9d4df
eaf5000b16212c37424d58636e79848f9aa5b0bbc6d1dce7f2fd08131e29343f4a55606b7681
8c97a2adb8c3ced9e4effa05101b26313c47525d68737e89949faab5c0cbd6e1ecf7020d1823
2e39444f5a65707b86919ca7b2bdc8d3dee9f4ff0a15202b36414c57626d78838e99a4afbac5
d0dbe6f1fc07121d28333e49545f6a75808b96a1acb7c2cdd8e3eef9040f1a25303b46515c67
727d88939ea9b4bfcad5e0ebf6010c17222d38434e59646f7a85909ba6b1bcc7d2dde8f3fe09
141f2a35404b56616c77828d98a3aeb9c4cfdae5f0fb06111c27323d48535e69747f8a95a0ab
b6c1ccd7e2edf8030e19242f3a45505b66717c87929da8b3bec9d4dfeaf5000b16212c37424d
58636e79848f9aa5b0bbc6d1dce7f2fd08131e29343f4a55606b76818c97a2adb8c3ced9e4ef
fa05101b26313c47525d68737e89949faab5c0cbd6e1ecf7020d18232e39444f5a65707b8691
9ca7b2bdc8d3dee9f4ff0a15202b36414c57626d78838e99a4afbac5d0dbe6f1fc07121d2833
3e49545f6a75808b96a1acb7c2cdd8e3eef9040f1a25303b46515c67727d88939ea9b4bfcad5
e0ebf6010c17222d38434e59646f7a85909ba6b1bcc7d2dde8f3fe09141f2a35404b56616c77
828d98a3aeb9c4cfdae5f0fb06111c27323d48535e69747f8a95a0abb6c1ccd7e2edf8030e19
242f3a45505b66717c87929da8b3bec9d4dfeaf5000b16212c37424d58636e79848f9aa5b0bb
c6d1dce7f2fd08131e29343f4a55606b76818c97a2adb8c3ced9e4effa05101b26313c47525d
68737e89949faab5c0cbd6e1ecf7020d18232e39444f5a65707b86919ca7b2bdc8d3dee9f4ff
0a15202b36414c57626d78838e99a4afbac5d0dbe6f1fc07121d28333e49545f6a75808b96a1
acb7c2cdd8e3eef9040f1a25303b46515c67727d88939ea9b4bfcad5e0ebf6010c17222d3843
4e59646f7a85909ba6b1bcc7d2dde8f3fe09141f2a35404b56616c77828d98a3aeb9c4cfdae5
f0fb06111c27323d48535e69747f8a95a0abb6c1ccd7e2edf8030e19242f3a45505b66717c87
929da8b3bec9d4dfeaf5000b16212c37424d58636e79848f9aa5b0bbc6d1dce7f2fd08131e29
343f4a55606b76818c97a2adb8c3ced9e4effa05101b26313c47525d68737e89949faab5c0cb
d6e1ecf7020d18232e39444f5a65707b86919ca7b2bdc8d3dee9f4ff0a15202b36414c57626d
78838e99a4afbac5d0dbe6f1fc07121d28333e49545f6a75808b96a1acb7c2cdd8e3eef9040f
1a25303b46515c67727d88939ea9b4bfcad5e0ebf6010c17222d38434e59646f7a85909ba6b1
bcc7d2dde8f3fe09141f2a35404b56616c77828d98a3aeb9
""")
        let v5fpr      = hx("05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98")
        let expected   = "0b065220494200b01b70776ccd31f39147b5c3ebc99565033f4283fb9a092b25"

        let kek = LibrePGPCombiner.deriveKEK(
            eccShared: eccShared, eccCipherText: eccCT,
            mlkemShared: mlkemShared, mlkemCipherText: mlkemCT,
            sessionKeyAlgo: 9, v5Fingerprint: v5fpr)
        XCTAssertEqual(kek.count, 32)
        XCTAssertEqual(hex(kek), expected, "LibrePGP combiner KEK mismatch vs GnuPG framing")
    }
}
