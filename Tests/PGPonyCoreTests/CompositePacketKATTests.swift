// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CompositePacketKATTests.swift
// PGPony — Phase F (PQC) F3.
//
// End-to-end packet-layer known-answer tests for the composite ML-KEM-768 +
// X25519 KEM (algorithm 35), driven by RFC 9980's OWN sample artifacts:
//   * pkeskBody / secSubkeyBody / seipdBody — individual packet bodies
//   * fullMessage — the complete v6-eddsa-sample-message (PKESK + SEIPD)
// The expected session key is RFC 9980's stated value; the plaintext is the
// signed message "Testing\n". Every byte here was extracted and cross-checked
// in the sandbox before being baked in.
//
// Hex literals use multiline strings (not "+"-chains) so the Swift type-checker
// stays fast on the large packet bodies; hex() strips whitespace before decode.

import XCTest
@testable import PGPonyCore

final class CompositePacketKATTests: XCTestCase {

    private let pkeskBody = hex("""
062106dafe0eebb2675ecfcdc20a23fe89ca5d12e83f527dfa354b6dcf662131a48b9d2385e2
fe4ce047b23147c1583272389a01b4bc2b99607d0c38ac18d2ab1d7a4a6bbdd2ea61b0fe3948
775c6318025d386e43b4cdfa24a2f9e0a0e8dc080f870645be23557760d12f6eaf77a15a60b5
e362b906e9246d658140324cd2141af435be2f3fb93c06fa24e7c53867db5f34539ae34133c9
de3eb8a0c4eaed0ded342baa99943bc18d73b1e66bee09e8ffdf75a77c91583e1c6965fbf4fb
ad39766fd2cbe234414a5a2ab5625d9a11e19d35826df934a8180949983d5f4cb29b05f1ac99
9623969139cb6dab945ae0c24e5f0a35b310e163f940e6b1b3ae4257cd8060c929441a029ac8
237c5072f1fc527aa20a875aa0855decfbbc437294b151cfb6d8efff34c353aba9f00de3308d
0f243a5e44845583d164f640d5c13cc4d7ad05748e8c79be223ea20a263be4a413723ae81efb
38ab4ec0d3f8090f1d143da126993f1b5fb298637284ca9808de214dae1a225ecb001d4aa6f8
dcd5948ae318a3a369b8b9af3d57d7a27602a2a3c46b8a4cc47ba9303b2740db5967c878c20c
f7d9dc262d0e9d01617801ae5d0c9d958218c8ffb4c5383daeaabcaeff9b4b330a91183b2fa7
6049df822a21b2e7f8954d867b26d4ac560ebf9d56105e17ea745ab4acff073db94f3af55d88
183db3323a6de050f4744c7de594dbabdc4a102eae27e1bafd7a3517fd57ca64f1245a4ba0fc
89bca67cfcda5bf46aa255aa7c847836345622036c29e3547848f4255c93caecb440a32dc252
93d4f3a92fbc4e98b4ee27ba17dd5701189a07077c1e8a45e11d4b9a729c121105effedc2552
9369ad26651e454732069f5a0a7b400d00dd0b14fe70d8766a5dba66b91c0aae9c9f908b0762
315118ef710cc7fbb8f22a3f3135a8bdb25487e97831a9ac7bc96c6cdc4c9f3aaf9a8703fff6
e7b980adf7c70f6e105b2b418af3e414325158821087736eded3705a27f99136ab4e0afae823
dfc016bf84b79058f19c16ad32961deb846f0262fc58e5cca3e0e482a7743b337771a1d4b65e
c58808aa14183a3413dba278973b7fcd37f7b0c6a781370603fbb3f5e4da77164fb365ae972d
62016230a0a311d4966ced3c0bc446f0e62006731c637a79c6a936bbadb525c09ebacdee7f72
a0eb05013e89236b95dd94b6d540877ef34333103ca386fdf1e9cfc5d1acff2ebceadffd9da6
7defcb4ad4f56679f775919d567bd29708590a9a2580a23b267b9a44e4ab2860f0fdfc61466e
16d4861a4ebd9fb403ddb7590636f33119ef7af42ec577baf96797693f6ebc463f18a2deb2d8
29a08d5a0d2f7b39f9b174e25a7d524d8c3ce5d83272284a4276a08eb1369b55f2da1aee82dc
d41336370724d5c985317c06df5ce9dd562120c449f987b439f3b4c5be63fcbe8ee53f845c0a
f70977768d6138742fa9d52bb2487e6bbad9bf89d4b7d05a7657baa19b52cd798333ee4f56a5
362d0e9122b39e6764a820c06fe0f9ecca47ab0285304541f8cf8824422d2b537af8c15b5aea
40dfa3d1e5b4d779b25e807f2e12604d3af95b09f5fa6bd50e232841db3616a790f829becd02
41433252503c1c19f4e5eaa690844602287374a273524b623e0600b60e6c0be4f5a30c662eec
e2adb13315095472044b0f3346d5415e8b3772
""")
    private let secSubkeyBody = hex("""
066774858023000004c022150b430cf724ec19b8be55df9bcaade327085711369404a575c802
3443b05f5e4242dd8374b0650b0752c8bd9052945131ffda29e27727fb427d20a78aceebb8e3
d9aed9474d03f5cafb9c25fac18675354dac9ab7b3b47f064b5535604c1b4b7e79806d22d41a
c7062e72c3a7b5c3b7e38b87d4103e6472002f1b0737a2ab64f09ea9f17da694c1f14025bd54
742404cfb72caec45c3a3147b1d3a1a56338ab31769f1fc8cae4aa9925b8c1296c0fa3b6c8b0
105b2e9aa4f724316fb61827a550306922b6b47058dc10c531834de7bcfc5c9430862494631e
c261bae5190aac130a202b015fb943d5c43b7e2b04a7b63e5a8395a9ab2ce85b8e58a24b221c
ab83e03dde852c341846cff8848097a13f683c0103cd3273be22272023041d57e60946b7962a
f428b18307c6da2941158a4579a6ac628f1587a8cefa28eaa47e2489af203832d2057f784ba7
f2256841bc6e0573c841724e89c3853e25a35e2b06ff41b7acec9113da348af97164f92edaa2
9ac9f16d330c5b356839e22795fee45fae34511ce9cbd126b18a063c374148c1a4c1e2e31eca
aa611be462ee74a09cb5716844bdfedccd88a960b2e02e0b993b13e5cf0289c6cbd2249bea07
27d860d1728dcefc8d47fbb05a10765859850d107795d544dffc212cb7bbc8f9a9b481566772
762da685a93c94868356eaca5191459e34c828dccc514b7420981197aa8bbaffb453dad755ad
6218f1624ee5298c9d972b27aa17dea298805889260093b947a0aff70d34934b13fb21c9e764
7717c6ea36904b3acbc4e5a0d1f047b6b775b27596af20a87f08bbadacb71e33672a335d75f8
828635a42e9bb91f675833f0b37679a63a593def5bc981e67a4ab8af525c0b4c70c8915a95af
917e88f5c753e59dea1714c6b207e1e5174c914851889a992a9bdf9720000cce0414bf0cac03
e3aa4e511721c1135151bbb8eea889138013e886b475316409245ecda25704d7bdfa88ac3c37
2d413c7f5596a4b64bcae2173e0cbc2e32242e40ca1ebf40a0ccb96bed7a71bc26841983a215
3272745b6585ea6685e677934a6e139958f003890447753ca3c40f3c2a0f4c0e07168c4c4406
88fa87dfd10db38ab4f0170e5e300dab0b63c55a2d248bab94173182c675e9164eca2691702b
37e7c00cac4c4c49c35f53e1c120e36ac5193308f3aa9f7b0233340ef9dc09bb1354a0460371
402d628b3cfb505d687bc669e34c63712ec5059e00940437876961f7b6f6a95c60ec1c1d1b58
a2c98b73b39a1cc43bc270b37497b2887a1b00881564666f0325bac3d713950776a5376c0e04
a63bca2bebd8183cac6c98b7a26f7268cad7a3b4186769ec727de085864b07cc996ee3c97ae5
f0c51378793e6aa3f2f4467c58a4daa6c8ceb535d5a95afc88890fb467c1340262e3befb2281
6bbac2d6a5c25c11598b1070c136af1de1003cd9cc996c437e76b67eb36714a46874369333ba
3be86b3bae04c878b03341f662875c802694b08c47150d974845a453ae42bfe0f27354719be3
0c243b07cba0f10108cb80613c5fa8954481d062ea952c3da10e43391478878e560a059cc84f
dfe376d9f31690205cfcb60e4e1b4f5c55ad1e4ab98e69a3f9a8aec8639a69d71c04a593bf19
68065cb6e500037db608da8226b55bb52438c509fe8f43be1459211ff44be64e0b0c42afd33c
808b0d4ca84e4b5e2d3400c04dbeb8360fc5ba3ce71959dbfc869de7225d2f0cbdfa81cfc64e
23fcb40b7c51b27ed9159da710068ff5151ba1049291cfe07ab8b17b8ec70bb5fe30fea1ed40
32e3dfa776f44ee801f1db36733e20e56743605f7a7a01e9b8e738df313efe
""")
    private let seipdBody = hex("""
0209020c4666e60fe58caa34a4fb861191c2c175c0253738365713199566b3d7a5daeced1548
2cdadfb87b8dadf35d42b260e6dbed8382ce933f31a4bf8ffdc8d48ab68656144ece7e8b4fb0
0b73d0b8787b7b03380932dd9b2c8dc1cb2dd88a515a531463bbc7e85041ec183172cdbac841
5431ddc52632d5260245187e2bfcb380892366ffabb4021f2fcb69640e325443185e9b01363e
38efb433871959ac1842dc342b8eea8e1aa2a67b07797ec17cede7e95f069b1e074ec04d09be
a0e875fb2daa7b840c63e99862bc1ecac41810bf0789f9f958470fb130e6538ed09b37c5cbb1
f03563b4d17c7af7ad01a94d0d53590b1b3e827b46d0b659edd058c36d130d0eb571654829e9
3d507cc50de1b93b375f7c57129b691444386f9e0a85ac491d3b368e1e22196ab57be32dc6df
0672cd7a1b8e9f9da4
""")
    private let fullMessage = hex("""
c1c3ed062106dafe0eebb2675ecfcdc20a23fe89ca5d12e83f527dfa354b6dcf662131a48b9d
2385e2fe4ce047b23147c1583272389a01b4bc2b99607d0c38ac18d2ab1d7a4a6bbdd2ea61b0
fe3948775c6318025d386e43b4cdfa24a2f9e0a0e8dc080f870645be23557760d12f6eaf77a1
5a60b5e362b906e9246d658140324cd2141af435be2f3fb93c06fa24e7c53867db5f34539ae3
4133c9de3eb8a0c4eaed0ded342baa99943bc18d73b1e66bee09e8ffdf75a77c91583e1c6965
fbf4fbad39766fd2cbe234414a5a2ab5625d9a11e19d35826df934a8180949983d5f4cb29b05
f1ac999623969139cb6dab945ae0c24e5f0a35b310e163f940e6b1b3ae4257cd8060c929441a
029ac8237c5072f1fc527aa20a875aa0855decfbbc437294b151cfb6d8efff34c353aba9f00d
e3308d0f243a5e44845583d164f640d5c13cc4d7ad05748e8c79be223ea20a263be4a413723a
e81efb38ab4ec0d3f8090f1d143da126993f1b5fb298637284ca9808de214dae1a225ecb001d
4aa6f8dcd5948ae318a3a369b8b9af3d57d7a27602a2a3c46b8a4cc47ba9303b2740db5967c8
78c20cf7d9dc262d0e9d01617801ae5d0c9d958218c8ffb4c5383daeaabcaeff9b4b330a9118
3b2fa76049df822a21b2e7f8954d867b26d4ac560ebf9d56105e17ea745ab4acff073db94f3a
f55d88183db3323a6de050f4744c7de594dbabdc4a102eae27e1bafd7a3517fd57ca64f1245a
4ba0fc89bca67cfcda5bf46aa255aa7c847836345622036c29e3547848f4255c93caecb440a3
2dc25293d4f3a92fbc4e98b4ee27ba17dd5701189a07077c1e8a45e11d4b9a729c121105effe
dc25529369ad26651e454732069f5a0a7b400d00dd0b14fe70d8766a5dba66b91c0aae9c9f90
8b0762315118ef710cc7fbb8f22a3f3135a8bdb25487e97831a9ac7bc96c6cdc4c9f3aaf9a87
03fff6e7b980adf7c70f6e105b2b418af3e414325158821087736eded3705a27f99136ab4e0a
fae823dfc016bf84b79058f19c16ad32961deb846f0262fc58e5cca3e0e482a7743b337771a1
d4b65ec58808aa14183a3413dba278973b7fcd37f7b0c6a781370603fbb3f5e4da77164fb365
ae972d62016230a0a311d4966ced3c0bc446f0e62006731c637a79c6a936bbadb525c09ebacd
ee7f72a0eb05013e89236b95dd94b6d540877ef34333103ca386fdf1e9cfc5d1acff2ebceadf
fd9da67defcb4ad4f56679f775919d567bd29708590a9a2580a23b267b9a44e4ab2860f0fdfc
61466e16d4861a4ebd9fb403ddb7590636f33119ef7af42ec577baf96797693f6ebc463f18a2
deb2d829a08d5a0d2f7b39f9b174e25a7d524d8c3ce5d83272284a4276a08eb1369b55f2da1a
ee82dcd41336370724d5c985317c06df5ce9dd562120c449f987b439f3b4c5be63fcbe8ee53f
845c0af70977768d6138742fa9d52bb2487e6bbad9bf89d4b7d05a7657baa19b52cd798333ee
4f56a5362d0e9122b39e6764a820c06fe0f9ecca47ab0285304541f8cf8824422d2b537af8c1
5b5aea40dfa3d1e5b4d779b25e807f2e12604d3af95b09f5fa6bd50e232841db3616a790f829
becd0241433252503c1c19f4e5eaa690844602287374a273524b623e0600b60e6c0be4f5a30c
662eece2adb13315095472044b0f3346d5415e8b3772d2c0790209020c4666e60fe58caa34a4
fb861191c2c175c0253738365713199566b3d7a5daeced15482cdadfb87b8dadf35d42b260e6
dbed8382ce933f31a4bf8ffdc8d48ab68656144ece7e8b4fb00b73d0b8787b7b03380932dd9b
2c8dc1cb2dd88a515a531463bbc7e85041ec183172cdbac8415431ddc52632d5260245187e2b
fcb380892366ffabb4021f2fcb69640e325443185e9b01363e38efb433871959ac1842dc342b
8eea8e1aa2a67b07797ec17cede7e95f069b1e074ec04d09bea0e875fb2daa7b840c63e99862
bc1ecac41810bf0789f9f958470fb130e6538ed09b37c5cbb1f03563b4d17c7af7ad01a94d0d
53590b1b3e827b46d0b659edd058c36d130d0eb571654829e93d507cc50de1b93b375f7c5712
9b691444386f9e0a85ac491d3b368e1e22196ab57be32dc6df0672cd7a1b8e9f9da4
""")

    private let expectedV        = hex("85e2fe4ce047b23147c1583272389a01b4bc2b99607d0c38ac18d2ab1d7a4a6b")
    private let expectedR        = hex("22150b430cf724ec19b8be55df9bcaade327085711369404a575c8023443b05f")
    private let expectedR_secret = hex("c04dbeb8360fc5ba3ce71959dbfc869de7225d2f0cbdfa81cfc64e23fcb40b7c")
    private let expectedSeed     = hex("51b27ed9159da710068ff5151ba1049291cfe07ab8b17b8ec70bb5fe30fea1ed4032e3dfa776f44ee801f1db36733e20e56743605f7a7a01e9b8e738df313efe")
    private let expectedWrappedC = hex("7374a273524b623e0600b60e6c0be4f5a30c662eece2adb13315095472044b0f3346d5415e8b3772")
    private let expectedSession  = hex("94a3b8c9784463bb96b682cddf549adb23579b75bcb646f989d7cfe3e6e14435")
    private let subkeyFingerprint = hex("dafe0eebb2675ecfcdc20a23fe89ca5d12e83f527dfa354b6dcf662131a48b9d")

    // MARK: - PKESK parsing (algorithm 35)

    func testCompositePKESKParse() throws {
        let pkesk = try OpenPGPPacketParser.parsePKESK(body: [UInt8](pkeskBody))
        XCTAssertEqual(pkesk.version, 6)
        XCTAssertEqual(pkesk.algorithm, 35)
        XCTAssertEqual(Data(pkesk.ephemeralPublicKey), expectedV, "ecdhCipherText (V) mismatch")
        XCTAssertEqual(pkesk.mlkemCipherText.count, 1088)
        XCTAssertEqual(Data(pkesk.wrappedSessionKey), expectedWrappedC, "wrapped session key (C) mismatch")
    }

    // MARK: - Secret-material parsing

    func testCompositeSecretMaterialParse() throws {
        let m = try CompositeKEMPacket.parseUnprotectedSecretMaterial(secretBody: [UInt8](secSubkeyBody))
        XCTAssertEqual(Data(m.ecdhSecret), expectedR_secret, "X25519 secret mismatch")
        XCTAssertEqual(Data(m.ecdhPublic), expectedR, "X25519 public (R) mismatch")
        XCTAssertEqual(Data(m.mlkemSeed), expectedSeed, "ML-KEM seed mismatch")
    }

    // MARK: - Session-key decapsulation (RFC 9980 message)

    func testCompositeDecryptSessionKeyKAT() throws {
        let pkesk = try OpenPGPPacketParser.parsePKESK(body: [UInt8](pkeskBody))
        let m = try CompositeKEMPacket.parseUnprotectedSecretMaterial(secretBody: [UInt8](secSubkeyBody))
        let sk = try CompositeKEMPacket.decryptSessionKey(pkesk: pkesk, secret: m)
        XCTAssertEqual(Data(sk), expectedSession, "decapsulated session key mismatch vs RFC 9980")
    }

    // MARK: - Full end-to-end decrypt via the low-level SEIPD path

    func testCompositeEndToEndDecryptKAT() throws {
        let pkesk = try OpenPGPPacketParser.parsePKESK(body: [UInt8](pkeskBody))
        let m = try CompositeKEMPacket.parseUnprotectedSecretMaterial(secretBody: [UInt8](secSubkeyBody))
        let sk = try CompositeKEMPacket.decryptSessionKey(pkesk: pkesk, secret: m)

        let seipd = try OpenPGPPacketParser.parseSEIPD(body: [UInt8](seipdBody))
        let inner = try OpenPGPPacketParser.decryptSEIPDv2(seipd: seipd, sessionKey: sk)
        XCTAssertNotNil(Data(inner).range(of: Data("Testing".utf8)),
                        "decrypted inner packet stream should contain the literal 'Testing'")
    }

    // MARK: - Full decrypt through the public decryptMessage entry point

    /// Exercises the wired composite branch in the app's real decrypt path:
    /// build a CompositeKEMPacket.DecryptionKey from the sample secret and hand
    /// the whole encrypted message to decryptMessage. It must return the literal
    /// payload "Testing\n".
    func testCompositeDecryptMessageEndToEnd() throws {
        let secret = try CompositeKEMPacket.parseUnprotectedSecretMaterial(secretBody: [UInt8](secSubkeyBody))
        let key = CompositeKEMPacket.DecryptionKey(
            subkeyID: Array(subkeyFingerprint.prefix(8)),
            subkeyFingerprint: [UInt8](subkeyFingerprint),
            secret: secret)

        let out = try OpenPGPPacketParser.decryptMessage(
            messageData: fullMessage,
            decryptionKeys: [],
            compositeKeys: [key])

        XCTAssertNotNil(out.range(of: Data("Testing".utf8)),
                        "decryptMessage should recover the literal 'Testing'")
    }

    // MARK: - helper

    private static func hex(_ s: String) -> Data {
        let chars = s.filter { $0.isHexDigit }
        var out = Data(capacity: chars.count / 2)
        var idx = chars.startIndex
        while idx < chars.endIndex {
            let next = chars.index(idx, offsetBy: 2)
            out.append(UInt8(chars[idx..<next], radix: 16)!)
            idx = next
        }
        return out
    }
    private func hex(_ s: String) -> Data { Self.hex(s) }
}
