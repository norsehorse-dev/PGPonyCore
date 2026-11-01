// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// Ed448Tests.swift
// PGPonyCoreTests
//
// 8.4.0 build 8 (plan 2, Android 4.6.0 item 3): Ed448 (Ed448.swift) and the
// RFC 9980 algorithm 31 composite (ML-DSA-87 + Ed448) it completes.
//
//   - SHAKE256 known answers (Ed448 hashes with it).
//   - Every pure Ed448 vector of RFC 8032 section 7.4: key derivation,
//     signing (deterministic, so byte for byte) and verification.
//   - Strict verification: tampered message and signature, S >= L, a
//     nonzero top octet of S, non-canonical and off-curve points, the x = 0
//     sign-bit case, wrong lengths.
//   - Cross-checks: seeds, messages and signatures made by OpenSSL's Ed448
//     (Python cryptography 50), and the Ed448 half of a Sequoia-made
//     ML-DSA-87 + Ed448 certificate.
//   - Algorithm 31 end to end: a composite sign and verify round trip, a
//     generated ML-DSA-87 key's shape, self-signatures and subkey binding
//     through CertificateValidator, and the Sequoia fixture's bindings and
//     back-signatures through CertificateValidator.
//
// Ed448 itself needs nothing from the OS; the ML-DSA half needs CryptoKit's
// MLDSA87 (iOS 26), and those tests skip below it the way the 65 tests do.
//
// Ported from the app's Build8Ed448Tests.swift. The tests there that need the app's
// storage, models or secret-key unlock stay in the app.

import XCTest
import CryptoKit
@testable import PGPonyCore

@MainActor
final class Ed448Tests: XCTestCase {

    // MARK: - Helpers

    private func requireMLDSA() throws {
        guard MLDSAService.isAvailable else {
            throw XCTSkip("ML-DSA needs an iOS 26 runtime (CryptoKit MLDSA87); this simulator has none.")
        }
    }

    private func bytes(_ hex: String) -> [UInt8] {
        var out: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            out.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    private func hex(_ b: [UInt8]) -> String {
        b.map { String(format: "%02x", $0) }.joined()
    }

    private struct Vector {
        let seed: String
        let publicKey: String
        let message: String
        let signature: String
    }

    /// RFC 8032 section 7.4, the pure Ed448 vectors (blank, 1, 11, 12, 13,
    /// 64, 256 and 1023 octets). The context vector is left out: RFC 9980
    /// uses the empty context only.
    private let rfc8032: [Vector] = [
        Vector(seed: "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
               publicKey: "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
               message: "",
               signature: "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600"),
        Vector(seed: "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
               publicKey: "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
               message: "03",
               signature: "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00"),
        Vector(seed: "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328",
               publicKey: "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400",
               message: "0c3e544074ec63b0265e0c",
               signature: "1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d389dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00b8dbdeea6d3b051068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5028961c9bf8ffd973fe5d5c206492b140e00"),
        Vector(seed: "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b",
               publicKey: "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580",
               message: "64a65f3cdedcdd66811e2915",
               signature: "7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4ae90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00b45c2c96ba457eb1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861e72003cbae6d6b8b827e4e6c143064ff3c00"),
        Vector(seed: "7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eebc0266a11a93970100e",
               publicKey: "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80",
               message: "64a65f3cdedcdd66811e2915e7",
               signature: "6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb4890810c162c027468675ecf645a83176c0d7323a2ccde2d80efe5a1268e8aca1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf56b4e7e0ba5519234d047155ac727a1053100"),
        Vector(seed: "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01",
               publicKey: "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00",
               message: "bd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5512204a30c17d1f50b5079631f64eb3112182da3005835461113718d1a5ef944",
               signature: "554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b18dfde9b9b90775e67f47d4a1c3482058efc9f40d2ca033a0801b63d45b3b722ef552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba5f30e88e36ec2703b349ca229c2670833900"),
        Vector(seed: "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5",
               publicKey: "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00",
               message: "15777532b0bdd0d1389f636c5f6b9ba734c90af572877e2d272dd078aa1e567cfa80e12928bb542330e8409f3174504107ecd5efac61ae7504dabe2a602ede89e5cca6257a7c77e27a702b3ae39fc769fc54f2395ae6a1178cab4738e543072fc1c177fe71e92e25bf03e4ecb72f47b64d0465aaea4c7fad372536c8ba516a6039c3c2a39f0e4d832be432dfa9a706a6e5c7e19f397964ca4258002f7c0541b590316dbc5622b6b2a6fe7a4abffd96105eca76ea7b98816af0748c10df048ce012d901015a51f189f3888145c03650aa23ce894c3bd889e030d565071c59f409a9981b51878fd6fc110624dcbcde0bf7a69ccce38fabdf86f3bef6044819de11",
               signature: "c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f00cf966546b72bcc7d58be2b9badef28743954e3a44a23f880e8d4f1cfce2d7a61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc60987fd08527c1a8e80d5823e65cafe2a3d00"),
        Vector(seed: "872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8",
               publicKey: "a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400",
               message: "6ddf802e1aae4986935f7f981ba3f0351d6273c0a0c22c9c0e8339168e675412a3debfaf435ed651558007db4384b650fcc07e3b586a27a4f7a00ac8a6fec2cd86ae4bf1570c41e6a40c931db27b2faa15a8cedd52cff7362c4e6e23daec0fbc3a79b6806e316efcc7b68119bf46bc76a26067a53f296dafdbdc11c77f7777e972660cf4b6a9b369a6665f02e0cc9b6edfad136b4fabe723d2813db3136cfde9b6d044322fee2947952e031b73ab5c603349b307bdc27bc6cb8b8bbd7bd323219b8033a581b59eadebb09b3c4f3d2277d4f0343624acc817804728b25ab797172b4c5c21a22f9c7839d64300232eb66e53f31c723fa37fe387c7d3e50bdf9813a30e5bb12cf4cd930c40cfb4e1fc622592a49588794494d56d24ea4b40c89fc0596cc9ebb961c8cb10adde976a5d602b1c3f85b9b9a001ed3c6a4d3b1437f52096cd1956d042a597d561a596ecd3d1735a8d570ea0ec27225a2c4aaff26306d1526c1af3ca6d9cf5a2c98f47e1c46db9a33234cfd4d81f2c98538a09ebe76998d0d8fd25997c7d255c6d66ece6fa56f11144950f027795e653008f4bd7ca2dee85d8e90f3dc315130ce2a00375a318c7c3d97be2c8ce5b6db41a6254ff264fa6155baee3b0773c0f497c573f19bb4f4240281f0b1f4f7be857a4e59d416c06b4c50fa09e1810ddc6b1467baeac5a3668d11b6ecaa901440016f389f80acc4db977025e7f5924388c7e340a732e554440e76570f8dd71b7d640b3450d1fd5f0410a18f9a3494f707c717b79b4bf75c98400b096b21653b5d217cf3565c9597456f70703497a078763829bc01bb1cbc8fa04eadc9a6e3f6699587a9e75c94e5bab0036e0b2e711392cff0047d0d6b05bd2a588bc109718954259f1d86678a579a3120f19cfb2963f177aeb70f2d4844826262e51b80271272068ef5b3856fa8535aa2a88b2d41f2a0e2fda7624c2850272ac4a2f561f8f2f7a318bfd5caf9696149e4ac824ad3460538fdc25421beec2cc6818162d06bbed0c40a387192349db67a118bada6cd5ab0140ee273204f628aad1c135f770279a651e24d8c14d75a6059d76b96a6fd857def5e0b354b27ab937a5815d16b5fae407ff18222c6d1ed263be68c95f32d908bd895cd76207ae726487567f9a67dad79abec316f683b17f2d02bf07e0ac8b5bc6162cf94697b3c27cd1fea49b27f23ba2901871962506520c392da8b6ad0d99f7013fbc06c2c17a569500c8a7696481c1cd33e9b14e40b82e79a5f5db82571ba97bae3ad3e0479515bb0e2b0f3bfcd1fd33034efc6245eddd7ee2086ddae2600d8ca73e214e8c2b0bdb2b047c6a464a562ed77b73d2d841c4b34973551257713b753632efba348169abc90a68f42611a40126d7cb21b58695568186f7e569d2ff0f9e745d0487dd2eb997cafc5abf9dd102e62ff66cba87",
               signature: "e301345a41a39a4d72fff8df69c98075a0cc082b802fc9b2b6bc503f926b65bddf7f4c8f1cb49f6396afc8a70abe6d8aef0db478d4c6b2970076c6a0484fe76d76b3a97625d79f1ce240e7c576750d295528286f719b413de9ada3e8eb78ed573603ce30d8bb761785dc30dbc320869e1a00"),
    ]

    /// Made with Python cryptography 50 (OpenSSL Ed448) from random seeds
    /// and messages of 0, 1, 32, 64, 200 and 1000 octets.
    private let openSSL: [Vector] = [
        Vector(seed: "cd78b43e7812764aaa2648090463e601031ec587098510dbbf97fddbe3a1aaa5a932579714acc809f6df8bdd2446bd8b7f7d5cc53f58335fd2",
               publicKey: "269cee2ef638c76b6906bddda20defa025267a97fa8e20e239ec9f191e059cfa2326343f481bd8303571bc87d9b0aca202fe3519183bfa6a80",
               message: "",
               signature: "4c27b8fe7b6b71ed0b3032f9b36363998eb38bef3685c75cba187db04a07338a911eb459cbe298e566083b1aee2e5fccefe27a9be088e1e1801053225b0e2899c0caaf997aa62000180092b33f5062eb9bd0c9a569a9febcedddb4ef44ea27eeff532ed1121a5a6697e67eabfd75dc3d1b00"),
        Vector(seed: "3b4c9dad9916598fccc8e87df0b753e2398a5359bf29556d31e49fa95c16f71306b8ce619edfa12f83452e1d32ce1d653e20d6c40ef52d305e",
               publicKey: "03b7c999d113469496bf6e78182b3863a668fcd6385b0ab49eb1948786447da6e24a89e5c5ee506eb07cd23fdb3c04dd905d803f393da12a80",
               message: "fd",
               signature: "e46cd75e1c34f7b9f01ef85dc82d728d4fd4bd55fae0e3274b2f273aa85e7d9a212a67a288bf25f2ac4e0f79ccee493acae68b6ab966150a006019545b4597a993dcd03fc5c651dce8cca1117bf3ca045776ffd3cb0b5609208a780c84937157bc02eb304c830be0b5bfcf2238c7b2273e00"),
        Vector(seed: "e2c1596794fb07080f31e24037c8f1f454c379942d12670d762f69f0592af57210c1cd99fcf35ed446321ebc4a9792435a2721fbe3445c578e",
               publicKey: "0f9275c08a32bc731952269a1067b4f25e1d5b48a98062b8ef3ef6aba6ae65c206c67ad8169599a5c700501c1fe5bf244c860c326d93ada680",
               message: "4361a139f705608d7d734e2f96a0e5c505fe937a4d7dd1b587b82e531cd74fda",
               signature: "72c6cb745d69252e82439acf4de5dcc61c1fa9849d75ff64add09ef78d6386cd015265143601a9a2247bc12100bef3698f8a421a7efb7e9a00d60ccc36a788bd469ecc30601bd4f837b152826214964123027768d73d53d0bfe9170e477aee12b56b6143c1bb56524badb685e2b1f2a13100"),
        Vector(seed: "9dcce66a3a849d7f80a23b0d5f5ede64b77a4599f87d1a0dbdd64b9fd8543f5ec3945dd59dcdfd25c968e81bc39f6fc4e1d8d2696b41825100",
               publicKey: "cc7829af5d333c64110d0de1ad57d731a33ebd59bafc9f0d72fdac0439f9431c1ae8b94755735754cb4edd505d9c20209f73baaf8afc109400",
               message: "b1cfa6fac5695890ac27a331d4d5cd942dae547bd9bca205763ee170bb648faacc70ae7fc6ce2a62e1052135dec8a26e3dcbebe826cc2301c0a11f3c210116eb",
               signature: "9307acd3a4d88c8a57f2cee280932c90355855a1d737e91908fa70b4108f481fd151c537fd00a0429af7049a342816e04f01296d11f04489801363fe19b3e76b3f86a8141d78d42d6c13aa021b25cff56734bfd9eb849ec02f110c5e07ed9c273cf29e94a0be6ef78df4874edfed6ca62100"),
        Vector(seed: "e7e2d1649df25793d687c295ed302cb17550fe30d86634917d650fcab5c9bbbae1b8efd1bc753a97c1ff9dcc02eab490aed0e752cd17c11350",
               publicKey: "f8ac2e8712570718740685bdd2a9ca9d029f271c5493f719ef1da4d19537d9677ff68bf276b6a4d6e7f190f4803486137fb0b62f1fdf9f5280",
               message: "de16a1c0f22f781a008cbc24233a2df666af7e403b4abb8c51cd559733122f6067c5748aae97df83354905584407fef64705d39e10a23ef8d1c248fbf22de6d912337a18ffda856882e01f9653fdd613221cb492df09086444faa85d1ff894598c57a6584f7b06b8702e54312217061c2710e61a72a8a62ba4d8dff275dfb0c8443caf98180f30bc292a8de3b8356ef78bca314abe3950ad4774399e662b463247ea5520f3a9e0578da14c684ec409022e5620f6bbb9aea5a71531a53381644f4746d3ac1adc8991",
               signature: "239e6e364d0085d3c3d5b35982765a5ef80147e3f11424ebeabda42bf15ec45d8de50ead9f216016ef9cb63d5582f230bcf7fe3071ffb911006313bf68758819ab79f9889e6d5d868fa7415756bb6cd23ede03c18115de60a18201b8927e56c53bb758f2bce7c431df4d1f98a32d941f2200"),
        Vector(seed: "9b1d6f64fcdf6d5082b0717b76a2540e327955fcad36720040584183ac76d8b9d4faf79304434bbb2d335dcf0e9c86e837c95cecca8d6ec918",
               publicKey: "3c4aa83e7fe4286c8ba60c1acd4157598a660c740557f6de021107c200e410cd80e8792f38b8fbfc3029bfe4b04dde2b92cb3be0a2de8ee480",
               message: "8e740cc2caa4db8d5facc74e4d7fed43d2cfe8f7d5f0a82eb6bdbc921008ea595f5278837a870be9325651960275ab7052222ee6363f064da1a29beeddf9e0317f8358924676139f8420dc3563d96562cee43149e4acbf804061204665016b3d74c5dd10b372fca0277a96522666b3bea518252a542edf4f2b15bb75389620caed9ca0539aaf75645908ba4b8cc7e4e4434cfb4dd0dea3cf9573e2222981512f0c78a3bf23408ff694ec55450886f16e51cd44b6573746e72f945fcec5e4acf08f06200af25ecd22578a00262da19828978e850e039ad773e00c9a18869993f847edd3215d9103536e316e2c7789ce3731e210cb20e9969fe5c8b666a2fcf07556fc2650ba299c3c3f70cda37f344358e2f5feed956093941de6d871fab509bfd8ad673ff459e7420d57601bc45693310f582ae0a570965a934b8e07fed6bf843499ab5464b39c884ca4f0f8e2b765f6b1a6fc09daf79796e74820abbc4e21b53f1aa7fd8a56a5f7efdcd1172e1607c42235d7ca4c7fa845f10f342720cf4ddd328411f0519e4095a93edc2e3fd6b1abcaf3cd97b758b82bbe5cecb119a4c12313381080e84a4372da13300ac78cef333f0b91831c8844a72f0af7e9ef528d7f8cbd14b072156fbc2e40869650fe32a763367ebf4314328317a7e75996198c1041c4f2009ed63c828bbf256ff2055839398cfe3d133e60e5bc20ec807fcd1efe63e3b317d6c07bb9b12b765481e459c4cf277ad98eab59da496b33d4e055ebd0216b3ce6a948fc9eb4435f6bb5facc756f375800c28f64a8b9fa2a91c92a7225ca30b358b7b4eff8c3709ca17aa961dfbbe2fed10f153f3eeb36229bc1c2f7fc4ffb66d6aaddbc8b97e13094d8985cc752f2cb061c73812b47e38d876f0c8db4fb11514f87c7db05bdd95af40465e9f363ef60dc380eb72b4126a75c6998042b86776e604f2046a14b74bf010d27f2f0e86011e1e03e9f99d817d3814629e36025dadb11fb79c02d23b1a931bc913c692725b586b7152fb77340ac649854c3b97b36b00382a08ad0bfb899e04902e9210bc51a32f2ad4c39e6883895a6c639a9fae2102f679c82be2acbe7f52a007b359f25bbda2cdf35201a7e311b31b471d39b62dee30851a69dceda9c46035e2e7988afdc616af45c1dc7025800e2cba040b3c064f7ca3915467ac38bdfcc8c9bed080cae92795094a6eb9d4f69fd840623e3ccddff776c216666acb2b9138da64e20fb81ebeb9f000a12604ae9bfa4ec5388620425d98a69cbeaa60cece36109fb902140eb6a809fc1c5ac0dbf1d1645366a2bc1b6443085d7ca649d73ae8c295535c3150ae4d53ac3cf4a370ea9187573c48e7edc0296a571350c204aa768925357a5a23b2fa816b0d07a5268da69c8444dfdbb61da978152",
               signature: "40e2d1ccabe01ee8c224c4dce17db1f8a2a04c1c82191d5be46e0e9e37655c2c9735ff08f1378e6228286492c60a80bfb5300f60defc26d4009eb206f88f3e234e96ca469a95f46f8d2ef7c1de0aa46d2a4573c54412bd8878a9c2ee28d661fc7dec154811156160924c81a240c2363a1600"),
    ]

    // MARK: - SHAKE256

    func testShake256KnownAnswers() {
        XCTAssertEqual(hex(Keccak.shake256([], outLen: 32)),
                       "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
        XCTAssertEqual(hex(Keccak.shake256(Array("abc".utf8), outLen: 64)),
                       "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4")
    }

    // MARK: - RFC 8032 vectors

    func testRFC8032PureVectors() throws {
        XCTAssertEqual(rfc8032.count, 8)
        for (i, v) in rfc8032.enumerated() {
            let seed = bytes(v.seed), pub = bytes(v.publicKey), msg = bytes(v.message), sig = bytes(v.signature)
            XCTAssertEqual(try Ed448.publicKey(seed: seed), pub, "vector \(i): public key")
            XCTAssertEqual(try Ed448.sign(message: msg, seed: seed), sig, "vector \(i): signature")
            XCTAssertTrue(Ed448.verify(signature: sig, message: msg, publicKey: pub), "vector \(i): verifies")
        }
    }

    func testRFC8032VectorsRejectTampering() {
        for (i, v) in rfc8032.enumerated() {
            let pub = bytes(v.publicKey), msg = bytes(v.message), sig = bytes(v.signature)
            XCTAssertFalse(Ed448.verify(signature: sig, message: msg + [0], publicKey: pub), "vector \(i): longer message")
            if !msg.isEmpty {
                var m = msg; m[0] ^= 0x01
                XCTAssertFalse(Ed448.verify(signature: sig, message: m, publicKey: pub), "vector \(i): changed message")
            }
            var r = sig; r[3] ^= 0x01
            XCTAssertFalse(Ed448.verify(signature: r, message: msg, publicKey: pub), "vector \(i): changed R")
            var s = sig; s[60] ^= 0x01
            XCTAssertFalse(Ed448.verify(signature: s, message: msg, publicKey: pub), "vector \(i): changed S")
            let other = bytes(rfc8032[(i + 1) % rfc8032.count].publicKey)
            XCTAssertFalse(Ed448.verify(signature: sig, message: msg, publicKey: other), "vector \(i): another key")
        }
    }

    // MARK: - Strict verification

    func testStrictVerificationRejectsMalformedInput() throws {
        let pub = bytes("0f9275c08a32bc731952269a1067b4f25e1d5b48a98062b8ef3ef6aba6ae65c206c67ad8169599a5c700501c1fe5bf244c860c326d93ada680")
        let msg = bytes("4361a139f705608d7d734e2f96a0e5c505fe937a4d7dd1b587b82e531cd74fda")
        let sig = bytes("72c6cb745d69252e82439acf4de5dcc61c1fa9849d75ff64add09ef78d6386cd015265143601a9a2247bc12100bef3698f8a421a7efb7e9a00d60ccc36a788bd469ecc30601bd4f837b152826214964123027768d73d53d0bfe9170e477aee12b56b6143c1bb56524badb685e2b1f2a13100")
        XCTAssertTrue(Ed448.verify(signature: sig, message: msg, publicKey: pub), "the untouched signature verifies")
        // S + L: the same value mod L, non-canonical (signature malleability).
        XCTAssertFalse(Ed448.verify(signature: bytes("72c6cb745d69252e82439acf4de5dcc61c1fa9849d75ff64add09ef78d6386cd015265143601a9a2247bc12100bef3698f8a421a7efb7e9a00c95124e2394b366af35bf6ed8d966559418958115e7190e7eb9a32543d53d0bfe9170e477aee12b56b6143c1bb56524badb685e2b1f2a17100"), message: msg, publicKey: pub), "S >= L")
        var topS = sig; topS[113] = 1
        XCTAssertFalse(Ed448.verify(signature: topS, message: msg, publicKey: pub), "S with a nonzero last octet")
        // R encoded with y = 1 + p, a non-canonical encoding of the identity.
        XCTAssertFalse(Ed448.verify(signature: bytes("00000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00d60ccc36a788bd469ecc30601bd4f837b152826214964123027768d73d53d0bfe9170e477aee12b56b6143c1bb56524badb685e2b1f2a13100"), message: msg, publicKey: pub), "non-canonical R")
        // y = 2 has no x on the curve.
        let offCurve = bytes("020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        XCTAssertFalse(Ed448.verify(signature: offCurve + Array(sig[57...]), message: msg, publicKey: pub), "R off the curve")
        XCTAssertFalse(Ed448.verify(signature: sig, message: msg, publicKey: offCurve), "public key off the curve")
        XCTAssertFalse(Ed448.verify(signature: sig, message: msg, publicKey: bytes("00000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00")), "non-canonical public key")
        // x = 0 with the sign bit set (the identity, y = 1, x0 = 1).
        XCTAssertFalse(Ed448.verify(signature: sig, message: msg, publicKey: bytes("010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080")), "x = 0 with sign bit 1")
        var lowBits = pub; lowBits[56] |= 0x01
        XCTAssertFalse(Ed448.verify(signature: sig, message: msg, publicKey: lowBits), "bits 448 to 454 set")
        XCTAssertFalse(Ed448.verify(signature: Array(sig.dropLast()), message: msg, publicKey: pub), "113-octet signature")
        XCTAssertFalse(Ed448.verify(signature: sig, message: msg, publicKey: Array(pub.dropLast())), "56-octet public key")
        XCTAssertThrowsError(try Ed448.publicKey(seed: [UInt8](repeating: 7, count: 56)))
        XCTAssertThrowsError(try Ed448.sign(message: msg, seed: [UInt8](repeating: 7, count: 58)))
    }

    // MARK: - Cross-checks

    func testMatchesOpenSSL() throws {
        for (i, v) in openSSL.enumerated() {
            let seed = bytes(v.seed), pub = bytes(v.publicKey), msg = bytes(v.message), sig = bytes(v.signature)
            XCTAssertEqual(try Ed448.publicKey(seed: seed), pub, "OpenSSL \(i): public key")
            XCTAssertEqual(try Ed448.sign(message: msg, seed: seed), sig, "OpenSSL \(i): signature")
            XCTAssertTrue(Ed448.verify(signature: sig, message: msg, publicKey: pub), "OpenSSL \(i): verifies")
        }
    }

    func testFreshSeedsRoundTrip() throws {
        for length in [0, 32, 64] {
            let seed = try Ed448.generateSeed()
            XCTAssertEqual(seed.count, 57)
            let pub = try Ed448.publicKey(seed: seed)
            let msg = [UInt8](repeating: 0x5A, count: length)
            let sig = try Ed448.sign(message: msg, seed: seed)
            XCTAssertEqual(sig.count, 114)
            XCTAssertEqual(try Ed448.sign(message: msg, seed: seed), sig, "pure Ed448 is deterministic")
            XCTAssertTrue(Ed448.verify(signature: sig, message: msg, publicKey: pub))
        }
    }

    /// The Ed448 half of the direct-key signature on the Sequoia-made
    /// ML-DSA-87 + Ed448 fixture (sq-1024-sec), over its SHA-512 v6 digest.
    func testSequoiaEd448HalfVerifies() {
        let pub = bytes("f8d4395c119dbd29d3d9e301cbea7ac2a8f5298f680451a343aaa16204e89d2813052d05b1bcb158c2af2838252a5b5678fb434f4878b44680")
        let digest = bytes("a8c8ef67692b9ba867591cbd3a32297766d0161e11a9705197831902d110b7a76395a6867e6058856a4b2425213d46a7a46bd7b12b2e1d197c1629ada708a21b")
        let sig = bytes("4c219e8acf650fb1c06cab056439a51c5425d17320bab5db9c08e756da9f26fba5115b85663e2cdddfdef7c49c55f44cd75dce9be32e65d400be2413c485e2ad854a95d4775ce57bd736673934e7bff7a2a23e2f6f3f13282a2a25044d3c417ca772f2e9776c0310a03964d6a666611f1300")
        XCTAssertTrue(Ed448.verify(signature: sig, message: digest, publicKey: pub))
        var other = digest; other[0] ^= 0x80
        XCTAssertFalse(Ed448.verify(signature: sig, message: other, publicKey: pub))
    }

    func testCompositeSignVerifyRoundTrip() throws {
        try requireMLDSA()
        let suite = CompositeSignSuite.mldsa87Ed448
        let secret = try Ed448.generateSeed() + MLDSAService.randomSeed()
        XCTAssertEqual(secret.count, suite.compositeSecretLength)
        let material = try CompositeSigner.publicMaterial(suite: suite, compositeSecret: secret)
        XCTAssertEqual(material.count, suite.compositePublicLength)
        XCTAssertEqual(Array(material[0..<57]), try Ed448.publicKey(seed: Array(secret[0..<57])))

        let digest = Array(SHA256.hash(data: Data("algorithm 31 round trip".utf8)))
        let signature = try V6SignatureKey.composite(suite, compositeSecret: secret).sign(digest: digest)
        XCTAssertEqual(signature.count, 114 + 4627)
        XCTAssertEqual(CompositeSigVerifier.verify(suite: suite, compositePublic: material, signature: signature, digest: digest), .valid)

        var edTampered = signature; edTampered[10] ^= 0x01
        XCTAssertEqual(CompositeSigVerifier.verify(suite: suite, compositePublic: material, signature: edTampered, digest: digest),
                       .invalid, "a bad Ed448 half fails the composite")
        var mlTampered = signature; mlTampered[200] ^= 0x01
        XCTAssertEqual(CompositeSigVerifier.verify(suite: suite, compositePublic: material, signature: mlTampered, digest: digest),
                       .invalid, "a bad ML-DSA half fails the composite")
        var otherDigest = digest; otherDigest[0] ^= 0x01
        XCTAssertEqual(CompositeSigVerifier.verify(suite: suite, compositePublic: material, signature: signature, digest: otherDigest),
                       .invalid)
    }

    func testMLDSA87IsOfferedAfterMLDSA65() {
        let generatable = KeyAlgorithm.generatable
        XCTAssertEqual(generatable.contains(.v6MLDSA87), MLDSAService.isAvailable)
        if let i65 = generatable.firstIndex(of: .v6MLDSA65), let i87 = generatable.firstIndex(of: .v6MLDSA87) {
            XCTAssertLessThan(i65, i87, "ML-DSA-65 stays first, the recommended tier")
        }
        XCTAssertTrue(KeyAlgorithm.v6MLDSA87.isCompositeSignature)
        XCTAssertEqual(CompositeSignSuite.mldsa87Ed448.keyAlgorithm, .v6MLDSA87)
    }
}
