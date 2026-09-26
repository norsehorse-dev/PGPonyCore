// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// UncheckableBindingTests
//
// Bindings made by a primary this code cannot verify (DSA, brainpool) count
// for encryption only for subkeys the caller lists in `pinnedSubkeys`, and
// `newestVerifiedBinding` never returns one. A ring that does not parse, or
// has no public primary key packet, is refused. Fixtures made with gpg
// 2.4.4: a DSA primary with an ElGamal subkey, the same key with a second
// ElGamal subkey whose binding has one byte of its signature changed, and a
// brainpoolP256r1 primary with an ECDH subkey.

import XCTest
@testable import PGPonyCore

final class UncheckableBindingTests: XCTestCase {

    private let dsaRing = Data(base64Encoded: "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")!
    private let dsaRingWithAlteredSecondBinding = Data(base64Encoded: "mQMuBGq0cfURCAD3qbxAS5EWTDqlVO8ghg2VDDGAU5CYy7FaSvGurhc9HGcJio9attPdj3/cLTUFd0jv94sDJZZigvF9+w/US2tpYm3rOjxQ4o8LIKM207QahmVvctyOi+JeFQmNqXxkFDjubr6sVAW5bgPHC7RjhsGAzSSsNBNCsp7GmOX50RPIG7gY6CDl8ii4wqkjmhzcXuSaYcjOTLqwkCeIu2wJ/cL07G6rHO7BG62W8Vw3E6lXUaVU2nOzPtI5J0ULv3Dy+Fmjk6yCXKW6vAng8lhUfJa3ot+HMBN0lOl7JmLQJjcHn1awXFNk70p+ZOfjj/UZ0Vi8+ylwIEQYBa0Gt2WBhlr/AQC0Li/33+Mv0+nTnQi1MV3L4O/46xfB+UfkWoZs26t1CQgAuVd9HJW368y6odKxsBArnsbJVICwPaN5UgH0p5UWfLFV7hfnCfghAwX52Sl2dFRdnJVSx6jflnAqqO/MxYmT//E39c7KCRrp7n2AtRfDSOQzmyXhxvkTDKtIMZthLqRnwZbYGfbO+AR4mC6AVGao5qZPElRdGGsYnu/5wltki5BUlbznwwhp7befj+sydeEKRJsXnFQIYjH/mNpTkAwpITwe+Tm8MSMDoNHpa0K/3joIHsDwdDSR2+GFOU1T97/C1cCcl3jQEt9m+QNpRAbQ49Ha2JoRxFcyapTbAz9xxU51wF7he+O+SwujMf1QLzAaWAUVe/zkEd1HfODaxCf6uAgAisT4qujYUyObECwEV/P0uwYkVxbR8fvzYLeNhtIi9r6H7ydGBfAqxp1TWKwYbY+IMhpqzcznHwO9+rSkGST3k/bf77EbYgrdOQifYVlhYSXKJ5mXlm+kIkR+HHsLifdJleUw8HhXBjBYKduf1VZbqQ+5IlMBblKMEw6kxWgWXiCz8P1PFw/YQ7VTdf61wlUSrA5savBcKwRQ+SKmTIv5/uyl3Qj19O23XqnxbmeymnSVPDTCE7f8y8dxY3u3Yk3S6FmGlw4INP22bmTUYdE+ht10B3oWbGpSycUQI+Tj+Ke/OvsFjp5GVs6WSaSyT89AuS3sBu1wTniW0QgDehyD7bQdRHNhIENvbnRhY3QgPGRzYUBleGFtcGxlLm9yZz6IkwQTEQgAOxYhBPHrg0UjFfk3LrLnA12B/26PdyaGBQJqtHH1AhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEF2B/26PdyaG0Q4BAJkeowCPo8QXf9FKPaPa4KT/cWuLmwq41Bg1fhnCDc4BAP9aGkZPLEqnKDOeZTAI4zq1tvC3HYLwlAufgYA6x3Cr17kCDQRqtHH2EAgAszdrbjToMxpAqgJQvbydvPJHk5JCL9JJvWMYUxPgtOofCSCXc/38pLC5DgjFqnAx706PUueclxU9O5w1scXGKN//nNNzyE+KaPdbMof9J92wawE28TWYMPqRaNPA87tbYtpYkNI2Nszg76gpOxSqfT3RWmocmRkX893697GbSRSWhkh04bpNpqCLqRtzcpGxw8yO2czM8pO2dgI36sd82E1wgKyvgvB57pYI8ds9rwCzi3G5y/Q4v38RTqISBKNIYKrIsG0c0gS07HEiv9WhrjKXpxeOmdd8QXVy1XzB5IgkwN/CH5FWJ3cwPA2wx07YjacA9xvdQOO1DmvtxazYuwADBQf+LAlm6Uzfea+s/EIm8Z/1Z27didkV52aay4JRIGDPzF5LRKGnDqEin7bZlzvH8Tyfnd+Q4hv+t+XvLyV2Ql8f6FgxBDX6M9OMDWbTHQQcqGVMsNmCqHGbWKpPLm/DQNuMdFC47YL1BmCZMNWp+5OV+DwHIN3Hp+t8b54xeIfqP2CGKLnEt4AXHv46Up7m4o4eln96PPEiYCv6GgNPdqshDkIpv6S/2vcrWM6HVxhqnyW+kcmMYL0N1LD210bvfrJxIPvkyeVWwT/tWivOOcbvGuU1pyghaWUI8/PtWPd3hdhOBBA4MdxYIDfdkpVDHcZGgYknbeO3AB4X2BtB9g1yBoh4BBgRCAAgFiEE8euDRSMV+TcusucDXYH/bo93JoYFAmq0cfYCGwwACgkQXYH/bo93JoY5pAD+OCSLJ8glnZhS1EWvH7XnP0g99gwsmCTTbQeQl8pqTDkA/Axm9uBgyXkkDbuuixbHOPX0KlWphb0D0hq8qMUAW6GOuQINBGq0cfcQCACERM6yXVO1xqRf8BkHVdWK/x1wqBAowoNG5wL3HG3cqGvcs1+dYqWOuRLmmFLKp6EAgYHZtc7nwCMZ7opZ7MmkCyl769rafu58zrxBO14GDDHcwsMdtxCW4p49Os0vtyeCmnYtTRIKhfgOnqwNqP8ic9Ae2O+fauGAP5nl7SweAjJxrwi8KJJOftwiHCupLUQxjO16BDWViEfgvoOfmiQHP8kyelJ9a7OwOI+d4PO07UfQ8q6c57p+dy/mbLni2WuLHlJLamOMpm+9UXsp5vcPs4rhmIs/HilpUYP427wko9C/DGVp/DFOe/TIL/GoHUVoX/n+aHwK3dUlwvDYYqazAAMGB/9a+eLmPZOOCtDe0vXso9Sx1KkGMAauvVkoHEkPKz6o5ttc1/tid8f0RwvlM/vWojQlqJOHyXVkBS9Rj+0oLokqj+dmwTlESj/3J3Cm+oZMkGAIU5Zm5TfaWp54k8oLYMaILqC0BFMHrZlLpJ6aIIaN7PIMMYlI5Y/+/SfdZQnwsS44HUM8KHyKawFDYO0AIY/fsPWZp3+rXlwvnQB0A+fA+ch+uNPgTANnBsFcG8D0dU1gu75uzokyZHQ6LgMseS8SOrVWIeIpVt1/u8rOxDrEkDGxmY3ZSEYR8Hmvueq+uRuDDEtVzbR/OolZJ0pmsYs2OSM/KayVs5duO7Vy2ZNqiHgEGBEIACAWIQTx64NFIxX5Ny6y5wNdgf9uj3cmhgUCarRx9wIbDAAKCRBdgf9uj3cmhsPsAP95frQ13q50UroCOMcWbkXhHgQCxVx57RzkYosJC0pZxwD/XEdPFAZPMwm4vW2vWT9GnvZgrepl9NEkFm1b9/H4Kuc=")!
    private let brainpoolRing = Data(base64Encoded: "mFMEarRx+BMJKyQDAwIIAQEHAgMEWoNu80/g7ZDXuOg7poqq925dz3PS8VVutWo4fYpt5GsK3BvlpecIXPXviFlynH2bf5g7aZxsWP0IuJRoDhx7brQbQnAgQ29udGFjdCA8YnBAZXhhbXBsZS5vcmc+iJMEExMIADsWIQQ26y65K3qM8o1gc88s2u7C31/hegUCarRx+AIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRAs2u7C31/hejhGAP0aKHaw1xVeht3LwWcLq7Oc2Tjr0SY0ou2/BPU9IlyfaAD7BAXXRDiEOzQqSH7DBqJoaQZILkOVwBgJ11g+psbI21C4VwRqtHH4EgkrJAMDAggBAQcCAwRZqrMwAsuWRLccitLMzHgo2AEzWu08vtqJoYzuTwy6aioL35HKsCFPmOMIq4uzQLMN3/I8koWe/3kKv2V+ahLAAwEIB4h4BBgTCAAgFiEENusuuSt6jPKNYHPPLNruwt9f4XoFAmq0cfgCGwwACgkQLNruwt9f4XrFYQEAp+SRZNFhpvyGW0HtowetYapPIeWQ/Ekgn1by1c87588A/2l6Cq6BoSdwZEylDhvUoqeEgAvZrU88Rx0/OIFexEnS")!

    override func tearDown() {
        CertificateValidator.pinnedSubkeys = { _ in [] }
        super.tearDown()
    }

    private func subkeyCount(_ data: Data) throws -> Int {
        try OpenPGPPacketParser.parsePackets(data: Array(data)).filter { $0.tag == 14 }.count
    }

    private func pin(_ ring: Data) {
        let found = CertificateValidator.uncheckableSubkeys(in: ring)
        let pinned = Set(found.subkeys)
        let primary = found.primary
        CertificateValidator.pinnedSubkeys = { $0 == primary ? pinned : [] }
    }

    func testUnpinnedUncheckableSubkeysAreNotEncryptionTargets() throws {
        for ring in [dsaRing, brainpoolRing] {
            XCTAssertEqual(CertificateValidator.uncheckableSubkeys(in: ring).subkeys.count, 1)
            XCTAssertEqual(try subkeyCount(try CertificateValidator.boundComponents(ring, purpose: .encrypt)), 0)
            XCTAssertEqual(try subkeyCount(try CertificateValidator.boundComponents(ring, purpose: .any)), 1)
        }
    }

    func testPinnedUncheckableSubkeysAreEncryptionTargets() throws {
        for ring in [dsaRing, brainpoolRing] {
            pin(ring)
            XCTAssertEqual(try CertificateValidator.boundComponents(ring, purpose: .encrypt), ring)
        }
    }

    func testAnAlteredBindingIsNotUsedAndNeverVerified() throws {
        pin(dsaRing)
        let targets = try CertificateValidator.boundComponents(dsaRingWithAlteredSecondBinding, purpose: .encrypt)
        XCTAssertEqual(try subkeyCount(targets), 1)
        let packets = try OpenPGPPacketParser.parsePackets(data: Array(dsaRingWithAlteredSecondBinding))
        let primary = try XCTUnwrap(packets.first { $0.tag == 6 })
        let last = try XCTUnwrap(packets.lastIndex { $0.tag == 14 })
        let signatures = packets[(last + 1)...].filter { $0.tag == 2 }.map(\.body)
        XCTAssertNil(CertificateValidator.newestVerifiedBinding(subkeyBody: packets[last].body, signatures: signatures,
                                                                primaryBody: primary.body))
    }

    func testAnUnreadableRingThrows() throws {
        let broken = dsaRing + Data([0xCE, 0x20, 0x04])
        XCTAssertThrowsError(try CertificateValidator.boundComponents(broken, purpose: .encrypt)) {
            XCTAssertTrue($0 is CertificateValidator.UnreadableKey)
        }
    }

    func testARingWithNoPublicPrimaryThrows() throws {
        // The subkey and its binding alone: nothing to check the binding
        // against, so the ring is unreadable rather than passed through.
        let packets = try OpenPGPPacketParser.parsePackets(data: Array(brainpoolRing))
        let start = try XCTUnwrap(packets.firstIndex { $0.tag == 14 })
        var bare: [UInt8] = []
        for p in packets[start...] { bare += OpenPGPPacketBuilder.buildNewFormatPacketBytes(tag: p.tag, body: p.body) }
        XCTAssertThrowsError(try CertificateValidator.boundComponents(Data(bare), purpose: .any)) {
            XCTAssertTrue($0 is CertificateValidator.UnreadableKey)
        }
        XCTAssertThrowsError(try LibrePGPEncryptService.findRecipient(publicKeyData: bare))
    }
}
