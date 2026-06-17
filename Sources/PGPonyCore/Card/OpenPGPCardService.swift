// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// OpenPGPCardService.swift
// PGPony
//
// v6.0 — Phase 8a: NFC transport + session for OpenPGP smart cards (hardware keys).
//
// This is the foundation the card features stand on. It owns the CoreNFC session,
// speaks ISO 7816 APDUs to the card, selects the OpenPGP applet, reads the card's
// application data (AID, serial, the three key fingerprints, PIN retry counter),
// and verifies a PIN. The cryptographic operations themselves — PSO:CDS (sign) and
// PSO:DECIPHER (cv25519 ECDH) — are Phase 8b and layer on top of `transmit`.
//
// SESSION SHAPE: "open once, verify once, run N operations, close." The connected
// tag is held for the lifetime of the session so multiple operations (e.g. a
// self-cert plus each subkey binding during a card expiration edit) run under a
// single tap and a single PIN verify. Do not collapse this into one-shot calls.
//
// HARDWARE: iPhone only, physical device only (the simulator has no NFC). Verified
// target is the Token2 R3.3 (Ed25519 sign, cv25519 decrypt). RSA signing keys are
// supported as of HW-R2 (PSO:CDS over a PKCS#1 v1.5 DigestInfo via `signRSA`); RSA
// decryption (PSO:DECIPHER) is not wired yet — that is HW-R3, which reuses the
// outbound command chaining added in HW-R1 (`transmitChained`). Cross-hardware
// (YubiKey 5.2+, Nitrokey) testing follows hardware arrival.
//
// PROJECT SETUP REQUIRED (see the deploy notes): the "Near Field Communication Tag
// Reading" capability, plus `NFCReaderUsageDescription` and the iso7816
// select-identifiers list (OpenPGP AID D2760001240103) in Info.plist. Without these
// the session fails immediately at `begin()`.

import Foundation
import CoreNFC

// MARK: - Public surface

/// What we read off the card on connect. Fingerprints are 40-char hex (uppercase),
/// or nil when that key slot is empty (all-zero fingerprint).
struct OpenPGPCardInfo {
    let aidHex: String
    let serialHex: String
    let signFingerprint: String?
    let decryptFingerprint: String?
    let authFingerprint: String?
    /// PW1 (user PIN) attempts remaining before the card locks that PIN.
    let pinRetriesRemaining: Int?
    // v6.0 — Phase 10b: richer read (display parity with Android). Plain `let`
    // (no default) so they're part of the synthesized memberwise initializer —
    // a `let` with a default value would be excluded from it.
    let manufacturerName: String?
    let signAlgorithm: String?
    let decryptAlgorithm: String?
    let authAlgorithm: String?
    let signGenTime: Date?
    let decryptGenTime: Date?
    let authGenTime: Date?
    /// PW3 (admin PIN) attempts remaining.
    let adminRetriesRemaining: Int?
    /// Raw OpenPGP-card algorithm-attribute ID for the signing slot (first byte
    /// of the C1 DO): 0x01 = RSA, 0x16 = EdDSA, 0x13 = ECDSA, etc. nil if the
    /// card didn't report a signing attribute. Used to choose the signature
    /// packet shape; the display string above is for the UI.
    let signAlgoID: UInt8?

    // B3 — extended status (all optional; nil when the card doesn't report them).
    /// PW1 is "forced": valid for a single PSO:CDS, re-verified per signature
    /// (PW status byte 0 == 0x00). false = cached for multiple signatures.
    let signaturePINForced: Bool?
    /// Maximum lengths the card accepts for PW1 / reset code / PW3.
    let maxUserPINLength: Int?
    let maxResetCodeLength: Int?
    let maxAdminPINLength: Int?
    /// Reset code (PW2) attempts remaining.
    let resetCodeRetriesRemaining: Int?
    /// User-interaction (touch) policy per slot: "Off" / "On" / "On (fixed)".
    let touchPolicySign: String?
    let touchPolicyDecrypt: String?
    let touchPolicyAuth: String?
    /// Digital-signature counter (number of signatures the card has made).
    let signatureCounter: Int?

    /// The on-card signing algorithm mapped to the packet shape CardSigner can
    /// build, or nil if absent/unsupported.
    var signatureAlgorithm: CardSignatureAlgorithm? {
        guard let signAlgoID else { return nil }
        return CardSignatureAlgorithm(cardAlgoID: signAlgoID)
    }
}

enum OpenPGPCardPIN {
    case signing          // PW1 in mode 0x81 — gates PSO:CDS
    case confidentiality  // PW1 in mode 0x82 — gates PSO:DECIPHER
    case admin            // PW3 in mode 0x83

    var p2: UInt8 {
        switch self {
        case .signing:         return 0x81
        case .confidentiality: return 0x82
        case .admin:           return 0x83
        }
    }
}

/// The signature-packet shape CardSigner builds for an on-card signing key,
/// selected from the card's signature algorithm attribute (the first byte of the
/// C1 DO). EdDSA is two MPIs (R, S) over a bare digest; RSA is a single MPI over
/// a PKCS#1 v1.5 DigestInfo.
enum CardSignatureAlgorithm: Equatable {
    case eddsa   // algo 22 (Ed25519) — bare digest in, 64-byte R||S out
    case rsa     // algo 1 (RSA) — DigestInfo in, modulus-length value out

    /// OpenPGP public-key algorithm ID used in the v4 signature packet trailer.
    var packetAlgorithmID: UInt8 {
        switch self {
        case .eddsa: return 22
        case .rsa:   return 1
        }
    }

    /// Map a raw OpenPGP-card algorithm-attribute ID (first byte of the C1
    /// signature DO) to the packet shape. Returns nil for algorithms PGPony's
    /// card signer doesn't build yet (e.g. ECDSA).
    init?(cardAlgoID: UInt8) {
        switch cardAlgoID {
        case 0x16: self = .eddsa   // 22
        case 0x01: self = .rsa     // 1
        default:   return nil
        }
    }
}

enum OpenPGPCardError: LocalizedError {
    case nfcUnavailable
    case notISO7816
    case appletNotFound
    case unexpectedStatus(UInt8, UInt8)
    case pinBlocked
    case wrongPIN(retriesRemaining: Int?)
    case malformedResponse
    case sessionClosed
    case underlying(Error)
    /// B1e — the NFC link dropped mid-operation (tag moved, or session timed out).
    case connectionLost
    /// B1e — a PIN change returned success but the new PIN failed to verify, so it
    /// likely didn't commit to the card.
    case changeNotCommitted

    var errorDescription: String? {
        switch self {
        case .nfcUnavailable:
            return "This device can't read NFC hardware keys, or NFC is unavailable right now."
        case .notISO7816:
            return "That tag isn't an OpenPGP smart card."
        case .appletNotFound:
            return "No OpenPGP application was found on the card."
        case .unexpectedStatus(let sw1, let sw2):
            return String(format: "The card returned an unexpected status (0x%02X%02X).", sw1, sw2)
        case .pinBlocked:
            return "This PIN is blocked. Unblock it with your admin PIN (PW3) before continuing."
        case .wrongPIN(let n):
            if let n { return "Incorrect PIN. \(n) attempt\(n == 1 ? "" : "s") remaining." }
            return "Incorrect PIN."
        case .malformedResponse:
            return "The card's response could not be understood."
        case .sessionClosed:
            return "The card session is no longer active. Tap your key again."
        case .connectionLost:
            return "The card connection dropped before the operation finished. Hold your key steady against the top of your iPhone and tap to try again."
        case .changeNotCommitted:
            return "The card reported the PIN change but the new PIN didn't verify — it may not have saved. Hold the key steady and try again."
        case .underlying(let e):
            return e.localizedDescription
        }
    }
}

// MARK: - Service

final class OpenPGPCardService: NSObject {

    /// OpenPGP applet AID prefix (RID D27600 + application 0124 + 01). The card's
    /// full AID adds version + manufacturer + serial; SELECT by this prefix.
    static let openPGPAID: [UInt8] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]

    private var session: NFCTagReaderSession?
    private var tag: NFCISO7816Tag?
    private var connectContinuation: CheckedContinuation<NFCISO7816Tag, Error>?

    var isAvailable: Bool { NFCTagReaderSession.readingAvailable }

    // MARK: Lifecycle

    /// Open an NFC session, wait for the user to present a card, connect, and SELECT
    /// the OpenPGP applet. The returned service keeps the tag live until `end(...)`.
    func connect(alertMessage: String = "Hold your hardware key near the top of your iPhone.") async throws -> OpenPGPCardService {
        guard NFCTagReaderSession.readingAvailable else { throw OpenPGPCardError.nfcUnavailable }

        let connectedTag: NFCISO7816Tag = try await withCheckedThrowingContinuation { cont in
            self.connectContinuation = cont
            guard let s = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: nil) else {
                self.connectContinuation = nil
                cont.resume(throwing: OpenPGPCardError.nfcUnavailable)
                return
            }
            s.alertMessage = alertMessage
            self.session = s
            s.begin()
        }

        self.tag = connectedTag
        try await selectOpenPGPApplet()
        return self
    }

    /// Update the on-screen NFC prompt mid-session (e.g. "Signing…").
    func updateAlert(_ message: String) {
        session?.alertMessage = message
    }

    /// Close the session. On success the system shows a checkmark; on failure the
    /// red error UI with `message`.
    func end(success: Bool, message: String? = nil) {
        if success {
            if let message { session?.alertMessage = message }
            session?.invalidate()
        } else {
            session?.invalidate(errorMessage: message ?? "Couldn't read the card.")
        }
        session = nil
        tag = nil
    }

    // MARK: Applet operations

    private func selectOpenPGPApplet() async throws {
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00, instructionCode: 0xA4,
            p1Parameter: 0x04, p2Parameter: 0x00,
            data: Data(Self.openPGPAID), expectedResponseLength: 256
        )
        let (_, sw1, sw2) = try await transmit(apdu)
        guard sw1 == 0x90, sw2 == 0x00 else { throw OpenPGPCardError.appletNotFound }
    }

    /// Read application-related data (DO 0x6E) and parse the fields we surface.
    func readCardInfo() async throws -> OpenPGPCardInfo {
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00, instructionCode: 0xCA,
            p1Parameter: 0x00, p2Parameter: 0x6E,
            data: Data(), expectedResponseLength: 256
        )
        let (data, sw1, sw2) = try await transmit(apdu)
        guard sw1 == 0x90, sw2 == 0x00 else { throw OpenPGPCardError.unexpectedStatus(sw1, sw2) }

        let aid = BERTLV.find(0x4F, in: data) ?? []
        let fprs = BERTLV.find(0x00C5, in: data) ?? []          // 60 bytes: sign|decrypt|auth
        let pwStatus = BERTLV.find(0x00C4, in: data) ?? []      // 7 bytes
        // v6.0 — Phase 10b: algorithm attributes (C1/C2/C3) + generation times (CD).
        let algoSig = BERTLV.find(0x00C1, in: data)
        let algoDec = BERTLV.find(0x00C2, in: data)
        let algoAuth = BERTLV.find(0x00C3, in: data)
        let genTimes = BERTLV.find(0x00CD, in: data) ?? []      // 3 × 4-byte BE unix seconds

        func fpr(_ range: Range<Int>) -> String? {
            guard fprs.count >= range.upperBound else { return nil }
            let slice = Array(fprs[range])
            guard slice.contains(where: { $0 != 0 }) else { return nil }  // all-zero = empty slot
            return hex(slice)
        }

        func algoDisplay(_ raw: [UInt8]?) -> String? {
            guard let raw, !raw.isEmpty else { return nil }
            return CardAlgorithmAttributes.parse(raw)?.displayName
        }

        func genTime(_ index: Int) -> Date? {
            let start = index * 4
            guard genTimes.count >= start + 4 else { return nil }
            var secs: UInt32 = 0
            for i in 0..<4 { secs = (secs << 8) | UInt32(genTimes[start + i]) }
            guard secs != 0 else { return nil }
            return Date(timeIntervalSince1970: TimeInterval(secs))
        }

        // AID layout: RID(5) app(1) version(2) manufacturer(2) serial(4) rfu(2).
        let serial = aid.count >= 14 ? Array(aid[10..<14]) : []
        let manufacturer: String? = aid.count >= 10
            ? Self.manufacturerName((Int(aid[8]) << 8) | Int(aid[9]))
            : nil

        // B3 — user-interaction (touch) policy DOs (D6/D7/D8); first byte is the mode.
        func uif(_ tag: UInt16) -> String? {
            guard let d = BERTLV.find(tag, in: data), let b = d.first else { return nil }
            switch b {
            case 0x00: return "Off"
            case 0x01: return "On"
            case 0x02: return "On (fixed)"
            default:   return nil
            }
        }

        // B3 — digital-signature counter lives in the Security Support Template
        // (DO 0x7A → 0x93, 3-byte big-endian). Best-effort: a card that doesn't
        // return it just leaves the counter nil.
        var sigCounter: Int? = nil
        let secApdu = NFCISO7816APDU(
            instructionClass: 0x00, instructionCode: 0xCA,
            p1Parameter: 0x00, p2Parameter: 0x7A,
            data: Data(), expectedResponseLength: 256
        )
        if let (secData, s1, s2) = try? await transmit(secApdu), s1 == 0x90, s2 == 0x00,
           let counter = BERTLV.find(0x0093, in: secData), counter.count == 3 {
            sigCounter = (Int(counter[0]) << 16) | (Int(counter[1]) << 8) | Int(counter[2])
        }

        return OpenPGPCardInfo(
            aidHex: hex(aid),
            serialHex: hex(serial),
            signFingerprint: fpr(0..<20),
            decryptFingerprint: fpr(20..<40),
            authFingerprint: fpr(40..<60),
            pinRetriesRemaining: pwStatus.count >= 5 ? Int(pwStatus[4]) : nil,
            manufacturerName: manufacturer,
            signAlgorithm: algoDisplay(algoSig),
            decryptAlgorithm: algoDisplay(algoDec),
            authAlgorithm: algoDisplay(algoAuth),
            signGenTime: genTime(0),
            decryptGenTime: genTime(1),
            authGenTime: genTime(2),
            adminRetriesRemaining: pwStatus.count >= 7 ? Int(pwStatus[6]) : nil,
            signAlgoID: algoSig?.first,
            signaturePINForced: pwStatus.count >= 1 ? (pwStatus[0] == 0x00) : nil,
            maxUserPINLength: pwStatus.count >= 2 ? Int(pwStatus[1]) : nil,
            maxResetCodeLength: pwStatus.count >= 3 ? Int(pwStatus[2]) : nil,
            maxAdminPINLength: pwStatus.count >= 4 ? Int(pwStatus[3]) : nil,
            resetCodeRetriesRemaining: pwStatus.count >= 6 ? Int(pwStatus[5]) : nil,
            touchPolicySign: uif(0x00D6),
            touchPolicyDecrypt: uif(0x00D7),
            touchPolicyAuth: uif(0x00D8),
            signatureCounter: sigCounter
        )
    }

    /// VERIFY a PIN for the given mode. Throws `wrongPIN`/`pinBlocked` on failure so
    /// the caller can prompt again with the remaining-attempts count.
    func verify(pin: String, mode: OpenPGPCardPIN) async throws {
        let pinBytes = Array(pin.utf8)
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00, instructionCode: 0x20,
            p1Parameter: 0x00, p2Parameter: mode.p2,
            data: Data(pinBytes), expectedResponseLength: -1
        )
        let (_, sw1, sw2) = try await transmit(apdu)
        if sw1 == 0x90, sw2 == 0x00 { return }
        // 0x63 0xCx = verification failed, x attempts left. 0x69 0x83 = blocked.
        if sw1 == 0x63, (sw2 & 0xF0) == 0xC0 {
            throw OpenPGPCardError.wrongPIN(retriesRemaining: Int(sw2 & 0x0F))
        }
        if sw1 == 0x69, sw2 == 0x83 { throw OpenPGPCardError.pinBlocked }
        // Some cards (incl. YubiKey) report a failed PIN check as 0x6982 "security
        // status not satisfied" rather than 0x63Cx — no attempt count is provided.
        if sw1 == 0x69, sw2 == 0x82 { throw OpenPGPCardError.wrongPIN(retriesRemaining: nil) }
        throw OpenPGPCardError.unexpectedStatus(sw1, sw2)
    }

    // MARK: Change Reference Data (Phase 10a — PW1 PIN change)

    /// CHANGE REFERENCE DATA (INS 0x24). The card splits the concatenated
    /// oldPIN‖newPIN using its stored length of the *current* PIN, so the caller
    /// just supplies both as UTF-8. `pinReference` is 0x81 for PW1 (user) or 0x83
    /// for PW3 (admin). Assumes the applet is already selected (connect() does
    /// that). Throws `wrongPIN`/`pinBlocked` so the UI can show remaining attempts.
    func changeReferenceData(pinReference: UInt8, oldPIN: String, newPIN: String) async throws {
        let payload = Array(oldPIN.utf8) + Array(newPIN.utf8)
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00, instructionCode: 0x24,
            p1Parameter: 0x00, p2Parameter: pinReference,
            data: Data(payload), expectedResponseLength: -1
        )
        let (_, sw1, sw2) = try await transmit(apdu)
        if sw1 == 0x90, sw2 == 0x00 { return }
        // 0x63 0xCx = current PIN wrong, x attempts left. 0x69 0x83 = blocked.
        if sw1 == 0x63, (sw2 & 0xF0) == 0xC0 {
            throw OpenPGPCardError.wrongPIN(retriesRemaining: Int(sw2 & 0x0F))
        }
        if sw1 == 0x69, sw2 == 0x83 { throw OpenPGPCardError.pinBlocked }
        // Some cards (incl. YubiKey) report a failed PIN check as 0x6982 "security
        // status not satisfied" rather than 0x63Cx — no attempt count is provided.
        if sw1 == 0x69, sw2 == 0x82 { throw OpenPGPCardError.wrongPIN(retriesRemaining: nil) }
        throw OpenPGPCardError.unexpectedStatus(sw1, sw2)
    }

    /// Change the user PIN (PW1). PW1-only, matching the Android scope (no admin
    /// PIN, no reset/unblock). The applet must already be selected by connect().
    func changeUserPin(oldPIN: String, newPIN: String) async throws {
        try await changeReferenceData(pinReference: 0x81, oldPIN: oldPIN, newPIN: newPIN)
        try await confirmPINChanged(newPIN: newPIN, mode: .signing)
    }

    /// Change the admin PIN (PW3). Applet must already be selected by connect().
    func changeAdminPin(oldPIN: String, newPIN: String) async throws {
        try await changeReferenceData(pinReference: 0x83, oldPIN: oldPIN, newPIN: newPIN)
        try await confirmPINChanged(newPIN: newPIN, mode: .admin)
    }

    /// B1e — after a CHANGE REFERENCE DATA that returned success, verify the new PIN
    /// in the same session. A real commit verifies cleanly (and resets the retry
    /// counter); if the change silently failed to stick (e.g. an NFC glitch), the
    /// new PIN won't verify and we surface `.changeNotCommitted` instead of a false
    /// success. A genuine connection drop here propagates as `.connectionLost`.
    private func confirmPINChanged(newPIN: String, mode: OpenPGPCardPIN) async throws {
        do {
            try await verify(pin: newPIN, mode: mode)
        } catch let error as OpenPGPCardError {
            switch error {
            case .wrongPIN, .pinBlocked:
                // New PIN didn't take — the change didn't actually commit.
                throw OpenPGPCardError.changeNotCommitted
            default:
                // Connection drop or anything else: surface it as-is.
                throw error
            }
        }
    }

    /// Unblock the user PIN (PW1) with the admin PIN (PW3): RESET RETRY COUNTER
    /// (INS 0x2C), P1=0x02 (authorise via a verified PW3), P2=0x81 (target PW1).
    /// Verifies PW3 first, then installs `newPIN` as PW1 and resets its retry
    /// counter. Use this when PW1 is blocked (0 attempts remaining).
    func unblockUserPin(adminPIN: String, newPIN: String) async throws {
        try await verify(pin: adminPIN, mode: .admin)
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00, instructionCode: 0x2C,
            p1Parameter: 0x02, p2Parameter: 0x81,
            data: Data(Array(newPIN.utf8)), expectedResponseLength: -1
        )
        let (_, sw1, sw2) = try await transmit(apdu)
        if sw1 == 0x90, sw2 == 0x00 { return }
        if sw1 == 0x69, sw2 == 0x83 { throw OpenPGPCardError.pinBlocked }   // PW3 blocked
        throw OpenPGPCardError.unexpectedStatus(sw1, sw2)
    }

    /// Factory-reset the OpenPGP applet: TERMINATE DF (INS 0xE6) then ACTIVATE FILE
    /// (INS 0x44). WIPES all keys and resets every PIN to the card's factory
    /// defaults. On YubiKey / Token2 / Gnuk this is permitted without first blocking
    /// the PINs; a card that returns 0x6985 here requires PW1 and PW3 to be blocked
    /// first (by design). DESTRUCTIVE and irreversible.
    func factoryReset(adminPIN: String) async throws {
        // TERMINATE DF requires PW3 verification (cards return 0x6982 otherwise).
        // If PW3 is already blocked, the applet permits TERMINATE without auth
        // (both-PINs-blocked recovery), so a `pinBlocked` here is not fatal — fall
        // through and let TERMINATE decide. A wrong (not blocked) PIN propagates.
        do {
            try await verify(pin: adminPIN, mode: .admin)
        } catch OpenPGPCardError.pinBlocked {
            // proceed: card may allow reset when PINs are blocked
        }

        let terminate = NFCISO7816APDU(
            instructionClass: 0x00, instructionCode: 0xE6,
            p1Parameter: 0x00, p2Parameter: 0x00,
            data: Data(), expectedResponseLength: -1
        )
        let (_, t1, t2) = try await transmit(terminate)
        guard t1 == 0x90, t2 == 0x00 else { throw OpenPGPCardError.unexpectedStatus(t1, t2) }

        let activate = NFCISO7816APDU(
            instructionClass: 0x00, instructionCode: 0x44,
            p1Parameter: 0x00, p2Parameter: 0x00,
            data: Data(), expectedResponseLength: -1
        )
        let (_, a1, a2) = try await transmit(activate)
        guard a1 == 0x90, a2 == 0x00 else { throw OpenPGPCardError.unexpectedStatus(a1, a2) }
    }

    /// PSO:COMPUTE DIGITAL SIGNATURE. Assumes PW1 (mode `.signing`) is already
    /// verified in this session. Sends the 32-byte digest, returns the 64-byte
    /// Ed25519 signature (R || S).
    func sign(digest: [UInt8]) async throws -> [UInt8] {
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00, instructionCode: 0x2A,
            p1Parameter: 0x9E, p2Parameter: 0x9A,
            data: Data(digest), expectedResponseLength: 256
        )
        let (data, sw1, sw2) = try await transmit(apdu)
        guard sw1 == 0x90, sw2 == 0x00 else { throw OpenPGPCardError.unexpectedStatus(sw1, sw2) }
        return data
    }

    /// PSO:COMPUTE DIGITAL SIGNATURE for an RSA signing key. `digestInfo` is the
    /// PKCS#1 v1.5 DigestInfo (the ASN.1-wrapped hash OID + digest); the card
    /// applies EMSA-PKCS1-v1_5 padding and the private-key transform, returning
    /// the modulus-length signature value (256/384/512 bytes for RSA-2048/3072/
    /// 4096). PW1 (mode `.signing`) must already be verified. The DigestInfo for
    /// SHA-256 is ~51 bytes, so the input fits one short APDU; `transmitChained`
    /// is used for symmetry and to stay correct if a longer hash is ever passed.
    ///
    /// The response is requested with an extended-length Le (512). An RSA-4096
    /// signature is 512 bytes — too large for a single short-APDU response — and
    /// the Yubico/Token2 OpenPGP applets expect extended length for it (the same
    /// thing scdaemon uses). Requesting more than the modulus length is fine: the
    /// card returns exactly its signature bytes with 0x9000.
    func signRSA(digestInfo: [UInt8]) async throws -> [UInt8] {
        let (data, sw1, sw2) = try await transmitChained(
            instructionCode: 0x2A, p1Parameter: 0x9E, p2Parameter: 0x9A,
            data: digestInfo, expectedResponseLength: 512
        )
        guard sw1 == 0x90, sw2 == 0x00 else { throw OpenPGPCardError.unexpectedStatus(sw1, sw2) }
        return data
    }

    /// PSO:DECIPHER for a Curve25519 (cv25519) ECDH key. Assumes PW1 (mode
    /// `.confidentiality`) is already verified. `ephemeralPoint` is the sender's
    /// ephemeral public point; a leading 0x40 native-format prefix is stripped so
    /// the card receives the bare 32-byte point (Token2 returns 0x6700 otherwise).
    /// Returns the ECDH shared secret; the RFC 6637 KDF + key unwrap run host-side.
    func decipher(ephemeralPoint: [UInt8]) async throws -> [UInt8] {
        var point = ephemeralPoint
        if point.count == 33, point.first == 0x40 { point.removeFirst() }

        // Cipher DO for ECDH: A6 { 7F49 { 86 <point> } }
        let do86: [UInt8] = [0x86] + berLength(point.count) + point
        let do7F49: [UInt8] = [0x7F, 0x49] + berLength(do86.count) + do86
        let doA6: [UInt8] = [0xA6] + berLength(do7F49.count) + do7F49

        let apdu = NFCISO7816APDU(
            instructionClass: 0x00, instructionCode: 0x2A,
            p1Parameter: 0x80, p2Parameter: 0x86,
            data: Data(doA6), expectedResponseLength: 256
        )
        let (data, sw1, sw2) = try await transmit(apdu)
        guard sw1 == 0x90, sw2 == 0x00 else { throw OpenPGPCardError.unexpectedStatus(sw1, sw2) }
        return data
    }

    /// PSO:DECIPHER for an RSA encryption key. Assumes PW1 (mode
    /// `.confidentiality`) is already verified. `cryptogram` is the RSA cipher
    /// value from the PKESK (m^e mod n, modulus length: 256/384/512 bytes for
    /// RSA-2048/3072/4096). The OpenPGP card command data for RSA is a 0x00
    /// padding-indicator byte followed by the cryptogram, so an RSA-4096 input is
    /// 513 bytes — past the 255-byte short-APDU limit — and is sent with HW-R1
    /// command chaining via `transmitChained`. The card performs the private-key
    /// transform AND removes the PKCS#1 v1.5 padding, returning the original
    /// session-key block: cipher-algorithm(1) || session key || 2-byte checksum.
    /// No host-side KDF or key unwrap is needed (unlike the ECDH path).
    func decipherRSA(cryptogram: [UInt8], modulusLength: Int) async throws -> [UInt8] {
        let input = Self.rsaDecipherCommandData(cryptogram: cryptogram, modulusLength: modulusLength)
        let (data, sw1, sw2) = try await transmitChained(
            instructionCode: 0x2A, p1Parameter: 0x80, p2Parameter: 0x86,
            data: input, expectedResponseLength: 256
        )
        guard sw1 == 0x90, sw2 == 0x00 else { throw OpenPGPCardError.unexpectedStatus(sw1, sw2) }
        return data
    }

    /// Build the PSO:DECIPHER command data for an RSA key: a 0x00 padding-indicator
    /// byte followed by the cryptogram, left-padded with zeros to the modulus
    /// length. The PKESK stores the cryptogram as an MPI with leading zero bytes
    /// stripped, but the card requires the full modulus-length value (e.g. 512
    /// bytes for RSA-4096), so a cryptogram whose high byte is zero must be padded
    /// back out or the card rejects the length. Pure, so it can be unit-tested.
    static func rsaDecipherCommandData(cryptogram: [UInt8], modulusLength: Int) -> [UInt8] {
        var c = cryptogram
        if c.count < modulusLength {
            c = [UInt8](repeating: 0x00, count: modulusLength - c.count) + c
        }
        return [0x00] + c
    }

    /// Read the card's decryption (encryption subkey) public point via GENERATE
    /// ASYMMETRIC KEY PAIR in read mode (P1 0x81, CRT 0xB8 = confidentiality/
    /// decryption key). Strips a leading 0x40. Used by the ECDH self-test and,
    /// later, card-key import.
    func readEncryptionPublicKey() async throws -> [UInt8] {
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00, instructionCode: 0x47,
            p1Parameter: 0x81, p2Parameter: 0x00,
            data: Data([0xB8, 0x00]), expectedResponseLength: 256
        )
        let (data, sw1, sw2) = try await transmit(apdu)
        guard sw1 == 0x90, sw2 == 0x00 else { throw OpenPGPCardError.unexpectedStatus(sw1, sw2) }
        guard var point = BERTLV.find(0x86, in: data) else { throw OpenPGPCardError.malformedResponse }
        if point.count == 33, point.first == 0x40 { point.removeFirst() }
        return point
    }

    /// Read the card's RSA decryption (encryption subkey) public key via GENERATE
    /// ASYMMETRIC KEY PAIR in read mode (P1 0x81, CRT 0xB8). The response is a 7F49
    /// template with 81 = modulus and 82 = public exponent. The RSA-4096 modulus is
    /// 512 bytes, so the response (~520 bytes) needs an extended-length Le;
    /// `transmit` also follows any 0x61xx response chaining. No PIN required.
    func readEncryptionRSAPublicKey() async throws -> (modulus: [UInt8], exponent: [UInt8]) {
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00, instructionCode: 0x47,
            p1Parameter: 0x81, p2Parameter: 0x00,
            data: Data([0xB8, 0x00]), expectedResponseLength: 1024
        )
        let (data, sw1, sw2) = try await transmit(apdu)
        guard sw1 == 0x90, sw2 == 0x00 else { throw OpenPGPCardError.unexpectedStatus(sw1, sw2) }
        guard let modulus = BERTLV.find(0x81, in: data),
              let exponent = BERTLV.find(0x82, in: data) else {
            throw OpenPGPCardError.malformedResponse
        }
        return (modulus, exponent)
    }

    // MARK: - B1: On-card key generation (engine layer)
    //
    // Raw card operations for generating a key pair ON the card. The caller MUST
    // verify the ADMIN PIN (PW3, `.admin`) first — GENERATE, setting algorithm
    // attributes, and writing fingerprints are all admin-protected.
    //
    // GENERATE is DESTRUCTIVE: it overwrites whatever key occupies the target slot.
    // Building the OpenPGP public-key packet, computing the v4 fingerprint, writing
    // it back, and linking the result into the keyring live one layer up (B1b); the
    // UI and the no-backup warning are B1c.

    /// The three OpenPGP card key slots. `crt` is the Control Reference Template used
    /// by GENERATE (0x47); the tags are the PUT DATA data objects for that slot.
    enum CardKeySlot {
        case signature
        case decryption
        case authentication

        /// CRT tag for GENERATE ASYMMETRIC KEY PAIR (0x47): B6 sign / B8 dec / A4 auth.
        var crt: UInt8 {
            switch self {
            case .signature:      return 0xB6
            case .decryption:     return 0xB8
            case .authentication: return 0xA4
            }
        }
        /// Algorithm-attributes DO: C1 sign / C2 decrypt / C3 auth.
        var algorithmAttributesTag: UInt16 {
            switch self {
            case .signature:      return 0x00C1
            case .decryption:     return 0x00C2
            case .authentication: return 0x00C3
            }
        }
        /// Fingerprint DO: C7 sign / C8 decrypt / C9 auth.
        var fingerprintTag: UInt16 {
            switch self {
            case .signature:      return 0x00C7
            case .decryption:     return 0x00C8
            case .authentication: return 0x00C9
            }
        }
    }

    /// Public-key material parsed from the 7F49 template returned by GENERATE. EC
    /// keys carry the raw point (leading 0x40 prefix stripped); RSA keys carry
    /// modulus + exponent.
    enum CardPublicKeyMaterial {
        case ec(point: [UInt8])
        case rsa(modulus: [UInt8], exponent: [UInt8])
    }

    /// PUT DATA (00 DA P1 P2) — write a simple data object. `tag` is the 2-byte DO
    /// tag (e.g. 0x00C7). The objects written here are admin-protected, so PW3 must
    /// already be verified. Assumes the applet is selected.
    func putData(tag: UInt16, _ value: [UInt8]) async throws {
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00, instructionCode: 0xDA,
            p1Parameter: UInt8((tag >> 8) & 0xFF), p2Parameter: UInt8(tag & 0xFF),
            data: Data(value), expectedResponseLength: -1
        )
        let (_, sw1, sw2) = try await transmit(apdu)
        guard sw1 == 0x90, sw2 == 0x00 else {
            // 0x69 0x82 = security status not satisfied (admin PIN not verified).
            if sw1 == 0x69, sw2 == 0x82 { throw OpenPGPCardError.pinBlocked }
            throw OpenPGPCardError.unexpectedStatus(sw1, sw2)
        }
    }

    /// GENERATE ASYMMETRIC KEY PAIR in *generate* mode (P1 0x80) for `slot`. The card
    /// creates a fresh key pair and returns its public key (7F49 template). The
    /// secret key never leaves the card. DESTRUCTIVE — overwrites the slot. Requires
    /// PW3 (admin) verified first.
    func generateKeyPair(slot: CardKeySlot) async throws -> CardPublicKeyMaterial {
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00, instructionCode: 0x47,
            p1Parameter: 0x80, p2Parameter: 0x00,
            data: Data([slot.crt, 0x00]), expectedResponseLength: 1024
        )
        let (data, sw1, sw2) = try await transmit(apdu)
        guard sw1 == 0x90, sw2 == 0x00 else { throw OpenPGPCardError.unexpectedStatus(sw1, sw2) }

        // EC keys: 0x86 carries the public point. RSA keys: 0x81 modulus + 0x82 exp.
        if var point = BERTLV.find(0x86, in: data) {
            if point.count == 33, point.first == 0x40 { point.removeFirst() }
            return .ec(point: point)
        }
        if let modulus = BERTLV.find(0x81, in: data),
           let exponent = BERTLV.find(0x82, in: data) {
            return .rsa(modulus: modulus, exponent: exponent)
        }
        throw OpenPGPCardError.malformedResponse
    }

    /// Set the algorithm attributes for `slot` (PUT DATA C1/C2/C3) before generating,
    /// when the target algorithm differs from the card default. Requires PW3.
    func setAlgorithmAttributes(slot: CardKeySlot, _ attributes: [UInt8]) async throws {
        try await putData(tag: slot.algorithmAttributesTag, attributes)
    }

    /// Write the 20-byte v4 fingerprint of a generated key into the slot's
    /// fingerprint DO (PUT DATA C7/C8/C9). Requires PW3. The fingerprint is computed
    /// one layer up from the public key + the chosen creation timestamp.
    func writeKeyFingerprint(slot: CardKeySlot, _ fingerprint: [UInt8]) async throws {
        try await putData(tag: slot.fingerprintTag, fingerprint)
    }

    private func berLength(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        if n < 0x100 { return [0x81, UInt8(n)] }
        return [0x82, UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)]
    }

    // MARK: Command chaining (HW-R1)

    /// One outbound block of a chained command. Intermediate blocks carry CLA
    /// 0x10 ("more blocks follow"); the final block carries CLA 0x00 so the card
    /// executes the assembled command.
    struct CommandChainBlock: Equatable {
        let cla: UInt8
        let data: [UInt8]
        let isLast: Bool
    }

    /// Split a command data field into ISO 7816-4 command-chaining blocks.
    ///
    /// Short APDUs cap the data field at 255 bytes, so any command whose data
    /// exceeds that must be sent as a chain. The motivating case is RSA-4096
    /// PSO:DECIPHER, whose input is 513 bytes (a 0x00 padding-indicator byte plus
    /// a 512-byte ciphertext block). Every block but the last sets CLA bit 0x10;
    /// the last clears it. Empty input yields a single empty final block (a plain
    /// Case 1/2 command). This function is pure so the chunking can be unit-tested
    /// without NFC hardware. `maxBlock` is the per-block data cap and must be
    /// 1...255 for short APDUs.
    static func commandChainBlocks(data: [UInt8], maxBlock: Int = 255) -> [CommandChainBlock] {
        precondition(maxBlock >= 1 && maxBlock <= 255, "short-APDU block size must be 1...255")
        if data.isEmpty {
            return [CommandChainBlock(cla: 0x00, data: [], isLast: true)]
        }
        var blocks: [CommandChainBlock] = []
        var offset = 0
        while offset < data.count {
            let end = Swift.min(offset + maxBlock, data.count)
            let isLast = (end == data.count)
            blocks.append(CommandChainBlock(
                cla: isLast ? 0x00 : 0x10,
                data: Array(data[offset..<end]),
                isLast: isLast
            ))
            offset = end
        }
        return blocks
    }

    // MARK: APDU transport

    /// Map an SW2 length byte from a 0x61xx ("more data available") or 0x6Cxx
    /// ("wrong Le") status word to a CoreNFC expected-response length. Per ISO
    /// 7816-4 an SW2 of 0x00 in these status words means 256, not 0 — requesting
    /// zero bytes yields an empty/failed GET RESPONSE. This path is first
    /// exercised by RSA signing (a 512-byte RSA-4096 result spans more than one
    /// short-APDU response); the EdDSA and cv25519 paths always fit in one.
    static func leFromSW2(_ sw2: UInt8) -> Int {
        sw2 == 0x00 ? 256 : Int(sw2)
    }

    /// Send one APDU, transparently following 0x61xx (GET RESPONSE) and 0x6Cxx
    /// (wrong Le) so the caller always gets the full response body plus final SW.
    @discardableResult
    func transmit(_ apdu: NFCISO7816APDU) async throws -> (data: [UInt8], sw1: UInt8, sw2: UInt8) {
        guard let tag else { throw OpenPGPCardError.sessionClosed }

        var (response, sw1, sw2) = try await sendOnce(apdu, tag: tag)
        var accumulated = response

        // 0x6Cxx: card wants a specific Le; resend the same command with Le = sw2.
        if sw1 == 0x6C {
            let retry = NFCISO7816APDU(
                instructionClass: apduCLA(apdu), instructionCode: apdu.instructionCode,
                p1Parameter: apdu.p1Parameter, p2Parameter: apdu.p2Parameter,
                data: apdu.data ?? Data(), expectedResponseLength: Self.leFromSW2(sw2)
            )
            (response, sw1, sw2) = try await sendOnce(retry, tag: tag)
            accumulated = response
        }

        // 0x61xx: more data available; pull it with GET RESPONSE until 0x9000.
        while sw1 == 0x61 {
            let getResponse = NFCISO7816APDU(
                instructionClass: 0x00, instructionCode: 0xC0,
                p1Parameter: 0x00, p2Parameter: 0x00,
                data: Data(), expectedResponseLength: Self.leFromSW2(sw2)
            )
            let (more, s1, s2) = try await sendOnce(getResponse, tag: tag)
            accumulated += more
            sw1 = s1; sw2 = s2
        }

        return (accumulated, sw1, sw2)
    }

    /// Send a command whose data field may exceed the 255-byte short-APDU limit,
    /// using ISO 7816-4 command chaining. Intermediate blocks (CLA 0x10) are sent
    /// in order and must each acknowledge with 0x9000; the final block (CLA 0x00)
    /// carries `expectedResponseLength` and is routed through `transmit`, so the
    /// caller still gets transparent 0x61xx/0x6Cxx handling on the result.
    ///
    /// When the data fits in a single block this is equivalent to building one
    /// APDU and calling `transmit` directly.
    @discardableResult
    func transmitChained(
        instructionCode ins: UInt8,
        p1Parameter p1: UInt8,
        p2Parameter p2: UInt8,
        data: [UInt8],
        expectedResponseLength: Int
    ) async throws -> (data: [UInt8], sw1: UInt8, sw2: UInt8) {
        guard let tag else { throw OpenPGPCardError.sessionClosed }

        let blocks = Self.commandChainBlocks(data: data)

        // Intermediate blocks: CLA 0x10, Le absent, each must ack 0x9000.
        for block in blocks where !block.isLast {
            let apdu = NFCISO7816APDU(
                instructionClass: block.cla, instructionCode: ins,
                p1Parameter: p1, p2Parameter: p2,
                data: Data(block.data), expectedResponseLength: -1
            )
            let (_, sw1, sw2) = try await sendOnce(apdu, tag: tag)
            guard sw1 == 0x90, sw2 == 0x00 else { throw OpenPGPCardError.unexpectedStatus(sw1, sw2) }
        }

        // Final block: CLA 0x00 with the real Le, routed through `transmit` for
        // transparent response chaining. `commandChainBlocks` always returns at
        // least one block, so `last` is non-nil.
        guard let last = blocks.last else { throw OpenPGPCardError.malformedResponse }
        let finalApdu = NFCISO7816APDU(
            instructionClass: last.cla, instructionCode: ins,
            p1Parameter: p1, p2Parameter: p2,
            data: Data(last.data), expectedResponseLength: expectedResponseLength
        )
        return try await transmit(finalApdu)
    }

    private func sendOnce(_ apdu: NFCISO7816APDU, tag: NFCISO7816Tag) async throws -> ([UInt8], UInt8, UInt8) {
        do {
            let (data, sw1, sw2) = try await tag.sendCommand(apdu: apdu)
            return (Array(data), sw1, sw2)
        } catch {
            throw Self.mapNFCError(error)
        }
    }

    /// B1e — turn raw CoreNFC transceive/session failures into a clear, actionable
    /// `.connectionLost` (the "hold steady, tap again" case) instead of a generic
    /// `.underlying` message. Anything we don't recognise stays `.underlying`.
    static func mapNFCError(_ error: Error) -> OpenPGPCardError {
        if let already = error as? OpenPGPCardError { return already }
        if let nfc = error as? NFCReaderError {
            switch nfc.code {
            case .readerTransceiveErrorTagConnectionLost,
                 .readerTransceiveErrorTagResponseError,
                 .readerTransceiveErrorTagNotConnected,
                 .readerSessionInvalidationErrorSessionTimeout,
                 .readerSessionInvalidationErrorSessionTerminatedUnexpectedly:
                return .connectionLost
            default:
                return .underlying(error)
            }
        }
        return .underlying(error)
    }

    /// NFCISO7816APDU doesn't expose its CLA; we only ever resend our own commands,
    /// which all use CLA 0x00, so this is safe for the 0x6Cxx retry path.
    private func apduCLA(_ apdu: NFCISO7816APDU) -> UInt8 { 0x00 }

    // MARK: Helpers

    /// OpenPGP card manufacturer ID → name (port of Android's table).
    static func manufacturerName(_ id: Int) -> String {
        switch id {
        case 0x0000: return "Test card"
        case 0x0001: return "PPC Card Systems"
        case 0x0002: return "Prism Payment Technologies"
        case 0x0003: return "OpenFortress"
        case 0x0004: return "Wewid"
        case 0x0005: return "ZeitControl"
        case 0x0006: return "Yubico"
        case 0x0007: return "OpenKMS"
        case 0x0008: return "LogoEmail"
        case 0x0009: return "Fidesmo"
        case 0x000A: return "VivoKey"
        case 0x000B: return "Feitian Technologies"
        case 0x000D: return "Dangerous Things"
        case 0x000E: return "Excelsecu"
        case 0x000F: return "Nitrokey"
        case 0x0010: return "NeoPGP"
        case 0x0011: return "Token2"
        case 0x002A: return "Magrathea"
        case 0x0042: return "GnuPG e.V."
        case 0x1337: return "Warsaw Hackerspace"
        case 0x63AF: return "Trustica"
        case 0xFFFF: return "Test card"
        default:     return String(format: "Manufacturer 0x%04X", id)
        }
    }

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
}

// MARK: - NFCTagReaderSessionDelegate

extension OpenPGPCardService: NFCTagReaderSessionDelegate {

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // No-op; polling starts automatically.
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        // If we were still waiting to connect, surface the failure to connect().
        resumeConnect(.failure(Self.mapNFCError(error)))
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task {
            guard let first = tags.first else { return }
            guard case let .iso7816(iso) = first else {
                session.invalidate(errorMessage: "That isn't an OpenPGP smart card.")
                resumeConnect(.failure(OpenPGPCardError.notISO7816))
                return
            }
            do {
                try await session.connect(to: first)
                resumeConnect(.success(iso))
            } catch {
                resumeConnect(.failure(OpenPGPCardError.underlying(error)))
            }
        }
    }

    private func resumeConnect(_ result: Result<NFCISO7816Tag, Error>) {
        guard let cont = connectContinuation else { return }
        connectContinuation = nil
        switch result {
        case .success(let t): cont.resume(returning: t)
        case .failure(let e): cont.resume(throwing: e)
        }
    }
}

// MARK: - Minimal BER-TLV reader

/// Just enough BER-TLV to pull fields out of the OpenPGP application data. Handles
/// one- and two-byte tags, short/long length forms, and descends into constructed
/// (nested) objects so a tag like 0xC5 inside 0x73 inside 0x6E is found.
enum BERTLV {

    /// Find the value of `tag` anywhere in `bytes`, recursing into constructed TLVs.
    static func find(_ tag: UInt16, in bytes: [UInt8]) -> [UInt8]? {
        var i = 0
        while i < bytes.count {
            // Tag (1 or 2 bytes).
            let firstTagByte = bytes[i]
            var tagValue = UInt16(firstTagByte)
            let constructed = (firstTagByte & 0x20) != 0
            i += 1
            if (firstTagByte & 0x1F) == 0x1F {
                guard i < bytes.count else { return nil }
                tagValue = (UInt16(firstTagByte) << 8) | UInt16(bytes[i])
                i += 1
            }

            // Length.
            guard i < bytes.count else { return nil }
            var length = Int(bytes[i]); i += 1
            if length == 0x81 {
                guard i < bytes.count else { return nil }
                length = Int(bytes[i]); i += 1
            } else if length == 0x82 {
                guard i + 1 < bytes.count else { return nil }
                length = (Int(bytes[i]) << 8) | Int(bytes[i + 1]); i += 2
            }

            guard i + length <= bytes.count else { return nil }
            let value = Array(bytes[i..<(i + length)])

            if tagValue == tag {
                return value
            }
            if constructed {
                if let found = find(tag, in: value) { return found }
            }
            i += length
        }
        return nil
    }
}
