// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// OpenPGPCardService.swift
// PGPony
//
// The OpenPGP smart card protocol layer — transport-agnostic as of v8.1.0 §1.
//
// This owns everything that is true of an OpenPGP card no matter how the bytes
// get there: selecting the applet, reading application data, VERIFY and the KDF
// derivation it may require, PSO:CDS and PSO:DECIPHER, on-card key generation,
// PIN change and unblock, and the ISO 7816-4 command/response chaining that
// sits under all of it. It owns NOTHING about sessions — see CardTransport,
// NFCCardTransport and USBSmartCardTransport for that.
//
// Through 8.0.x this file also WAS the NFC session. That was extracted in 8.1.0
// because iPad has no NFC radio, so a universal build needs the USB-C smart
// card path or hardware keys arrive dead. The extraction was deliberately
// byte-neutral: same APDUs, same status-word handling, same order. `APDU`
// mirrors `NFCISO7816APDU`'s member names precisely so that claim stays
// checkable against the 8.0.x diff by eye.
//
// SESSION SHAPE: "open once, verify once, run N operations, close." The
// connection is held for the lifetime of the session so multiple operations
// (e.g. a self-cert plus each subkey binding during a card expiration edit) run
// under a single tap and a single PIN verify. Do not collapse this into
// one-shot calls. On a persistent USB session this matters even more — see
// CardTransportKind.isPersistent and §3c.
//
// HARDWARE: verified against the Token2 R3.3 (Ed25519 sign, cv25519 decrypt)
// and YubiKey 5 NFC. RSA signing is supported as of HW-R2 (PSO:CDS over a
// PKCS#1 v1.5 DigestInfo via `signRSA`); RSA decryption reuses the outbound
// command chaining from HW-R1 (`transmitChained`).
//
// PROJECT SETUP: NFC needs the "Near Field Communication Tag Reading"
// capability, `NFCReaderUsageDescription`, and the iso7816 select-identifiers
// list (OpenPGP AID D2760001240103) in Info.plist. USB-C smart card needs the
// `com.apple.security.smartcard` entitlement and iOS/iPadOS 16+.

import Foundation
import LocalAuthentication
import Security

/// CORE SEAM: the app observes UIApplication.protectedDataWillBecomeUnavailableNotification;
/// the core names the same notification by its string so it imports no UIKit.
private let protectedDataWillBecomeUnavailable = Notification.Name("UIApplicationProtectedDataWillBecomeUnavailable")
/// CORE SEAM: likewise UIApplication.didEnterBackgroundNotification, by its
/// underlying name, for the opt-in clear-on-background policy.
private let applicationDidEnterBackground = Notification.Name("UIApplicationDidEnterBackgroundNotification")

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

    // v8.1.0 — §4b. Whether the card carries an enabled KDF-DO (00F9), meaning it
    // expects derived PINs rather than the PIN itself. Surfaced in the card-status
    // UI because a KDF card that PGPony mishandles presents as "wrong PIN", which
    // sends the user looking in exactly the wrong place.
    let kdfEnabled: Bool
    /// Human-readable KDF parameters ("SHA-256, 100000 iterations") or "Off".
    let kdfDescription: String?

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

    /// Which KDF salt applies. Both PW1 modes share the PW1 salt — 0x81 vs 0x82
    /// selects what the verification *authorises*, not which secret it is.
    var kdfReference: CardKDF.PINReference {
        switch self {
        case .signing, .confidentiality: return .pw1
        case .admin:                     return .pw3
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
    /// v8.1.0 §1 — USB-C smart card isn't usable on this build or OS version.
    case usbSmartCardUnavailable
    /// v8.1.0 §1 — USB is usable but nothing is plugged in, and we waited.
    /// Distinct from `usbSmartCardUnavailable`: the fix is to insert a key, not
    /// to use a different device.
    case usbKeyNotAttached
    /// v8.1.0 §1 — an NFC session ended without ever seeing a card. This is the
    /// case behind the original 8.0.1 report: the reporter held a USB-C-only 5C
    /// Nano against the phone, which can never respond over NFC, and got a
    /// silent timeout that said nothing about why. Distinct from
    /// `connectionLost`, which means a card WAS there and went away mid-op.
    case noCardDetected
    /// v8.1.0 §1 — neither transport is available. On iPad this is the "no key
    /// plugged in and there is no NFC radio to fall back to" case, which is a
    /// real and permanent state rather than a transient failure.
    case noTransportAvailable
    case notISO7816
    case appletNotFound
    case unexpectedStatus(UInt8, UInt8)
    case pinBlocked
    case wrongPIN(retriesRemaining: Int?)
    /// #24 — the caller asked for the remembered PIN and this card has none.
    /// Thrown before anything touches the card; the UI reacts by prompting.
    case storedPINUnavailable
    case malformedResponse
    case sessionClosed
    case underlying(Error)
    /// B1e — the NFC link dropped mid-operation (tag moved, or session timed out).
    case connectionLost
    /// The link dropped BETWEEN sending a PIN and reading the card's answer.
    /// Found by a tester: his wrong PIN was counted by the card, but the NFC
    /// session died before the 63Cx status word came back, so the app reported
    /// a generic connection drop and the remaining-attempts feature never
    /// fired. We cannot recover a status word that never arrived — what we can
    /// do is stop pretending the attempt didn't happen.
    case pinCheckInterrupted(lastKnownRetries: Int?)
    /// B1e — a PIN change returned success but the new PIN failed to verify, so it
    /// likely didn't commit to the card.
    case changeNotCommitted
    /// v8.1.0 §4b — the PIN is longer than the card's declared maximum for that
    /// reference. Refused locally: sending it would spend a retry for nothing.
    case pinTooLong(maximum: Int)
    /// v8.1.0 §4b — the card advertises a KDF-DO we can't parse or can't derive
    /// (unknown algorithm/hash, or a missing salt). Refusing is deliberate: the
    /// raw fallback would be rejected by the card and burn an attempt every time.
    case kdfUnsupported

    var errorDescription: String? {
        switch self {
        case .nfcUnavailable:
            return "This device can't read NFC hardware keys, or NFC is unavailable right now."
        case .usbSmartCardUnavailable:
            return String(localized: "This device can't use a USB-C hardware key. That needs iOS or iPadOS 16 or later.")
        case .usbKeyNotAttached:
            return String(localized: "No USB-C hardware key detected. Plug your key in and try again.")
        case .noCardDetected:
            if CardTransportAvailability.isUSBSmartCardAvailable {
                return String(localized: "No card detected. If your key is USB-C only, like a YubiKey 5C, it can't be tapped. Plug it into the USB-C port instead.")
            }
            return String(localized: "No card detected. Check that your key supports NFC and hold it flat against the top of your iPhone. USB-C-only keys such as the YubiKey 5C can't be tapped.")
        case .noTransportAvailable:
            return String(localized: "No way to reach a hardware key. Plug a USB-C key into this device, or use a device that supports NFC.")
        case .notISO7816:
            return "That tag isn't an OpenPGP smart card."
        case .appletNotFound:
            return String(localized: "No OpenPGP application was found on the card.")
        case .unexpectedStatus(let sw1, let sw2):
            return String(format: "The card returned an unexpected status (0x%02X%02X).", sw1, sw2)
        case .pinBlocked:
            return String(localized: "This PIN is blocked: the card refused it too many times. Unblock it with your admin PIN (PW3) or your reset code. Your keys are not lost.")
        case .wrongPIN(let n):
            // #25 — the count is the difference between an annoyance and a
            // blocked card, so it escalates instead of staying flat.
            switch n {
            case .some(1):
                return String(localized: "Incorrect PIN. Only 1 attempt remains; if it fails, this key's PIN will be blocked. Double-check before trying again.")
            case .some(let n):
                return String(localized: "Incorrect PIN. \(n) attempts remaining before this key's PIN is blocked.")
            case .none:
                return String(localized: "Incorrect PIN.")
            }
        case .pinCheckInterrupted(let lastKnown):
            if let lastKnown {
                return String(localized: "The connection dropped while your PIN was being checked, so the result is unknown. If the PIN was wrong, the attempt was still counted. Before this try, \(lastKnown) attempts remained. Reconnect and the current count will be shown.")
            }
            return String(localized: "The connection dropped while your PIN was being checked, so the result is unknown. If the PIN was wrong, the attempt was still counted. Reconnect and the current count will be shown.")
        case .storedPINUnavailable:
            return String(localized: "No PIN is remembered for this key. Enter its PIN once and it can be remembered.")
        case .malformedResponse:
            return "The card's response could not be understood."
        case .sessionClosed:
            return "The card session is no longer active. Tap your key again."
        case .connectionLost:
            // v8.1.0: was NFC wording unconditionally. A tester on USB-C was
            // told to hold his key against the phone and tap.
            return CardConnectionCopy.prompt(
                nfc: String(localized: "The key moved out of range before the operation finished, so it was not completed. Hold the key flat and still against the top edge of your iPhone, behind the camera bar, and tap again."),
                usb: String(localized: "The card connection dropped before the operation finished. Check the key is firmly in the USB-C port and try again.")
            )
        case .changeNotCommitted:
            return "The card reported the PIN change but the new PIN didn't verify, so it may not have saved. Hold the key steady and try again."
        case .pinTooLong(let maximum):
            return String(localized: "That PIN is longer than this card accepts (maximum \(maximum) characters). It wasn't sent, so no attempt was used.")
        case .kdfUnsupported:
            return String(localized: "This card uses a PIN-protection setting (KDF) that PGPony can't read. PGPony didn't send your PIN, so no attempt was used. The card still works with GnuPG or Kleopatra.")
        case .underlying(let e):
            return e.localizedDescription
        }
    }
}

// MARK: - Service

final class OpenPGPCardService {

    /// OpenPGP applet AID prefix (RID D27600 + application 0124 + 01). The card's
    /// full AID adds version + manufacturer + serial; SELECT by this prefix.
    static let openPGPAID: [UInt8] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]

    // v8.1.0 — §1. How this session reaches the card. Resolved at connect()
    // rather than at init so the 15 existing `OpenPGPCardService()` call sites
    // keep working unchanged and pick up transport selection for free.
    private var transport: CardTransport?
    private let explicitTransport: CardTransport?
    private let preferredKind: CardTransportKind?

    /// The connected card's serial from its AID, read during connect. This is
    /// what the PIN cache is keyed by (#24); nil means the card would not
    /// identify itself, in which case no cached PIN is ever used for it.
    private(set) var connectedSerialHex: String?

    /// 8.3.0 (hardening): what a remembered PIN is bound to: the card's
    /// serial, the three key fingerprints it reports, and whether it asks for
    /// a KDF-derived PIN. A card that differs in any of them matches no
    /// remembered entry and gets the ordinary prompt. Nil when the card would
    /// not say, in which case nothing is remembered for it.
    private(set) var connectedPINIdentity: String?

    /// Which transport this session actually ended up on — for UI that wants to
    /// say "connected over USB-C" rather than guessing.
    var activeTransportKind: CardTransportKind? { transport?.kind }

    /// Build a session. Pass nothing for automatic selection (a plugged-in USB-C
    /// key wins over prompting for a tap); pass `preferring:` to force a
    /// transport when the user has overridden it in the UI; pass `transport:`
    /// directly in tests.
    init(transport: CardTransport? = nil, preferring kind: CardTransportKind? = nil) {
        self.explicitTransport = transport
        self.preferredKind = kind
    }

    // v8.1.0 — §4b. Read once at connect and held for the session.
    //
    // `kdf` nil means the card has no KDF-DO and PINs go over the wire as UTF-8,
    // which is the path every currently-working card takes. Non-nil-but-disabled
    // (algorithm byte 0x00) means the same thing, explicitly. Only an *enabled*
    // KDF-DO changes what gets sent.
    private(set) var kdf: CardKDF?
    /// True when DO 00F9 was present but could not be parsed into something we
    /// can derive with. Distinct from `kdf == nil` (genuinely absent) because
    /// the raw fallback is safe in the second case and harmful in the first.
    private(set) var kdfUnreadable = false
    /// PW status maxima (PW1, reset code, PW3), read at connect so a too-long
    /// PIN can be refused locally instead of costing the user a retry.
    private var pinMaxLengths: (pw1: Int, resetCode: Int, pw3: Int)?

    /// PW1 retry counter as read from DO 00C4 at connect — BEFORE any verify in
    /// this session. Used to make an interrupted PIN check honest about what was
    /// at stake, and refreshed after failures for cards that answer 0x6982
    /// without a count.
    private(set) var pw1RetriesAtConnect: Int?

    /// Whether ANY transport can reach a hardware key on this device. Callers
    /// that need to distinguish should ask CardTransportAvailability directly —
    /// iPad in particular must show no NFC affordance at all rather than a
    /// disabled one.
    var isAvailable: Bool { CardTransportAvailability.isAnyAvailable }

    // MARK: Lifecycle

    /// Open a session on the selected transport, connect to a card, and SELECT
    /// the OpenPGP applet. The connection is held until `end(...)`.
    ///
    /// `alertMessage` drives the CoreNFC sheet and is ignored on a wired
    /// session, which has no system UI. Whether this blocks on a human depends
    /// on the transport: NFC waits for a tap, USB may return immediately if a
    /// key is already plugged in.
    func connect(alertMessage: String = CardConnectionCopy.connectPrompt) async throws -> OpenPGPCardService {
        let resolved: CardTransport
        if let explicitTransport {
            resolved = explicitTransport
        } else if let made = CardTransportAvailability.makeTransport(preferredKind) {
            resolved = made
        } else {
            // Pick the message that names something the user can actually do.
            // On a device or build with no USB support at all, "plug in a USB-C
            // key" is advice about a transport that doesn't exist here.
            throw USBSmartCardTransport.isAvailable
                ? OpenPGPCardError.noTransportAvailable
                : OpenPGPCardError.nfcUnavailable
        }
        self.transport = resolved

        try await resolved.connect(alertMessage: alertMessage)
        // 8.3.0 (9.1): the coupling worked; say so at once and ask for the
        // hold, since the applet select, the PIN check and the operation all
        // still need the key exactly where it is.
        if resolved.kind == .nfc {
            resolved.updateStatus(CardConnectionCopy.keyFoundStatus)
        }
        try await selectOpenPGPApplet()
        // #24 — identify the card before any PIN can be needed. One GET DATA;
        // a card that won't answer simply gets no PIN-cache participation.
        connectedSerialHex = try? await readAIDSerial()
        // §4b — must happen before any PIN is sent. A transport failure here
        // propagates and fails the connect, which is correct: we would rather
        // not open a session than open one that might burn PW1 attempts.
        try await readKDFConfiguration()
        connectedPINIdentity = await readPINIdentity()
        return self
    }

    /// 8.3.0 (hardening): serial, key fingerprints (DO C5 inside the
    /// application related data) and KDF state, as `connectedPINIdentity`
    /// describes. One GET DATA; any failure leaves the identity nil.
    private func readPINIdentity() async -> String? {
        guard let serial = connectedSerialHex, !serial.isEmpty, !kdfUnreadable else { return nil }
        let apdu = APDU(
            instructionClass: 0x00, instructionCode: 0xCA,
            p1Parameter: 0x00, p2Parameter: 0x6E,
            data: Data(), expectedResponseLength: 256
        )
        guard let (data, sw1, sw2) = try? await transmit(apdu), sw1 == 0x90, sw2 == 0x00,
              let fingerprints = BERTLV.find(0x00C5, in: data), fingerprints.count >= 60 else { return nil }
        return Self.pinIdentity(serial: serial, fingerprints: Array(fingerprints.prefix(60)),
                                kdfEnabled: kdf?.isEnabled == true)
    }

    /// The identity string, split out so it can be tested without a card.
    nonisolated static func pinIdentity(serial: String, fingerprints: [UInt8], kdfEnabled: Bool) -> String {
        "\(serial)|\(fingerprints.map { String(format: "%02x", $0) }.joined())|kdf:\(kdfEnabled ? "on" : "off")"
    }

    /// v8.1.0 — §4b. Read the KDF data object (DO 00F9) and the PW status bytes
    /// (DO 00C4) so `verify` knows what form the card expects a PIN in, and how
    /// long a PIN it will accept.
    ///
    /// A card without KDF configured answers GET DATA 00F9 with 6A88 ("referenced
    /// data not found") or similar. That is the overwhelmingly common case and it
    /// leaves `kdf` nil, preserving the existing raw-PIN behaviour exactly.
    private func readKDFConfiguration() async throws {
        kdf = nil
        kdfUnreadable = false

        let kdfApdu = APDU(
            instructionClass: 0x00, instructionCode: 0xCA,
            p1Parameter: 0x00, p2Parameter: 0xF9,
            data: Data(), expectedResponseLength: 256
        )
        let (kdfData, k1, k2) = try await transmit(kdfApdu)
        if k1 == 0x90, k2 == 0x00, !kdfData.isEmpty {
            if let parsed = CardKDF.parse(kdfData) {
                kdf = parsed
            } else if kdfData.count >= 3, kdfData[0] == 0x81, kdfData[1] == 0x01,
                      kdfData[2] != CardKDF.Algorithm.none.rawValue {
                // The card is unambiguously declaring a KDF algorithm we can't
                // derive. Refuse rather than fall back: raw would be rejected and
                // would cost an attempt on every try.
                kdfUnreadable = true
            }
            // Anything else that answered 0x9000 but doesn't look like a KDF-DO
            // (a card echoing a template, a vendor quirk) is treated as "no KDF"
            // and takes the unchanged raw path. Declaring it unreadable would
            // make the card 100% unusable in PGPony, which is a strictly worse
            // outcome than the behaviour that shipped in 8.0.x.
        }

        // PW status: exactly 7 bytes, [0] = signature PIN forced flag,
        // [1...3] = max lengths for PW1 / reset code / PW3.
        //
        // The length is checked strictly (== 7, not >= 4) because this drives a
        // *local* refusal: a card that answers 00C4 with something else — an
        // echoed template, a vendor quirk — would otherwise populate bogus
        // maxima and start rejecting PINs that used to work, turning a guard
        // meant to save attempts into a new way to fail. The high bit of each
        // length byte is the PIN-format flag, not length, so it is masked off;
        // that only ever loosens the guard.
        pinMaxLengths = nil
        let pwApdu = APDU(
            instructionClass: 0x00, instructionCode: 0xCA,
            p1Parameter: 0x00, p2Parameter: 0xC4,
            data: Data(), expectedResponseLength: 256
        )
        pw1RetriesAtConnect = nil
        if let (pw, p1, p2) = try? await transmit(pwApdu), p1 == 0x90, p2 == 0x00, pw.count == 7 {
            pw1RetriesAtConnect = Int(pw[4])
            pinMaxLengths = (
                pw1: Int(pw[1] & 0x7F),
                resetCode: Int(pw[2] & 0x7F),
                pw3: Int(pw[3] & 0x7F)
            )
        }
    }

    /// v8.1.0 — §4b. Turn a user-entered PIN into the bytes this specific card
    /// expects in the command data field.
    ///
    /// This is the single chokepoint for every command that carries a PIN, so a
    /// new call site cannot forget the KDF step. That is deliberate: forgetting
    /// it is silent and costs the user a retry each time.
    ///
    /// The length guard applies only to the raw path. When KDF is on, the value
    /// sent is a fixed-length digest and the card's maxima describe *that*, not
    /// the passphrase the user typed.
    func pinPayload(_ pin: String, reference: CardKDF.PINReference) throws -> [UInt8] {
        if kdfUnreadable { throw OpenPGPCardError.kdfUnsupported }

        if let kdf, kdf.isEnabled {
            guard let derived = kdf.derive(pin: pin, reference: reference) else {
                throw OpenPGPCardError.kdfUnsupported
            }
            return derived
        }

        let bytes = Array(pin.utf8)
        if let maxima = pinMaxLengths {
            let maximum: Int
            switch reference {
            case .pw1:       maximum = maxima.pw1
            case .resetCode: maximum = maxima.resetCode
            case .pw3:       maximum = maxima.pw3
            }
            if maximum > 0, bytes.count > maximum {
                throw OpenPGPCardError.pinTooLong(maximum: maximum)
            }
        }
        return bytes
    }

    /// Update system-provided progress UI mid-session (e.g. "Signing…"). A
    /// no-op on a wired session; PGPony's own UI carries progress there.
    func updateAlert(_ message: String) {
        // 8.3.0 (9.1): on NFC every progress line carries the hold reminder,
        // so "Signing…" reads as "Signing… Keep the key still against the top
        // edge." A wired session shows PGPony's own UI and gets the bare text.
        if transport?.kind == .nfc, !message.contains(CardConnectionCopy.holdStillLine) {
            transport?.updateStatus(message + "\n" + CardConnectionCopy.holdStillLine)
        } else {
            transport?.updateStatus(message)
        }
    }

    /// Close the session. On success the system shows a checkmark; on failure the
    /// red error UI with `message`.
    func end(success: Bool, message: String? = nil) {
        transport?.disconnect(success: success, message: message)
        transport = nil
    }

    // MARK: Applet operations

    private func selectOpenPGPApplet() async throws {
        let apdu = APDU(
            instructionClass: 0x00, instructionCode: 0xA4,
            p1Parameter: 0x04, p2Parameter: 0x00,
            data: Data(Self.openPGPAID), expectedResponseLength: 256
        )
        let (_, sw1, sw2) = try await transmit(apdu)
        guard sw1 == 0x90, sw2 == 0x00 else { throw OpenPGPCardError.appletNotFound }
    }

    /// Read just the AID (DO 0x4F) and pull the 4-byte serial out of it.
    /// AID layout: RID(5) app(1) version(2) manufacturer(2) serial(4) rfu(2).
    private func readAIDSerial() async throws -> String? {
        let apdu = APDU(
            instructionClass: 0x00, instructionCode: 0xCA,
            p1Parameter: 0x00, p2Parameter: 0x4F,
            data: Data(), expectedResponseLength: 256
        )
        let (data, sw1, sw2) = try await transmit(apdu)
        guard sw1 == 0x90, sw2 == 0x00, data.count >= 14 else { return nil }
        return hex(Array(data[10..<14]))
    }

    /// Read application-related data (DO 0x6E) and parse the fields we surface.
    func readCardInfo() async throws -> OpenPGPCardInfo {
        let apdu = APDU(
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
        let secApdu = APDU(
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
            signatureCounter: sigCounter,
            kdfEnabled: kdf?.isEnabled ?? false,
            kdfDescription: kdf?.displayDescription
        )
    }

    /// VERIFY a PIN for the given mode. Throws `wrongPIN`/`pinBlocked` on failure so
    /// the caller can prompt again with the remaining-attempts count.
    ///
    /// An EMPTY pin is a sentinel meaning "use this card's remembered PIN".
    /// #24 — the caller cannot know which card will be present when it decides
    /// to skip the prompt, so the lookup has to happen here, after the card has
    /// identified itself. If this card has no remembered PIN, nothing is sent:
    /// `storedPINUnavailable` is thrown before any APDU, and no attempt is
    /// spent. That ordering is the entire fix — the old code sent first and
    /// found out by burning a retry on the wrong card.
    func verify(pin: String, mode: OpenPGPCardPIN) async throws {
        var pin = pin
        if pin.isEmpty {
            guard let remembered = CardPINCache.shared.pin(forSerial: connectedPINIdentity) else {
                throw OpenPGPCardError.storedPINUnavailable
            }
            pin = remembered
        }
        // §4b — derived on a KDF card, raw otherwise. Never `Array(pin.utf8)`
        // directly: that is the bug that burned the Jul 30 reporter's attempts.
        let pinBytes = try pinPayload(pin, reference: mode.kdfReference)
        // 8.3.0 (9.1): the PIN check is the first step that spends anything
        // if the key moves; name it, with the hold.
        updateAlert(String(localized: "Checking the PIN…"))
        let apdu = APDU(
            instructionClass: 0x00, instructionCode: 0x20,
            p1Parameter: 0x00, p2Parameter: mode.p2,
            data: Data(pinBytes), expectedResponseLength: -1
        )
        let sw1: UInt8, sw2: UInt8
        do {
            (_, sw1, sw2) = try await transmit(apdu)
        } catch OpenPGPCardError.connectionLost {
            // The command may have reached the card even though the answer did
            // not reach us — a tester's retry counter proved exactly that. A
            // generic "dropped, tap again" here hides a possibly-consumed
            // attempt, which is how someone taps their way to a blocked card
            // believing nothing happened.
            throw OpenPGPCardError.pinCheckInterrupted(lastKnownRetries: pw1RetriesAtConnect)
        }
        if sw1 == 0x90, sw2 == 0x00 { return }
        // 0x63 0xCx = verification failed, x attempts left. 0x69 0x83 = blocked.
        if sw1 == 0x63, (sw2 & 0xF0) == 0xC0 {
            throw OpenPGPCardError.wrongPIN(retriesRemaining: Int(sw2 & 0x0F))
        }
        if sw1 == 0x69, sw2 == 0x83 { throw OpenPGPCardError.pinBlocked }
        // Some cards (incl. YubiKey) report a failed PIN check as 0x6982 "security
        // status not satisfied" rather than 0x63Cx — no attempt count in the
        // status word. Which means the remaining-attempts feature would never
        // fire on exactly the hardware our testers carry. The count still
        // exists on the card, in the PW status bytes — fetch it while the
        // session is still open. Best-effort: a failed read degrades to the
        // countless message rather than failing the failure.
        if sw1 == 0x69, sw2 == 0x82 {
            throw OpenPGPCardError.wrongPIN(retriesRemaining: await readPW1RetriesBestEffort())
        }
        throw OpenPGPCardError.unexpectedStatus(sw1, sw2)
    }

    /// Read the PW1 retry counter from DO 00C4, returning nil on any failure.
    /// Called after a countless wrong-PIN answer, inside the same session.
    private func readPW1RetriesBestEffort() async -> Int? {
        let apdu = APDU(
            instructionClass: 0x00, instructionCode: 0xCA,
            p1Parameter: 0x00, p2Parameter: 0xC4,
            data: Data(), expectedResponseLength: 256
        )
        guard let (pw, p1, p2) = try? await transmit(apdu),
              p1 == 0x90, p2 == 0x00, pw.count == 7 else { return nil }
        return Int(pw[4])
    }

    // MARK: Change Reference Data (Phase 10a — PW1 PIN change)

    /// CHANGE REFERENCE DATA (INS 0x24). The card splits the concatenated
    /// oldPIN‖newPIN using its stored length of the *current* PIN, so the caller
    /// just supplies both as UTF-8. `pinReference` is 0x81 for PW1 (user) or 0x83
    /// for PW3 (admin). Assumes the applet is already selected (connect() does
    /// that). Throws `wrongPIN`/`pinBlocked` so the UI can show remaining attempts.
    func changeReferenceData(pinReference: UInt8, oldPIN: String, newPIN: String) async throws {
        // §4b — both halves must be in the card's expected form. On a KDF card
        // each is a fixed-length digest, which also makes the card's split
        // unambiguous. Mixing forms here would reject *and* spend an attempt.
        let reference: CardKDF.PINReference = (pinReference == 0x83) ? .pw3 : .pw1
        let payload = try pinPayload(oldPIN, reference: reference)
                    + pinPayload(newPIN, reference: reference)
        let apdu = APDU(
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
        // §4b — the new PW1 is installed in the card's expected form, so on a
        // KDF card it must be derived with the PW1 salt before being sent.
        let newPINBytes = try pinPayload(newPIN, reference: .pw1)
        let apdu = APDU(
            instructionClass: 0x00, instructionCode: 0x2C,
            p1Parameter: 0x02, p2Parameter: 0x81,
            data: Data(newPINBytes), expectedResponseLength: -1
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

        let terminate = APDU(
            instructionClass: 0x00, instructionCode: 0xE6,
            p1Parameter: 0x00, p2Parameter: 0x00,
            data: Data(), expectedResponseLength: -1
        )
        let (_, t1, t2) = try await transmit(terminate)
        guard t1 == 0x90, t2 == 0x00 else { throw OpenPGPCardError.unexpectedStatus(t1, t2) }

        let activate = APDU(
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
        let apdu = APDU(
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

        let apdu = APDU(
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
        let apdu = APDU(
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
        let apdu = APDU(
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
        let apdu = APDU(
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
        let apdu = APDU(
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
    func transmit(_ apdu: APDU) async throws -> APDUResponse {
        guard let transport, transport.isConnected else { throw OpenPGPCardError.sessionClosed }

        var (response, sw1, sw2) = try await transport.send(apdu)
        var accumulated = response

        // 0x6Cxx: card wants a specific Le; resend the same command with Le = sw2.
        if sw1 == 0x6C {
            let retry = APDU(
                instructionClass: apdu.instructionClass, instructionCode: apdu.instructionCode,
                p1Parameter: apdu.p1Parameter, p2Parameter: apdu.p2Parameter,
                data: apdu.data, expectedResponseLength: Self.leFromSW2(sw2)
            )
            (response, sw1, sw2) = try await transport.send(retry)
            accumulated = response
        }

        // 0x61xx: more data available; pull it with GET RESPONSE until 0x9000.
        // 8.3.0 (hardening): bounded. A real card's largest answer (the
        // application data, a 4096-bit key) is a few KiB in a handful of
        // rounds, so the loop is bounded well above that.
        var rounds = 0
        while sw1 == 0x61 {
            rounds += 1
            guard rounds <= 64, accumulated.count <= 64 * 1024 else {
                throw OpenPGPCardError.malformedResponse
            }
            let getResponse = APDU(
                instructionClass: 0x00, instructionCode: 0xC0,
                p1Parameter: 0x00, p2Parameter: 0x00,
                data: Data(), expectedResponseLength: Self.leFromSW2(sw2)
            )
            let (more, s1, s2) = try await transport.send(getResponse)
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
    ) async throws -> APDUResponse {
        guard let transport, transport.isConnected else { throw OpenPGPCardError.sessionClosed }

        let blocks = Self.commandChainBlocks(data: data)

        // Intermediate blocks: CLA 0x10, Le absent, each must ack 0x9000.
        for block in blocks where !block.isLast {
            let apdu = APDU(
                instructionClass: block.cla, instructionCode: ins,
                p1Parameter: p1, p2Parameter: p2,
                data: Data(block.data), expectedResponseLength: -1
            )
            let (_, sw1, sw2) = try await transport.send(apdu)
            guard sw1 == 0x90, sw2 == 0x00 else { throw OpenPGPCardError.unexpectedStatus(sw1, sw2) }
        }

        // Final block: CLA 0x00 with the real Le, routed through `transmit` for
        // transparent response chaining. `commandChainBlocks` always returns at
        // least one block, so `last` is non-nil.
        guard let last = blocks.last else { throw OpenPGPCardError.malformedResponse }
        let finalApdu = APDU(
            instructionClass: last.cla, instructionCode: ins,
            p1Parameter: p1, p2Parameter: p2,
            data: Data(last.data), expectedResponseLength: expectedResponseLength
        )
        return try await transmit(finalApdu)
    }

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

// MARK: - Minimal BER-TLV reader

/// Just enough BER-TLV to pull fields out of the OpenPGP application data. Handles
/// one- and two-byte tags, short/long length forms, and descends into constructed
/// (nested) objects so a tag like 0xC5 inside 0x73 inside 0x6E is found.
enum BERTLV {

    /// Find the value of `tag` anywhere in `bytes`, recursing into constructed TLVs.
    /// 8.3.0 (hardening): nesting is bounded; the OpenPGP card data is three
    /// levels deep at most, so anything past eight is not a real card.
    static let maxDepth = 8

    static func find(_ tag: UInt16, in bytes: [UInt8]) -> [UInt8]? {
        find(tag, in: bytes, depth: 0)
    }

    private static func find(_ tag: UInt16, in bytes: [UInt8], depth: Int) -> [UInt8]? {
        guard depth < maxDepth else { return nil }
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
                if let found = find(tag, in: value, depth: depth + 1) { return found }
            }
            i += length
        }
        return nil
    }
}

/// 8.3.0 (hardening): both secret caches normally outlive a trip to the
/// background, because sharing from Mail into PGPony backgrounds the app and
/// a cleared cache would ask again mid-flow. Users who would rather trade that
/// for a shorter window turn this on in Settings; off by default.
enum SecretCacheBackgroundPolicy {
    static let defaultsKey = "clearSecretsOnBackground"
    static var clearsOnBackground: Bool {
        get { UserDefaults.standard.bool(forKey: defaultsKey) }
        set { UserDefaults.standard.set(newValue, forKey: defaultsKey) }
    }
}

// MARK: - v7.1.0: Card user-PIN cache (a tester's request)

/// Opt-in, in-memory cache for the OpenPGP card *user* PIN (PW1), so a user doing
/// several card operations in one session isn't re-prompted every time.
///
/// Security posture (deliberately conservative):
/// - Default mode is `.never` → no caching at all, identical to prior behavior.
///   Caching only happens if the user explicitly opts in via Settings.
/// - The PIN lives ONLY in memory. It is never written to disk, UserDefaults, or
///   the Keychain. Only the cache *mode* (an enum) is persisted.
/// - The cache is wiped on: expiry, manual clear, and whenever a verify rejects
///   the PIN (so a stale PIN can't silently burn PW1 attempts). It is NOT wiped
///   on app backgrounding — the chosen duration is the sole time boundary.
/// - Only the user PIN (PW1) is ever cached. The admin PIN (PW3) is never cached.
final class CardPINCache {
    static let shared = CardPINCache()

    enum Mode: String, CaseIterable {
        case never            // ask every time (default)
        case oneMinute
        case fiveMinutes
        case fifteenMinutes
        /// 8.3.0 (9.4, Android 4.3.0 "until the phone locks"): held until
        /// iOS reports the device locking (protected data becoming
        /// unavailable), not by a timer. Ends with the process too.
        case untilDeviceLocks
        case untilCleared     // until manual clear (or a wrong-PIN clear)

        /// Seconds of validity, or nil for "until manually cleared", or 0 for never.
        var seconds: TimeInterval? {
            switch self {
            case .never:            return 0
            case .oneMinute:        return 60
            case .fiveMinutes:      return 300
            case .fifteenMinutes:   return 900
            case .untilDeviceLocks: return nil
            case .untilCleared:     return nil
            }
        }

        var label: String {
            switch self {
            case .never:          return String(localized: "Ask every time")
            case .oneMinute:      return String(localized: "1 minute")
            case .fiveMinutes:    return String(localized: "5 minutes")
            case .fifteenMinutes: return String(localized: "15 minutes")
            // v8.1.0 §3c — was "Until I clear it", which is not true: this
            // cache is in memory and dies with the process. A user who fully
            // quits PGPony and returns to a PIN prompt reported it as a bug,
            // and they were right to — the label promised persistence the
            // implementation never had. The behaviour is deliberate (a PIN on
            // disk alongside a key on the card collapses two factors into one),
            // so the label changed rather than the storage.
            case .untilDeviceLocks: return String(localized: "Until the phone locks")
            case .untilCleared:   return String(localized: "Until PGPony quits")
            }
        }

        /// Whether a held secret is cleared when the device locks (9.4).
        var endsOnDeviceLock: Bool { self == .untilDeviceLocks }
    }

    private static let modeKey = "pgpony_pin_cache_mode"

    static var mode: Mode {
        get { Mode(rawValue: UserDefaults.standard.string(forKey: modeKey) ?? "") ?? .never }
        set { UserDefaults.standard.set(newValue.rawValue, forKey: modeKey) }
    }

    // 8.3.0 (9.2, the 8.0.1 / 8.1.0 testers' pair):
    //
    // "Remember card PIN does not survive a full quit." It never could, by
    // the v8.1.0 §3c decision that a PIN on disk beside a key on the card
    // collapses two factors into one. What changed is the second factor: a
    // PIN kept across restarts is stored in the Keychain behind its own
    // user-presence access control (Face ID / Touch ID, passcode fallback),
    // this device only, never synced. Reading it back costs an authentication
    // every time the in-memory copy is gone, so the card and the PIN still
    // do not travel together. Opt-in, and only with "Until PGPony quits".
    //
    // "Face ID for the security-key PIN without the app-wide lock." A remembered
    // PIN (memory or Keychain) is used only after a fresh biometric check when
    // this is on; a typed PIN is never gated.
    static let persistKey = "pgpony_pin_cache_persist"
    static let biometricKey = "pgpony_pin_cache_biometric"

    /// Keep the remembered PIN in the Keychain across restarts (9.2).
    static var persistsAcrossRestarts: Bool {
        get { UserDefaults.standard.bool(forKey: persistKey) }
        set { UserDefaults.standard.set(newValue, forKey: persistKey) }
    }

    /// Require Face ID / Touch ID before a remembered PIN is used (9.2).
    static var requiresBiometric: Bool {
        get { UserDefaults.standard.bool(forKey: biometricKey) }
        set { UserDefaults.standard.set(newValue, forKey: biometricKey) }
    }

    /// Whether the persisted tier is in effect: opted in and on the one
    /// duration it makes sense for.
    static var persistenceActive: Bool { persistsAcrossRestarts && mode == .untilCleared }

    /// The one entry point the card flows use before opening a session:
    /// is there a remembered PIN this card may use without a prompt? It
    /// restores the Keychain copy (one system authentication) when memory
    /// is empty, and runs the Face ID gate when that is required. Called
    /// BEFORE the NFC session starts, because a system prompt during a tag
    /// session ends the session. False means "ask the user".
    @MainActor
    func rememberedPINIsUsable() async -> Bool {
        guard Self.mode != .never else { return false }
        var authenticatedByKeychain = false
        if !hasLiveEntry {
            guard Self.persistenceActive else { return false }
            var restored = await Task.detached(priority: .userInitiated) { CardPINKeychain.loadAll() }.value
            for legacy in restored.keys where !legacy.contains("|") {
                CardPINKeychain.remove(forSerial: legacy)
                restored.removeValue(forKey: legacy)
            }
            guard !restored.isEmpty else { return false }
            queue.sync {
                // Entries saved before 8.3.0 were keyed by serial alone; they
                // were removed above and the PIN is asked for once.
                for (serial, pin) in restored where entries[serial] == nil {
                    entries[serial] = Entry(pin: pin, expiry: nil, storedAt: Date())
                }
            }
            authenticatedByKeychain = true
        }
        if Self.requiresBiometric && !authenticatedByKeychain {
            return await Self.authenticate(reason: String(localized: "Use the remembered hardware key PIN"))
        }
        return true
    }

    /// Face ID / Touch ID with passcode fallback. False on any failure or
    /// cancel, which the caller turns into the ordinary PIN prompt.
    static func authenticate(reason: String) async -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return false }
        return await withCheckedContinuation { cont in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, _ in
                cont.resume(returning: ok)
            }
        }
    }

    // v8.1.0 build 3 (#24) — keyed by card serial, because a single global PIN
    // was replayed to whichever card happened to be present next. A tester with
    // two YubiKeys remembered the PIN on one, inserted the other, and the app
    // sent the first card's PIN to it: wrong, and a PW1 retry burned, with the
    // user never having typed anything. Same harm as the §4b KDF bug, harder to
    // notice.
    private struct Entry {
        var pin: String
        var expiry: Date?
        var storedAt: Date
    }
    private var entries: [String: Entry] = [:]
    private let queue = DispatchQueue(label: "app.pgpony.pincache")

    private init() {
        // v7.1.x (a tester's report): the PIN cache is bounded by the chosen duration, a
        // wrong-PIN clear, and the manual "Clear Remembered PIN" action — NOT by
        // app backgrounding. Backgrounding used to wipe it here, which defeated
        // the Mail -> PGPony flow (opening the share sheet backgrounds the app and
        // cleared the PIN before it could be used). The didEnterBackground
        // observer was removed so the chosen duration is the sole time boundary.
        // PW1 only, held in memory only, gone on app termination.
        //
        // 8.3.0 (9.4): "Until the phone locks" is the one boundary that is
        // neither a timer nor the process: iOS posts this when the device
        // locks (protected data goes away), which is exactly the moment a
        // held secret should not outlive. Backgrounding still does nothing.
        NotificationCenter.default.addObserver(
            forName: protectedDataWillBecomeUnavailable,
            object: nil, queue: nil
        ) { [weak self] _ in
            guard let self, Self.mode.endsOnDeviceLock else { return }
            self.clear()
        }
        // 8.3.0 (hardening): the opt-in "Forget When PGPony Leaves the Screen".
        // Memory only: a PIN kept across restarts stays in the Keychain, behind
        // its own Face ID check.
        NotificationCenter.default.addObserver(
            forName: applicationDidEnterBackground,
            object: nil, queue: nil
        ) { [weak self] _ in
            guard let self, SecretCacheBackgroundPolicy.clearsOnBackground else { return }
            self.queue.sync { self.entries.removeAll() }
        }
    }

    /// Live, read-only snapshot for the Settings countdown. Never mutates the
    /// cache (expiry is enforced on read in `pin(forSerial:)`).
    enum CacheState: Equatable {
        case off                                // mode is "Ask every time"
        case empty                              // caching on, nothing held right now
        case untilCleared                       // held, no time limit
        case untilDeviceLocks                   // held until the device locks (8.3.0, 9.4)
        case counting(remaining: TimeInterval)  // held, clears in `remaining` seconds
    }

    func state() -> CacheState {
        queue.sync {
            guard Self.mode != .never else { return .off }
            purgeExpiredLocked()
            // Several cards may be held; the countdown shows the most recently
            // stored one, which is the one the user is thinking about.
            guard let latest = entries.values.max(by: { $0.storedAt < $1.storedAt }) else {
                return .empty
            }
            if let expiry = latest.expiry {
                return .counting(remaining: expiry.timeIntervalSinceNow)
            }
            return Self.mode.endsOnDeviceLock ? .untilDeviceLocks : .untilCleared
        }
    }

    /// True when at least one live entry exists — the UI's pre-connect signal
    /// to skip the PIN prompt. Which card's entry applies is decided later, in
    /// the session, once the card has identified itself.
    var hasLiveEntry: Bool {
        queue.sync {
            guard Self.mode != .never else { return false }
            purgeExpiredLocked()
            return !entries.isEmpty
        }
    }

    private func purgeExpiredLocked() {
        let now = Date()
        entries = entries.filter { $0.value.expiry.map { $0 > now } ?? true }
    }

    /// The remembered PIN for THIS card, or nil. Never returns another card's
    /// PIN — that is the whole point of #24.
    func pin(forSerial serial: String?) -> String? {
        queue.sync {
            guard Self.mode != .never, let serial, !serial.isEmpty else { return nil }
            purgeExpiredLocked()
            return entries[serial]?.pin
        }
    }

    /// Store a PIN the card has just accepted, against that card's serial.
    /// A nil or empty serial means the card could not be identified, and an
    /// unidentifiable card gets nothing remembered — refusing to store beats
    /// storing under a key that can collide.
    func store(_ pin: String, forSerial serial: String?) {
        queue.sync {
            let mode = Self.mode
            guard mode != .never, !pin.isEmpty, let serial, !serial.isEmpty else { return }
            let expiry = mode.seconds.flatMap { $0 > 0 ? Date().addingTimeInterval($0) : nil }
            entries[serial] = Entry(pin: pin, expiry: expiry, storedAt: Date())
            // 8.3.0 (9.2): the persisted tier, only for "Until PGPony quits".
            if Self.persistenceActive {
                CardPINKeychain.save(pin, forSerial: serial)
            }
        }
    }

    /// Drop the entry for one card — after that card rejected its PIN.
    /// Falls back to clearing everything when the card was never identified,
    /// because keeping entries we can no longer attribute is how stale PINs
    /// outlive their welcome.
    func clearEntry(forSerial serial: String?) {
        queue.sync {
            if let serial, !serial.isEmpty {
                entries.removeValue(forKey: serial)
                CardPINKeychain.remove(forSerial: serial)
            } else {
                entries.removeAll()
                CardPINKeychain.removeAll()
            }
        }
    }

    /// Wipe every remembered PIN immediately, the Keychain copy included.
    func clear() {
        queue.sync {
            entries.removeAll()
            CardPINKeychain.removeAll()
        }
    }

    /// Turn the persisted tier on or off. Turning it off removes the Keychain
    /// copies at once; turning it on keeps what is already held in memory
    /// (the next accepted PIN is written).
    func setPersistsAcrossRestarts(_ on: Bool) {
        queue.sync {
            Self.persistsAcrossRestarts = on
            if !on { CardPINKeychain.removeAll() }
        }
    }

    /// v7.1.1 (a tester's report) — change the cache duration AND immediately re-apply it to a
    /// PIN that is already held, so switching (e.g.) "1 minute" -> "Until I clear
    /// it" takes effect on the CURRENT PIN right away instead of waiting for the
    /// next decrypt to call store().
    ///
    /// Before this, `mode` only wrote UserDefaults; the held PIN's `expiry` was
    /// recomputed solely inside store(), so a changed duration didn't apply until
    /// the next successful verify. Settings binds its picker to this method now
    /// instead of the bare `mode` setter.
    ///
    /// Re-application rules:
    ///   - a timed mode  -> expiry = now + the new duration
    ///   - untilCleared  -> expiry = nil (held, no time limit)
    ///   - never         -> purge the held PIN (caching is off; a held secret
    ///                      shouldn't silently linger or revive on a later switch
    ///                      back to a timed mode without a fresh verify)
    /// If no PIN is currently held, this only persists the mode; the next store()
    /// applies it normally.
    func setMode(_ newMode: Mode) {
        queue.sync {
            Self.mode = newMode
            // 8.3.0 (9.2): the Keychain tier exists only under "Until PGPony
            // quits"; any other duration drops it.
            if newMode != .untilCleared { CardPINKeychain.removeAll() }
            guard !entries.isEmpty else { return }
            switch newMode {
            case .never:
                entries.removeAll()
            case .untilCleared, .untilDeviceLocks:
                for key in entries.keys { entries[key]?.expiry = nil }
            default:
                let expiry = newMode.seconds.flatMap { $0 > 0 ? Date().addingTimeInterval($0) : nil }
                for key in entries.keys { entries[key]?.expiry = expiry }
            }
        }
    }
}

// MARK: - Keychain tier of the card-PIN cache (8.3.0, 9.2)

/// The user PIN of a card, keyed by its serial, as a Keychain item behind
/// user-presence access control: reading it costs a Face ID / Touch ID (or
/// passcode) prompt from the system every time. This-device-only, never
/// synced, never exported in a backup. PW1 only, like the memory cache.
enum CardPINKeychain {
    private static let service = "app.pgpony.cardpin"

    private static var accessControl: SecAccessControl? {
        SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, nil)
    }

    static func save(_ pin: String, forSerial serial: String) {
        guard let access = accessControl, let data = pin.data(using: .utf8) else { return }
        remove(forSerial: serial)
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: serial,
            kSecAttrLabel as String: "PGPony hardware key PIN",
            kSecAttrAccessControl as String: access,
            kSecValueData as String: data,
        ]
        let status = SecItemAdd(add as CFDictionary, nil)
        if status != errSecSuccess {
            pgpDebugLog("DEBUG CardPINKeychain: save failed (\(status))")
        }
    }

    /// Every stored PIN by serial. One system authentication covers the
    /// call; an empty result means nothing stored, or the prompt declined.
    static func loadAll() -> [String: String] {
        let context = LAContext()
        context.localizedReason = String(localized: "Unlock the remembered hardware key PIN")
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let items = result as? [[String: Any]] else {
            if status != errSecItemNotFound { pgpDebugLog("DEBUG CardPINKeychain: load failed (\(status))") }
            return [:]
        }
        var out: [String: String] = [:]
        for item in items {
            guard let serial = item[kSecAttrAccount as String] as? String,
                  let data = item[kSecValueData as String] as? Data,
                  let pin = String(data: data, encoding: .utf8), !pin.isEmpty else { continue }
            out[serial] = pin
        }
        return out
    }

    static func remove(forSerial serial: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: serial,
        ]
        SecItemDelete(query as CFDictionary)
    }

    static func removeAll() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - Passphrase cache (v8.2.0 §5)

/// The passphrase twin of `CardPINCache`, colocated with it because they are the
/// same mechanism for two secret kinds: an in-memory, never-persisted cache
/// bounded only by the chosen duration. §4.6 posture decision (Kevin): software
/// key passphrases mirror the card-PIN posture rather than going to the Keychain,
/// because a passphrase written to disk beside its key would collapse two factors
/// into one. It reuses `CardPINCache.Mode` so the duration options and labels stay
/// identical across both caches.
///
/// - Keyed by key FINGERPRINT so each key is remembered separately. This is the
///   passphrase analogue of #24's per-serial keying: caching a single global
///   passphrase would replay key A's secret to key B, burning attempts on a key
///   the user never typed a passphrase for. Callers must therefore only apply a
///   cached passphrase to the key it was stored under.
/// - Held ONLY in memory, never written to disk / UserDefaults / Keychain (only
///   the mode enum persists). Wiped on: expiry, a wrong-passphrase clear, the
///   manual "Clear Remembered Passphrase" action, and app termination. NOT wiped
///   on backgrounding, matching the PIN cache (so the Mail -> share-sheet flow
///   keeps working).
final class PassphraseCache {
    static let shared = PassphraseCache()

    typealias Mode = CardPINCache.Mode
    private static let modeKey = "pgpony_passphrase_cache_mode"

    static var mode: Mode {
        get { Mode(rawValue: UserDefaults.standard.string(forKey: modeKey) ?? "") ?? .never }
        set { UserDefaults.standard.set(newValue.rawValue, forKey: modeKey) }
    }

    private struct Entry {
        var passphrase: String
        var expiry: Date?
        var storedAt: Date
    }
    private var entries: [String: Entry] = [:]
    private let queue = DispatchQueue(label: "app.pgpony.passphrasecache")
    private init() {
        // 8.3.0 (9.4): "Until the phone locks", the same boundary as the PIN cache.
        NotificationCenter.default.addObserver(
            forName: protectedDataWillBecomeUnavailable,
            object: nil, queue: nil
        ) { [weak self] _ in
            guard let self, Self.mode.endsOnDeviceLock else { return }
            self.clear()
        }
        // 8.3.0 (hardening): the opt-in clear on background.
        NotificationCenter.default.addObserver(
            forName: applicationDidEnterBackground,
            object: nil, queue: nil
        ) { [weak self] _ in
            guard let self, SecretCacheBackgroundPolicy.clearsOnBackground else { return }
            self.clear()
        }
    }

    enum CacheState: Equatable {
        case off
        case empty
        case untilCleared
        case untilDeviceLocks
        case counting(remaining: TimeInterval)
    }

    func state() -> CacheState {
        queue.sync {
            guard Self.mode != .never else { return .off }
            purgeExpiredLocked()
            guard let latest = entries.values.max(by: { $0.storedAt < $1.storedAt }) else {
                return .empty
            }
            if let expiry = latest.expiry {
                return .counting(remaining: expiry.timeIntervalSinceNow)
            }
            return Self.mode.endsOnDeviceLock ? .untilDeviceLocks : .untilCleared
        }
    }

    private func purgeExpiredLocked() {
        let now = Date()
        entries = entries.filter { $0.value.expiry.map { $0 > now } ?? true }
    }

    /// The remembered passphrase for THIS key, or nil. Never returns another
    /// key's passphrase.
    func passphrase(forFingerprint fingerprint: String?) -> String? {
        queue.sync {
            guard Self.mode != .never, let fingerprint, !fingerprint.isEmpty else { return nil }
            purgeExpiredLocked()
            return entries[fingerprint]?.passphrase
        }
    }

    /// Store a passphrase a key has just accepted, against that key's fingerprint.
    func store(_ passphrase: String, forFingerprint fingerprint: String?) {
        queue.sync {
            let mode = Self.mode
            guard mode != .never, !passphrase.isEmpty, let fingerprint, !fingerprint.isEmpty else { return }
            let expiry = mode.seconds.flatMap { $0 > 0 ? Date().addingTimeInterval($0) : nil }
            entries[fingerprint] = Entry(passphrase: passphrase, expiry: expiry, storedAt: Date())
        }
    }

    /// Drop one key's entry — after that key rejected its passphrase.
    func clearEntry(forFingerprint fingerprint: String?) {
        queue.sync {
            if let fingerprint, !fingerprint.isEmpty {
                entries.removeValue(forKey: fingerprint)
            } else {
                entries.removeAll()
            }
        }
    }

    /// Wipe every remembered passphrase immediately.
    func clear() {
        queue.sync { entries.removeAll() }
    }

    /// Change the duration and re-apply it to any held passphrase right away, so
    /// switching (e.g.) "1 minute" -> "Until PGPony quits" takes effect on the
    /// currently held secret instead of waiting for the next store(). Mirrors
    /// `CardPINCache.setMode`.
    func setMode(_ newMode: Mode) {
        queue.sync {
            Self.mode = newMode
            guard !entries.isEmpty else { return }
            switch newMode {
            case .never:
                entries.removeAll()
            case .untilCleared, .untilDeviceLocks:
                for key in entries.keys { entries[key]?.expiry = nil }
            default:
                let expiry = newMode.seconds.flatMap { $0 > 0 ? Date().addingTimeInterval($0) : nil }
                for key in entries.keys { entries[key]?.expiry = expiry }
            }
        }
    }
}
