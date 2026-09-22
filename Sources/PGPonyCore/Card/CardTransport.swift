// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CardTransport.swift
// PGPony
//
// v8.1.0 — §1. The transport-agnostic seam under the OpenPGP card layer.
//
// WHY THIS EXISTS
// Through 8.0.x, OpenPGPCardService WAS the NFC session: it owned an
// NFCTagReaderSession, built NFCISO7816APDUs, and implemented
// NFCTagReaderSessionDelegate, with the card protocol (SELECT, VERIFY, PSO:CDS,
// GENERATE, ...) interleaved through it. That was fine while NFC was the only
// way in. It stops being fine the moment iPad enters the picture: iPad has no
// NFC radio at all, so an iPad build on that structure ships with hardware keys
// dead on arrival. USB-C smart card is not a second feature bolted next to NFC;
// it is the thing that makes an iPad build meaningful.
//
// So the split here is deliberately at the APDU boundary and nowhere else.
// Everything above it — every command, every status-word interpretation, the
// KDF derivation from §4b, fingerprint matching, key generation — is card
// protocol and is identical regardless of how the bytes travel. Everything
// below it is session mechanics, and that is where NFC and USB genuinely
// differ. Drawing the line anywhere higher would mean two copies of the card
// protocol, which is exactly the bug factory this refactor exists to avoid.
//
// LIFECYCLE DIFFERS BETWEEN TRANSPORTS, AND CALLERS MUST NOT CARE.
// NFC is a short modal system-driven tap: the OS shows a sheet, the user
// presents the card, and the session dies on its own schedule. USB is a
// persistent connection that can already be attached before the user asks for
// anything, and can be physically yanked mid-APDU. The protocol below is shaped
// so both fit: `connect` may return instantly (USB, already attached) or block
// on a human (NFC, waiting for a tap), and `updateStatus`/`disconnect` are
// no-ops rather than errors on a transport with no system UI to drive.
//
// CORE NOTE: the app-side presentation helpers that lived at the bottom of this
// file (`CardConnectionCopy` — SwiftUI prompt copy and LocalizedStringKey
// variants) are not part of the core. The boundary is bytes-in / bytes-out; the
// wording of a tap prompt is application logic and stays in the app.

import Foundation

// MARK: - Transport kind

enum CardTransportKind: String, CaseIterable, Equatable {
    case nfc
    case usbSmartCard

    var displayName: String {
        switch self {
        case .nfc:          return String(localized: "NFC (tap)")
        case .usbSmartCard: return String(localized: "USB-C (plugged in)")
        }
    }

    /// Whether a session on this transport persists beyond a single operation.
    /// NFC sessions are torn down by the system after the modal sheet closes;
    /// a USB session lives until the key is unplugged. This is what makes a
    /// verified PIN stay verified on USB, and it is the hinge the §3c PIN
    /// persistence decision turns on.
    var isPersistent: Bool {
        switch self {
        case .nfc:          return false
        case .usbSmartCard: return true
        }
    }
}

// MARK: - APDU

/// A transport-neutral ISO 7816-4 command APDU.
///
/// The member names deliberately mirror `NFCISO7816APDU` so that the card layer
/// reads identically to the CoreNFC code it replaced and the 8.0.x diff stays
/// reviewable — this refactor must not change a single byte that reaches a card,
/// and matching labels is what makes that claim checkable by eye.
struct APDU: Equatable {
    let instructionClass: UInt8
    let instructionCode: UInt8
    let p1Parameter: UInt8
    let p2Parameter: UInt8
    let data: Data
    /// Expected response length (Le). Follows the CoreNFC convention: `-1`
    /// means "no Le field" (a Case 1/3 command), 256 means a short-APDU maximum,
    /// and anything above 256 requests an extended-length response.
    let expectedResponseLength: Int

    init(
        instructionClass: UInt8,
        instructionCode: UInt8,
        p1Parameter: UInt8,
        p2Parameter: UInt8,
        data: Data,
        expectedResponseLength: Int
    ) {
        self.instructionClass = instructionClass
        self.instructionCode = instructionCode
        self.p1Parameter = p1Parameter
        self.p2Parameter = p2Parameter
        self.data = data
        self.expectedResponseLength = expectedResponseLength
    }
}

/// The result of one command: response body plus the two status bytes. Status
/// words are returned rather than thrown — the card layer decides what 0x63Cx
/// or 0x6A88 means in context, and a transport has no business guessing.
typealias APDUResponse = (data: [UInt8], sw1: UInt8, sw2: UInt8)

// MARK: - Transport

protocol CardTransport: AnyObject {

    var kind: CardTransportKind { get }

    /// True once a card is connected and ready for commands.
    var isConnected: Bool { get }

    /// Establish a session and connect to a card.
    ///
    /// `alertMessage` drives system-provided UI where the transport has any
    /// (the CoreNFC sheet); transports without it ignore the value. This may
    /// return more or less immediately — a USB key that is already plugged in
    /// needs no human — or block until the user presents a card.
    func connect(alertMessage: String) async throws

    /// Send a single command and return its response verbatim.
    ///
    /// Implementations do NOT interpret status words and do NOT follow 0x61xx
    /// or 0x6Cxx chaining — that lives once in the card layer so both transports
    /// share one implementation of it.
    func send(_ apdu: APDU) async throws -> APDUResponse

    /// Update system-provided progress UI mid-session ("Signing…"). A no-op on
    /// transports with no such UI.
    func updateStatus(_ message: String)

    /// Tear the session down. `success` selects the system's success or failure
    /// presentation where one exists.
    func disconnect(success: Bool, message: String?)
}

// MARK: - Availability

/// What this device can actually do, right now.
///
/// §1 is explicit that this must be driven by real capability rather than by a
/// device or OS guess: iPad shows no NFC affordance because NFC genuinely is not
/// there, not because the code checked `UIDevice.userInterfaceIdiom`. The two
/// capabilities are independent — an iPhone 15 has both, an iPad has only USB,
/// an iPhone 12 has only NFC — so they are asked separately and never derived
/// from one another.
enum CardTransportAvailability {

    static var isNFCAvailable: Bool {
        NFCCardTransport.isAvailable
    }

    static var isUSBSmartCardAvailable: Bool {
        USBSmartCardTransport.isAvailable
    }

    static var isAnyAvailable: Bool {
        isNFCAvailable || isUSBSmartCardAvailable
    }

    static var availableKinds: [CardTransportKind] {
        var kinds: [CardTransportKind] = []
        if isUSBSmartCardAvailable { kinds.append(.usbSmartCard) }
        if isNFCAvailable { kinds.append(.nfc) }
        return kinds
    }

    /// CORE SEAM: the defaults key the host app writes the user's explicit
    /// transport choice to. In PGPony that key is owned by
    /// `CardConnectionMonitor` (a @MainActor ObservableObject, hence app-side);
    /// the core reads the same string, so a host that offers the setting gets
    /// the same behaviour and a host that does not simply never writes it.
    static let transportOverrideKey = "cardTransportOverride"

    /// Which transport to use when the user hasn't chosen one.
    ///
    /// A wired key wins over NFC whenever one is actually attached. §1: an
    /// iPhone with a USB-C key already plugged in should just use it rather than
    /// putting up a tap sheet the user then has to satisfy with a key that is
    /// already connected. Note this asks whether a key is ATTACHED, not merely
    /// whether the device supports USB — an iPhone 15 with nothing plugged in
    /// should still prompt for a tap.
    static func preferredKind() -> CardTransportKind? {
        // v8.1.0 §1 — an explicit choice wins, when the device can honour it.
        //
        // Read from UserDefaults rather than from CardConnectionMonitor: this is
        // called from every transport-selection and prompt-copy site, many of
        // them off the main actor, and the monitor is @MainActor. One stored
        // value, one source of truth, no actor hops in a hot path.
        //
        // An override for a transport this device does not have is IGNORED
        // rather than honoured into a dead end — someone who forced USB-C and
        // then restored onto a device without it should not find hardware keys
        // silently broken.
        if let raw = UserDefaults.standard.string(forKey: transportOverrideKey),
           let forced = CardTransportKind(rawValue: raw),
           availableKinds.contains(forced) {
            return forced
        }
        if USBSmartCardTransport.isKeyAttached { return .usbSmartCard }
        if isNFCAvailable { return .nfc }
        if isUSBSmartCardAvailable { return .usbSmartCard }
        return nil
    }

    /// Build a transport for `kind`, or the preferred one when unspecified.
    static func makeTransport(_ kind: CardTransportKind? = nil) -> CardTransport? {
        switch kind ?? preferredKind() {
        case .nfc:          return NFCCardTransport()
        case .usbSmartCard: return USBSmartCardTransport()
        case nil:           return nil
        }
    }
}

// MARK: - Copy (core subset)

/// CORE SEAM: the transport-aware strings the card layer itself needs.
///
/// The app's full `CardConnectionCopy` — button titles, icon names, the
/// transport picker flag, the PIN-prompt OTP hint and the `LocalizedStringKey`
/// variants SwiftUI's `Text` takes — is presentation and stays in the app. Only
/// these are reachable from `OpenPGPCardService` (the CoreNFC sheet message, the
/// in-session NFC status lines, and the transport-correct wording of a dropped
/// connection), so only these cross the boundary, verbatim.
enum CardConnectionCopy {

    /// Message for the system NFC sheet. Ignored on a wired session, which has
    /// no system UI — so this only ever renders when NFC is genuinely in play.
    static var connectPrompt: String {
        // 8.3.0 (9.1, the CubicS3 tester): name the spot and the hold. The
        // NFC antenna is the top edge behind the camera bar, the coupling
        // window is small, and moving the key mid-session is what turns a
        // working tap into a generic failure.
        String(localized: "Hold your hardware key flat against the top edge of your iPhone, behind the camera bar, and keep it still until the checkmark appears.")
    }

    /// 8.3.0 (9.1): the line every in-session status carries on NFC, so the
    /// "working" states keep saying the one thing that matters.
    static var holdStillLine: String {
        String(localized: "Keep the key still against the top edge.")
    }

    /// 8.3.0 (9.1): the status shown the moment the tag is read, before the
    /// PIN check and the operation, so the user knows to stop moving.
    static var keyFoundStatus: String {
        String(localized: "Key found. Keep it still while PGPony works…")
    }

    /// Pick the wording that matches the transport actually in use.
    static func prompt(nfc: String, usb: String) -> String {
        CardTransportAvailability.preferredKind() == .usbSmartCard ? usb : nfc
    }
}
