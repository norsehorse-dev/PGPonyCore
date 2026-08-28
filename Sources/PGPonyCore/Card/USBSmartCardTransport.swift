// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// USBSmartCardTransport.swift
// PGPony
//
// v8.1.0 — §1. USB-C smart card implementation of CardTransport.
//
// WHAT THE PLATFORM ALLOWS
// YubiKit exposes a smart card connection over the device USB-C port on iOS and
// iPadOS 16+. It requires the `com.apple.security.smartcard` entitlement, and
// that transport is restricted to smart card applications only — which the
// OpenPGP applet is, so sign / decrypt / auth / PIN verify / key generation are
// all in scope. FIDO, U2F and OTP applets over the same transport are not, and
// PGPony does not need them. Reachable hardware: USB-C-only keys (5C, 5C Nano,
// 5C NFC by contact) on iPhone 15 and later, and any USB-C iPad.
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │ BUILD GATING                                                            │
// │ The YubiKit-backed body is behind `#if canImport(YubiKit)`, so this file │
// │ compiles today with the package absent and reports the transport simply │
// │ unavailable. Add YubiKit via SPM plus the entitlement and the real path  │
// │ activates with no other change. That ordering is deliberate: the         │
// │ abstraction and the NFC extraction are verifiable on their own, and a    │
// │ dependency that cannot be resolved shouldn't block reviewing them.       │
// └─────────────────────────────────────────────────────────────────────────┘
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │ VERIFIED AGAINST YubiKit 4.7.0 (the pinned revision)                    │
// │                                                                         │
// │ 1. DELEGATE NAMES — confirmed. didConnectSmartCard: and                 │
// │    didDisconnectSmartCard:error: are correct. The NFC and Accessory     │
// │    callbacks are REQUIRED; the smart-card trio is @optional, which is   │
// │    why an earlier revision of this file compiled while missing          │
// │    didFailConnectingSmartCard: entirely. That is implemented now.       │
// │                                                                         │
// │ 3. 0x61xx CHAINING — confirmed handled by YubiKit itself                │
// │    (executeCommand:sendRemainingIns: / executeRecursiveCommand:). The   │
// │    card layer's own GET RESPONSE loop therefore never fires over this   │
// │    transport. Harmless: it is the same bytes either way, just assembled │
// │    one layer lower.                                                     │
// └─────────────────────────────────────────────────────────────────────────┘
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │ 2. STATUS-WORD MAPPING — confirmed.                                     │
// │                                                                         │
// │ `YKFAPDUError` is a subclass of `YKFSessionError` whose `code` IS the    │
// │ raw ISO 7816 status word. The parent's own codes are 0x01...0x09, so     │
// │ the CLASS is the discriminator rather than the value — see               │
// │ statusWord(from:) below.                                                 │
// │                                                                         │
// │ YubiKit also splits the response: `dataFromKeyResponse` /               │
// │ `statusCodeFromKeyResponse`, so the trailing SW is stripped from the     │
// │ data and 0x90 0x00 is reinstated here for the card layer.                │
// │                                                                         │
// │ 4. TIMEOUTS — YubiKit's default is 10 seconds                            │
// │ (`YKFSmartCardInterfaceDefaultTimeout`), which is shorter than a single  │
// │ touch-policy confirmation (15s) and far shorter than on-card RSA-4096    │
// │ key generation. Both are handled explicitly below.                       │
// └─────────────────────────────────────────────────────────────────────────┘
//
// SESSION SHAPE, AND WHY IT IS NOT NFC
// A USB session is persistent and can exist before the user asks for anything.
// It has no system-provided modal UI, so `updateStatus` is a no-op and progress
// has to be PGPony's own. It can be physically unplugged mid-APDU, which NFC
// models as a timeout and this transport must model as an abrupt disconnect.
// And because a verified PIN stays verified until the card is removed or reset,
// this is the transport that makes the §3c "remember the PIN" question real
// rather than theoretical — see that section before wiring PIN reuse to it.

import Foundation

#if canImport(YubiKit)
import YubiKit

final class USBSmartCardTransport: NSObject, CardTransport {

    let kind: CardTransportKind = .usbSmartCard

    /// Whether this build/device can use a USB-C smart card at all. Independent
    /// of whether a key is currently plugged in — §1 requires capability and
    /// attachment to be separate questions so the UI can say "plug in your key"
    /// rather than "not supported".
    /// The deployment target is already past the iOS 16 floor this transport
    /// needs, so capability here is a build-configuration question (is YubiKit
    /// linked?) rather than an OS-version one. The `#else` branch below answers
    /// false for a build without it.
    static var isAvailable: Bool { true }

    /// Whether a key is attached RIGHT NOW.
    ///
    /// YubiKit publishes no synchronous "is something plugged in" query, so this
    /// is maintained from the delegate callbacks. It starts false, which means
    /// the very first operation after launch with a key already attached falls
    /// back to a tap prompt until the connection is observed. Acceptable, and
    /// preferable to claiming an attachment that isn't there — but it is the
    /// reason `preferredKind()` treats a false here as "no opinion" rather than
    /// as "definitely nothing plugged in".
    /// Presence, from the observer that runs for the life of the app rather
    /// than for the life of a session. See USBKeyPresence.
    static var isKeyAttached: Bool { USBKeyPresence.shared.isKeyAttached }

    /// How long to wait for a key before giving up. A wired session has no
    /// system UI, so an unbounded wait is indistinguishable from a hang — and on
    /// iPad, where USB is the ONLY transport, that wait is the default path when
    /// nothing is plugged in. Long enough for someone to find and insert a key.
    static let connectTimeout: TimeInterval = 30

    /// Per-command timeout for ordinary APDUs. Above YubiKit's 10s default so a
    /// touch-policy key (15s for the user to touch) does not time out.
    static let commandTimeout: TimeInterval = 30

    /// On-card key generation only. RSA-4096 on-card generation is slow enough
    /// that anything shorter fails on hardware that is working correctly.
    static let keyGenerationTimeout: TimeInterval = 180

    private var connection: YKFSmartCardConnection?
    private var connectContinuation: CheckedContinuation<YKFSmartCardConnection, Error>?
    private var connectTimeoutTask: Task<Void, Never>?

    var isConnected: Bool { connection != nil }

    // MARK: Lifecycle

    func connect(alertMessage: String) async throws {
        // alertMessage is intentionally unused: there is no system sheet on this
        // transport. Progress and instructions are PGPony's own UI.
        guard Self.isAvailable else { throw OpenPGPCardError.usbSmartCardUnavailable }

        // v8.1.0 hotfix: borrow the connection from USBKeyPresence rather than
        // claiming YubiKit's delegate here.
        //
        // Claiming it per session was the cause of the reported bug. The
        // delegate is what tells us a key is present, so owning it only while a
        // session runs meant presence was unknowable at the one moment it
        // mattered: when deciding whether to use the cable at all.
        //
        // A key already in the port now resolves immediately instead of racing
        // a continuation that may not exist yet, and an empty port fails after
        // the timeout instead of appearing to hang.
        connection = try await USBKeyPresence.shared.connection(waitingUpTo: Self.connectTimeout)
    }

    func updateStatus(_ message: String) {
        // No system-provided UI on a wired session.
    }

    func disconnect(success: Bool, message: String?) {
        connectTimeoutTask?.cancel()
        connectTimeoutTask = nil
        // Deliberately NOT calling stopSmartCardConnection() or clearing the
        // delegate. Both belong to USBKeyPresence now and must outlive any one
        // session: stopping observation here is what made the next operation
        // blind to a key that never left the port.
        connection = nil
    }

    // MARK: Transceive

    func send(_ apdu: APDU) async throws -> APDUResponse {
        guard let connection else { throw OpenPGPCardError.sessionClosed }
        guard let interface = connection.smartCardInterface else {
            throw OpenPGPCardError.sessionClosed
        }

        // Extended-length responses are requested above the short-APDU ceiling;
        // RSA-4096 signatures (512 bytes) are the case that needs it.
        // YubiKit's default command timeout is 10 seconds
        // (`YKFSmartCardInterfaceDefaultTimeout`). That is fine for ordinary
        // APDUs but far too short for two cases:
        //
        //  - GENERATE ASYMMETRIC KEY PAIR (INS 0x47) in generate mode. On-card
        //    RSA-4096 generation runs well past a minute. With the default this
        //    would fail over USB while working over NFC, and read as a USB bug
        //    rather than a timeout.
        //  - Any operation on a key with a touch policy: the user has 15
        //    seconds to touch it, which alone exceeds two thirds of the default.
        //
        // Ordinary commands still get a bounded 30s so a wedged card does not
        // hang the UI for minutes.
        let timeout: TimeInterval = apdu.instructionCode == 0x47
            ? Self.keyGenerationTimeout
            : Self.commandTimeout

        let type: YKFAPDUType = apdu.expectedResponseLength > 256 ? .extended : .short
        guard let command = YKFAPDU(
            cla: apdu.instructionClass,
            ins: apdu.instructionCode,
            p1: apdu.p1Parameter,
            p2: apdu.p2Parameter,
            data: apdu.data,
            type: type
        ) else {
            throw OpenPGPCardError.malformedResponse
        }

        return try await withCheckedThrowingContinuation { cont in
            interface.executeCommand(command, timeout: timeout) { response, error in
                if let error {
                    // See item 2 in the header block. YubiKit reports a non-0x9000
                    // card status as an error with the status word as its code;
                    // the card layer needs those two bytes, not an error, because
                    // 0x63Cx carries the remaining-attempts count and 0x6A88 is
                    // the ordinary "this card has no KDF-DO" answer.
                    if let sw = Self.statusWord(from: error) {
                        cont.resume(returning: ([], sw.sw1, sw.sw2))
                    } else {
                        cont.resume(throwing: Self.mapUSBError(error))
                    }
                    return
                }
                // Success: YubiKit strips the trailing 0x9000 before handing the
                // body back, so it is reinstated for the card layer.
                cont.resume(returning: (Array(response ?? Data()), 0x90, 0x00))
            }
        }
    }

    /// Recover (sw1, sw2) from a card response that YubiKit reported as an error.
    ///
    /// Verified against YubiKit 4.7.0: `YKFAPDUError` is a subclass of
    /// `YKFSessionError` whose `code` IS the raw ISO 7816 status word —
    /// YubiKit's own `selectApplication:` does exactly `UInt16 statusCode =
    /// error.code`. The parent class's own codes are 0x01...0x09 (read timeout,
    /// touch timeout, connection lost), so **the class is the discriminator,
    /// not the value**. A range check on `.code` would be fragile in both
    /// directions: it would miss any status word outside the guessed range, and
    /// it would happily misread an unrelated error that landed inside it,
    /// fabricating a card status out of a transport failure.
    ///
    /// Returns nil for genuine transport failures, which then throw.
    static func statusWord(from error: Error) -> (sw1: UInt8, sw2: UInt8)? {
        let ns = error as NSError
        guard ns.isKind(of: YKFAPDUError.self) else { return nil }
        let code = ns.code
        guard code >= 0, code <= 0xFFFF else { return nil }
        return (UInt8((code >> 8) & 0xFF), UInt8(code & 0xFF))
    }

    /// Map a genuine transport failure. An unplug mid-operation is the wired
    /// analogue of NFC's "tag moved away", and gets the same `.connectionLost`
    /// so the card layer's existing recovery paths apply unchanged.
    static func mapUSBError(_ error: Error) -> OpenPGPCardError {
        if let already = error as? OpenPGPCardError { return already }
        return .connectionLost
    }
}

// MARK: - YKFManagerDelegate

// Selector spelling verified against YubiKit 4.7.0, the pinned revision.
// `didConnectNFC` / `didDisconnectNFC` / `didConnectAccessory` /
// `didDisconnectAccessory` are required; the smart-card methods are @optional.
extension USBSmartCardTransport: YKFManagerDelegate {

    func didConnectNFC(_ connection: YKFNFCConnection) {}
    func didDisconnectNFC(_ connection: YKFNFCConnection, error: Error?) {}
    func didConnectAccessory(_ connection: YKFAccessoryConnection) {}
    func didDisconnectAccessory(_ connection: YKFAccessoryConnection, error: Error?) {}

    func didConnectSmartCard(_ connection: YKFSmartCardConnection) {
        self.connection = connection
        resumeConnect(.success(connection))
    }

    func didDisconnectSmartCard(_ connection: YKFSmartCardConnection, error: Error?) {
        self.connection = nil
        // A disconnect while still waiting to connect is a failure to connect;
        // a disconnect mid-session surfaces on the next send() as sessionClosed.
        resumeConnect(.failure(OpenPGPCardError.connectionLost))
    }

    /// YubiKit reports a genuine failure to connect here.
    ///
    /// Without this the only signal was the 30-second timeout, so a key that
    /// failed to enumerate — wrong cable, unpowered hub, a key the OS refused —
    /// left the user staring at a spinner for half a minute before being told
    /// nothing was plugged in. Failing immediately with the real reason is
    /// better on both counts.
    func didFailConnectingSmartCard(_ error: Error) {
        resumeConnect(.failure(Self.mapUSBError(error)))
    }

    private func resumeConnect(_ result: Result<YKFSmartCardConnection, Error>) {
        connectTimeoutTask?.cancel()
        connectTimeoutTask = nil
        guard let cont = connectContinuation else { return }
        connectContinuation = nil
        switch result {
        case .success(let c): cont.resume(returning: c)
        case .failure(let e): cont.resume(throwing: e)
        }
    }
}

#else

// MARK: - YubiKit absent

/// Stand-in used until the YubiKit package is added. Reports the transport
/// unavailable so capability gating, the iPad no-NFC-affordance path, and the
/// error copy are all exercisable now — a build without YubiKit behaves exactly
/// like an iPhone with no USB support, which is a state the UI must handle
/// correctly regardless.
final class USBSmartCardTransport: CardTransport {

    let kind: CardTransportKind = .usbSmartCard

    static var isAvailable: Bool { false }
    static var isKeyAttached: Bool { false }

    var isConnected: Bool { false }

    func connect(alertMessage: String) async throws {
        throw OpenPGPCardError.usbSmartCardUnavailable
    }

    func send(_ apdu: APDU) async throws -> APDUResponse {
        throw OpenPGPCardError.usbSmartCardUnavailable
    }

    func updateStatus(_ message: String) {}
    func disconnect(success: Bool, message: String?) {}
}

#endif
