// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// NFCCardTransport.swift
// PGPony
//
// v8.1.0 — §1. The CoreNFC implementation of CardTransport.
//
// This is the session code that lived inside OpenPGPCardService through 8.0.x,
// moved out essentially verbatim. Nothing about how PGPony talks to a card over
// NFC changed in the extraction — the same polling option, the same delegate
// dance, the same error mapping — because the whole point of doing the refactor
// before the USB work is that a regression here would be indistinguishable from
// a USB bug later.
//
// PROJECT SETUP (unchanged from 8.0.x): the "Near Field Communication Tag
// Reading" capability, `NFCReaderUsageDescription`, and the iso7816
// select-identifiers list (OpenPGP AID D2760001240103) in Info.plist. Without
// these the session fails immediately at `begin()`.
//
// SESSION SHAPE: NFC is modal and system-driven. `connect` blocks until the user
// presents a card or the OS gives up, the sheet stays on screen for the session,
// and `disconnect` chooses between the system's checkmark and its red error UI.
// Contrast USBSmartCardTransport, where none of that is true.

import Foundation
import CoreNFC

final class NFCCardTransport: NSObject, CardTransport {

    let kind: CardTransportKind = .nfc

    private var session: NFCTagReaderSession?
    private var tag: NFCISO7816Tag?
    private var connectContinuation: CheckedContinuation<NFCISO7816Tag, Error>?

    /// Whether this device has a usable NFC reader. False on every iPad and in
    /// the simulator, which is precisely why §1 requires the UI to ask this
    /// rather than assume from the device idiom.
    static var isAvailable: Bool { NFCTagReaderSession.readingAvailable }

    var isConnected: Bool { tag != nil }

    // MARK: Lifecycle

    func connect(alertMessage: String) async throws {
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
    }

    func updateStatus(_ message: String) {
        session?.alertMessage = message
    }

    func disconnect(success: Bool, message: String?) {
        if success {
            if let message { session?.alertMessage = message }
            session?.invalidate()
        } else {
            session?.invalidate(errorMessage: message ?? "Couldn't read the card.")
        }
        session = nil
        tag = nil
    }

    // MARK: Transceive

    func send(_ apdu: APDU) async throws -> APDUResponse {
        guard let tag else { throw OpenPGPCardError.sessionClosed }
        let command = NFCISO7816APDU(
            instructionClass: apdu.instructionClass,
            instructionCode: apdu.instructionCode,
            p1Parameter: apdu.p1Parameter,
            p2Parameter: apdu.p2Parameter,
            data: apdu.data,
            expectedResponseLength: apdu.expectedResponseLength
        )
        do {
            let (data, sw1, sw2) = try await tag.sendCommand(apdu: command)
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
}

// MARK: - NFCTagReaderSessionDelegate

extension NFCCardTransport: NFCTagReaderSessionDelegate {

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // No-op; polling starts automatically.
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        // If we were still waiting to connect, surface the failure to connect().
        //
        // A session that times out having NEVER seen a tag is a different event
        // from a card that went away mid-operation, even though CoreNFC reports
        // both as invalidation. `tag == nil` distinguishes them, and the
        // distinction is the whole substance of the original 8.0.1 report: a
        // USB-C-only key held against a phone produces exactly this — a silent
        // timeout — and the user has no way to learn that tapping was never
        // going to work. `.noCardDetected` says so.
        if tag == nil, let nfc = error as? NFCReaderError,
           nfc.code == .readerSessionInvalidationErrorSessionTimeout {
            resumeConnect(.failure(OpenPGPCardError.noCardDetected))
            return
        }
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
