// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// USBKeyPresence.swift
// PGPony
//
// v8.1.0 §1 hotfix. Knowing a key is plugged in BEFORE deciding how to talk to it.
//
// THE BUG THIS EXISTS TO FIX
// Reported by two TestFlight testers within hours of the first build, and the
// cause is circular:
//
//   preferredKind() asks USBSmartCardTransport.isKeyAttached
//     -> isKeyAttached is only set inside didConnectSmartCard
//        -> which only fires after connect() assigns the YubiKit delegate
//           -> which only runs once USB has already been chosen
//
// So the flag could never be true at the moment it was consulted. On an iPhone
// the check fell through to NFC every time and asked the user to tap a key that
// was already plugged into the port. On iPad it happened to work, because with
// no NFC radio USB won by elimination rather than by detection.
//
// The original design made each transport claim YubiKitManager's delegate for
// the duration of its own session. That is tidy while a session is running and
// useless the rest of the time: outside a session nobody is the delegate, so
// nobody is listening for a key being plugged in. Presence is not session state,
// it is app state, and it needs an owner with app lifetime.
//
// WHAT THIS OWNS
// This object is the YubiKit delegate for the whole life of the process. It
// tracks whether a smart card is present and hands the live connection to
// whichever transport asks. USBSmartCardTransport no longer competes for the
// delegate slot; it borrows the connection.
//
// A second bug falls out of the same fix. A tester forced USB-C, pulled the key
// mid-operation, and watched the button sit in "loading" for thirty seconds
// before reporting failure. That was the connect timeout running to completion,
// because with no presence tracking the app could not tell "not plugged in yet"
// from "about to arrive". With real presence, that case fails immediately.

import Foundation

#if canImport(YubiKit)
import YubiKit

final class USBKeyPresence: NSObject, YKFManagerDelegate {

    static let shared = USBKeyPresence()

    /// Posted whenever a key is attached or removed, so UI can react without
    /// polling.
    static let didChangeNotification = Notification.Name("PGPonyUSBKeyPresenceDidChange")

    private let lock = NSLock()
    private var currentConnection: YKFSmartCardConnection?
    private var waiters: [CheckedContinuation<YKFSmartCardConnection, Error>] = []

    /// True while a smart card is physically present. Safe to read from any
    /// thread and, unlike the flag it replaces, meaningful before a session
    /// has been started.
    var isKeyAttached: Bool {
        lock.lock()
        defer { lock.unlock() }
        return currentConnection != nil
    }

    private override init() { super.init() }

    /// Begin observing. Called once at app launch.
    ///
    /// Idempotent, because the alternative is a second caller silently stealing
    /// the delegate slot, which is the class of bug this file exists to remove.
    func beginObserving() {
        guard YubiKitManager.shared.delegate !== self else { return }
        YubiKitManager.shared.delegate = self
        YubiKitManager.shared.startSmartCardConnection()
    }

    /// Re-arm observation after a disconnect or a failed connect.
    ///
    /// v8.1.0 build 3 — a tester found that a key plugged in BEFORE launch is
    /// detected and a key plugged in AFTER launch is not: he could sit on the
    /// PIN sheet, insert his 5C, and still be routed to NFC. The launch-time
    /// `startSmartCardConnection()` call with an empty port appears to settle
    /// into a state that never reports a later insertion, so after any
    /// disconnect or failure we start the session again. Guarded by a delay and
    /// by `currentConnection == nil` so a live connection is never disturbed
    /// and a hard failure cannot spin.
    ///
    /// This is a hypothesis fix: I cannot run YubiKit hardware here, and the
    /// tester's before/after-launch split is the evidence it rests on. If build
    /// 3 still misses mid-session insertion, this is the first place to look.
    private func rearmSoon() {
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            guard let self else { return }
            self.lock.lock()
            let idle = self.currentConnection == nil
            self.lock.unlock()
            guard idle, YubiKitManager.shared.delegate === self else { return }
            YubiKitManager.shared.stopSmartCardConnection()
            YubiKitManager.shared.startSmartCardConnection()
        }
    }

    /// The current connection, waiting up to `timeout` for one to appear.
    ///
    /// Returns immediately when a key is already attached, which is the common
    /// case and the one the old code could not see.
    func connection(waitingUpTo timeout: TimeInterval) async throws -> YKFSmartCardConnection {
        beginObserving()

        lock.lock()
        if let existing = currentConnection {
            lock.unlock()
            return existing
        }
        lock.unlock()

        return try await withThrowingTaskGroup(of: YKFSmartCardConnection.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { cont in
                    self.lock.lock()
                    if let existing = self.currentConnection {
                        self.lock.unlock()
                        cont.resume(returning: existing)
                        return
                    }
                    self.waiters.append(cont)
                    self.lock.unlock()
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                throw OpenPGPCardError.usbKeyNotAttached
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else {
                throw OpenPGPCardError.usbKeyNotAttached
            }
            return first
        }
    }

    // MARK: - YKFManagerDelegate

    // YubiKit's delegate covers all three transports, so the NFC and Lightning
    // accessory callbacks have to exist even though this object only cares
    // about the wired smart card. PGPony's NFC path is CoreNFC directly, not
    // YubiKit, so there is nothing to forward.
    func didConnectNFC(_ connection: YKFNFCConnection) {}
    func didDisconnectNFC(_ connection: YKFNFCConnection, error: Error?) {}
    func didConnectAccessory(_ connection: YKFAccessoryConnection) {}
    func didDisconnectAccessory(_ connection: YKFAccessoryConnection, error: Error?) {}

    func didConnectSmartCard(_ connection: YKFSmartCardConnection) {
        lock.lock()
        currentConnection = connection
        let pending = waiters
        waiters.removeAll()
        lock.unlock()

        pending.forEach { $0.resume(returning: connection) }
        NotificationCenter.default.post(name: Self.didChangeNotification, object: nil)
    }

    func didDisconnectSmartCard(_ connection: YKFSmartCardConnection, error: Error?) {
        lock.lock()
        currentConnection = nil
        lock.unlock()
        NotificationCenter.default.post(name: Self.didChangeNotification, object: nil)
        rearmSoon()
    }

    func didFailConnectingSmartCard(_ error: Error) {
        lock.lock()
        currentConnection = nil
        let pending = waiters
        waiters.removeAll()
        lock.unlock()

        pending.forEach { $0.resume(throwing: error) }
        NotificationCenter.default.post(name: Self.didChangeNotification, object: nil)
        rearmSoon()
    }
}

#else

/// Simulator and any build without YubiKit: no wired transport exists.
final class USBKeyPresence {
    static let shared = USBKeyPresence()
    static let didChangeNotification = Notification.Name("PGPonyUSBKeyPresenceDidChange")
    var isKeyAttached: Bool { false }
    private init() {}
    func beginObserving() {}
}

#endif
