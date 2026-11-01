// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// NWPairTransport.swift
// The pairing protocol's TCP connection on the Network framework: NWPairTransport wraps an
// NWConnection, NWPairListener opens a host window (one connection from the local network, then
// the listener stops), and PairProtocol.join(invite:) connects to an invite's addresses in order.
//
// The first LAN connection shows iOS's local network prompt, so the app's Info.plist needs
// NSLocalNetworkUsageDescription. Nothing is advertised, so no NSBonjourServices entry.

#if canImport(Network)
import Foundation
import Network

/// Resumes a continuation at most once, whichever callback gets there first.
final class PairOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false

    func take() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if done { return false }
        done = true
        return true
    }
}

public final class NWPairTransport: PairTransport, @unchecked Sendable {
    public let connection: NWConnection
    private let queue = DispatchQueue(label: "app.pgpony.pair.connection")
    private let closed = PairFlag()

    /// Wraps a connection that is not started yet; `start(timeout:)` starts it.
    public init(connection: NWConnection) {
        self.connection = connection
    }

    /// Opens a TCP connection to `address` and waits until it is ready. The endpoint is built
    /// from the address bytes, never from text, so nothing is ever looked up.
    public static func connect(to address: PairInvite.Address, timeout: Double = PairInvite.connectTimeout) async throws -> NWPairTransport {
        guard let port = NWEndpoint.Port(rawValue: address.port) else { throw PairError(.closed, "bad port") }
        let raw = address.bytes
        let host: NWEndpoint.Host
        if raw.count == 4, let v4 = IPv4Address(raw) {
            host = .ipv4(v4)
        } else if raw.count == 16, let v6 = IPv6Address(raw) {
            host = .ipv6(v6)
        } else {
            throw PairError(.closed, "not an IP address")
        }
        let t = NWPairTransport(connection: NWConnection(host: host, port: port, using: .tcp))
        try await t.start(timeout: timeout)
        return t
    }

    /// Starts the connection and waits until it is ready, fails, or `timeout` passes. A
    /// connection that is waiting (no route yet, or the local network prompt still open) keeps
    /// waiting until the timeout.
    public func start(timeout: Double) async throws {
        let connection = self.connection
        let queue = self.queue
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            let once = PairOnce()
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if once.take() { c.resume() }
                case .failed(let error):
                    if once.take() { c.resume(throwing: PairError(.closed, "\(error)")) }
                case .cancelled:
                    if once.take() { c.resume(throwing: PairError(.closed, "the connection was closed")) }
                default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                if once.take() {
                    connection.cancel()
                    c.resume(throwing: PairError(.timeout, "no answer from that address"))
                }
            }
        }
    }

    public func write(_ data: Data) async throws {
        if closed.get() { throw PairError(.closed, "the connection is closed") }
        let connection = self.connection
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    c.resume(throwing: PairError(.closed, "\(error)"))
                } else {
                    c.resume()
                }
            })
        }
    }

    public func read(exactly count: Int) async throws -> Data {
        var out = Data()
        while out.count < count {
            if closed.get() { throw PairError(.closed, "the connection is closed") }
            let want = count - out.count
            let connection = self.connection
            let chunk: Data = try await withCheckedThrowingContinuation { c in
                connection.receive(minimumIncompleteLength: 1, maximumLength: want) { data, _, isComplete, error in
                    if let data, !data.isEmpty {
                        c.resume(returning: data)
                    } else if let error {
                        c.resume(throwing: PairError(.closed, "\(error)"))
                    } else if isComplete {
                        c.resume(throwing: PairError(.closed, "the other side closed the connection"))
                    } else {
                        c.resume(returning: Data())
                    }
                }
            }
            out.append(chunk)
        }
        return out
    }

    public func close() {
        closed.set()
        connection.cancel()
    }
}

/// A host window: listens on an ephemeral port on every interface except cellular and takes one
/// connection from the local network. A connection from anywhere else is closed at once and the
/// window stays open; the listener stops as soon as an allowed connection arrives
/// (docs/PAIRING_PROTOCOL.md, section 1).
public final class NWPairListener: @unchecked Sendable {
    private let listener: NWListener
    private let subnets: [PairPeer.Subnet]
    private let queue = DispatchQueue(label: "app.pgpony.pair.listener")
    private let lock = NSLock()
    private var arrived: NWConnection?
    private var taken = false
    private var waiter: CheckedContinuation<NWConnection, Error>?
    private var ended = false

    /// `localSubnets` are the networks whose other devices may connect besides the always-local
    /// ranges; by default the subnets of this device's own interfaces.
    public init(localSubnets: [PairPeer.Subnet]? = nil) throws {
        let parameters = NWParameters.tcp
        parameters.prohibitedInterfaceTypes = [.cellular]
        listener = try NWListener(using: parameters, on: .any)
        subnets = localSubnets ?? PairPeer.interfaceSubnets()
        listener.newConnectionHandler = { [weak self] connection in self?.arrive(connection) }
    }

    /// Starts listening and returns the port the host screen and the invite show.
    public func start() async throws -> UInt16 {
        let listener = self.listener
        return try await withCheckedThrowingContinuation { (c: CheckedContinuation<UInt16, Error>) in
            let once = PairOnce()
            listener.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    if once.take() { c.resume(returning: listener.port?.rawValue ?? 0) }
                case .failed(let error):
                    if once.take() { c.resume(throwing: PairError(.closed, "\(error)")) }
                    self?.end()
                case .cancelled:
                    if once.take() { c.resume(throwing: PairError(.closed, "the window was closed")) }
                default:
                    break
                }
            }
            listener.start(queue: queue)
        }
    }

    private func arrive(_ connection: NWConnection) {
        // From outside the local network: closed before a byte is read, and the window stays open.
        guard PairPeer.isAllowed(endpoint: connection.endpoint, subnets: subnets) else {
            connection.cancel()
            return
        }
        lock.lock()
        if arrived != nil || ended {
            lock.unlock()
            connection.cancel()
            return
        }
        arrived = connection
        let w = waiter
        if w != nil {
            waiter = nil
            taken = true
        }
        lock.unlock()
        listener.cancel()
        w?.resume(returning: connection)
    }

    private func end() {
        lock.lock()
        ended = true
        let w = waiter
        waiter = nil
        lock.unlock()
        listener.cancel()
        w?.resume(throwing: PairError(.timeout, "the pairing window closed"))
    }

    /// Waits up to `timeout` seconds for the one connection, stops listening, and returns it
    /// started. Then run PairProtocol.host on it.
    public func accept(timeout: Double) async throws -> NWPairTransport {
        let connection: NWConnection = try await withCheckedThrowingContinuation { c in
            lock.lock()
            if let a = arrived, !taken {
                taken = true
                lock.unlock()
                c.resume(returning: a)
                return
            }
            if ended || taken || waiter != nil {
                lock.unlock()
                c.resume(throwing: PairError(.closed, "the pairing window closed"))
                return
            }
            waiter = c
            lock.unlock()
            queue.asyncAfter(deadline: .now() + timeout) { [weak self] in self?.end() }
        }
        let transport = NWPairTransport(connection: connection)
        try await transport.start(timeout: PairProtocol.frameTimeout)
        return transport
    }

    /// Closes the window; a pending accept throws.
    public func close() {
        end()
    }
}

extension PairPeer {
    /// `isAllowed` for a connection's remote endpoint; anything but an IP address is refused.
    public static func isAllowed(endpoint: NWEndpoint, subnets: [Subnet]) -> Bool {
        guard case .hostPort(let host, _) = endpoint else { return false }
        switch host {
        case .ipv4(let address):
            return isAllowed(address.rawValue, subnets: subnets)
        case .ipv6(let address):
            return isAllowed(address.rawValue, subnets: subnets)
        default:
            return false
        }
    }
}

extension PairProtocol {
    /// Joins the host an invite points at: its addresses in order, 3 seconds each, then phase 1
    /// with the host key checked against the invite.
    public static func join(invite: PairInvite) async throws -> PairAttempt {
        var connected: NWPairTransport?
        var last: Error = PairError(.closed, "no address answered")
        for address in invite.addresses {
            do {
                connected = try await NWPairTransport.connect(to: address)
                break
            } catch {
                last = error
            }
        }
        guard let transport = connected else { throw PairProtocol.wrap(last) }
        return try await join(transport: transport, expectedHostKeyHash: invite.hostKeyHash)
    }
}
#endif
