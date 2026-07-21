// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import Foundation

/// Gated debug logging for the crypto / services layer.
///
/// Replaces the scattered ad-hoc console logging that used to run in every build. In
/// DEBUG builds this prints; in release builds it compiles to a no-op — and because
/// `message` is an `@autoclosure`, the string is never even evaluated in release, so
/// neither the log nor the work to build it runs in shipping builds.
///
/// Secret-bearing debug dumps — session keys, message keys, ECDH shared secrets,
/// Argon2-derived keys, private-scalar bytes — were **removed outright** rather than
/// routed through here. Key material must never be logged, not even in DEBUG.
#if DEBUG
@inline(__always)
func pgpDebugLog(_ message: @autoclosure () -> String) {
    Swift.print(message())
}
#else
@inline(__always)
func pgpDebugLog(_ message: @autoclosure () -> String) {}
#endif
