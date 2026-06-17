// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import Foundation

/// Gated debug logging for the crypto core.
///
/// Prints in DEBUG builds; compiles to a no-op in release. Because `message` is an
/// `@autoclosure`, the debug string is never even built in a release build — zero cost,
/// nothing logged. Secret-bearing dumps (session/message/shared/derived keys, private
/// scalars) were removed outright rather than routed here: key material is never logged.
#if DEBUG
@inline(__always)
func pgpDebugLog(_ message: @autoclosure () -> String) {
    Swift.print(message())
}
#else
@inline(__always)
func pgpDebugLog(_ message: @autoclosure () -> String) {}
#endif
