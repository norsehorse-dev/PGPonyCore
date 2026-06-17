// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import Foundation
import CommonCrypto

/// OpenPGP String-to-Key (S2K) passphrase-based key derivation (RFC 4880 §3.7).
///
/// Pure function: a passphrase + salt + parameters in, key bytes out. Supports
/// the simple/salted/iterated-salted variants over SHA-256 (default) and SHA-1
/// (legacy). Argon2-based S2K (RFC 9580) is handled separately by `Argon2Service`.
enum S2K {

    /// Derive `keySize` bytes from `passphrase` using the given S2K parameters.
    ///
    /// - Parameters:
    ///   - passphrase: the user passphrase (UTF-8 encoded internally).
    ///   - salt: the S2K salt (8 bytes for salted/iterated-salted; ignored for simple).
    ///   - s2kType: 0 = simple, 1 = salted, 3 = iterated-salted.
    ///   - hashAlgo: OpenPGP hash ID — 2 = SHA-1, 8 = SHA-256 (default for anything else).
    ///   - codedCount: the coded iteration count octet (type 3 only).
    ///   - keySize: number of key bytes to produce.
    static func deriveKey(
        passphrase: String,
        salt: [UInt8],
        s2kType: UInt8,
        hashAlgo: UInt8,
        codedCount: UInt8,
        keySize: Int
    ) -> [UInt8] {
        let passphraseBytes = Array(passphrase.utf8)
        let saltedPass = salt + passphraseBytes

        // Decode the iteration count for the iterated-salted variant (type 3).
        let iterCount: Int
        if s2kType == 3 {
            let expbias: UInt32 = 6
            let c = UInt32(codedCount)
            iterCount = Int((16 + (c & 15)) << ((c >> 4) + expbias))
        } else {
            iterCount = saltedPass.count  // simple/salted: hash the input once
        }

        var keyMaterial: [UInt8] = []
        var prefixCount = 0

        while keyMaterial.count < keySize {
            if hashAlgo == 2 {
                // SHA-1 (legacy)
                var ctx = CC_SHA1_CTX()
                CC_SHA1_Init(&ctx)

                if prefixCount > 0 {
                    let prefix = [UInt8](repeating: 0, count: prefixCount)
                    CC_SHA1_Update(&ctx, prefix, CC_LONG(prefix.count))
                }

                var bytesHashed = 0
                while bytesHashed < iterCount {
                    let chunk = min(saltedPass.count, iterCount - bytesHashed)
                    CC_SHA1_Update(&ctx, Array(saltedPass[0..<chunk]), CC_LONG(chunk))
                    bytesHashed += chunk
                }

                var hash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
                CC_SHA1_Final(&hash, &ctx)
                keyMaterial.append(contentsOf: hash)
            } else {
                // SHA-256 (default)
                var ctx = CC_SHA256_CTX()
                CC_SHA256_Init(&ctx)

                if prefixCount > 0 {
                    let prefix = [UInt8](repeating: 0, count: prefixCount)
                    CC_SHA256_Update(&ctx, prefix, CC_LONG(prefix.count))
                }

                var bytesHashed = 0
                while bytesHashed < iterCount {
                    let chunk = min(saltedPass.count, iterCount - bytesHashed)
                    CC_SHA256_Update(&ctx, Array(saltedPass[0..<chunk]), CC_LONG(chunk))
                    bytesHashed += chunk
                }

                var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
                CC_SHA256_Final(&hash, &ctx)
                keyMaterial.append(contentsOf: hash)
            }

            prefixCount += 1
        }

        return Array(keyMaterial.prefix(keySize))
    }
}
