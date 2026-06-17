// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// Ed25519KeyGenerator.swift
// PGPony
//
// Generates Ed25519 signing keys with Cv25519 encryption subkeys
// in OpenPGP v4 packet format, compatible with GnuPG and ObjectivePGP.
//
// Uses Apple CryptoKit for key generation and constructs proper
// OpenPGP packets per RFC 4880 + draft-koch-eddsa-for-openpgp.

import Foundation
import CryptoKit
import CommonCrypto

// MARK: - Ed25519 Key Generator

struct Ed25519KeyGeneratorResult {
    let fingerprint: String
    let publicKeyData: Data   // Full OpenPGP transferable public key
    let privateKeyData: Data  // Full OpenPGP transferable secret key
    let armoredPublicKey: String
    let armoredPrivateKey: String
}

class Ed25519KeyGenerator {
    
    // Ed25519 curve OID: 1.3.6.1.4.1.11591.15.1
    private static let ed25519OID: [UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]
    
    // Cv25519 curve OID: 1.3.6.1.4.1.3029.1.5.1
    private static let cv25519OID: [UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]
    
    // Algorithm IDs
    private static let eddsaAlgorithm: UInt8 = 22   // EdDSA
    private static let ecdhAlgorithm: UInt8 = 18     // ECDH
    
    // S2K constants
    private static let s2kSaltLength = 8
    private static let s2kIteratedSalted: UInt8 = 3   // Iterated+Salted S2K
    private static let s2kHashSHA256: UInt8 = 8
    private static let s2kCipherAES128: UInt8 = 7
    private static let aes128BlockSize = 16
    private static let aes128KeySize = 16
    // GnuPG default coded count = 0x60 → decoded = (16 + (0 & 15)) << ((0x60 >> 4) + 6)
    // = 16 << 12 = 65536 bytes
    private static let s2kCodedCount: UInt8 = 0x60
    
    // MARK: - Generate
    
    static func generate(
        name: String,
        email: String,
        passphrase: String?,
        expirationInterval: TimeInterval?
    ) throws -> Ed25519KeyGeneratorResult {
        
        let creationTime = UInt32(Date().timeIntervalSince1970)
        
        // Generate Ed25519 signing key (primary)
        let signingKey = Curve25519.Signing.PrivateKey()
        let signingPublicBytes = Array(signingKey.publicKey.rawRepresentation)
        let signingPrivateBytes = Array(signingKey.rawRepresentation)
        
        // Generate Cv25519 encryption subkey
        let encryptionKey = Curve25519.KeyAgreement.PrivateKey()
        let encryptionPublicBytes = Array(encryptionKey.publicKey.rawRepresentation)
        let encryptionPrivateBytes = Array(encryptionKey.rawRepresentation)
        
        // Build primary public key packet body
        let primaryPubBody = buildEdDSAPublicKeyBody(
            creationTime: creationTime,
            publicKey: signingPublicBytes
        )
        
        // Calculate fingerprint (SHA-1 of 0x99 + 2-byte length + key body)
        let fingerprint = calculateV4Fingerprint(keyBody: primaryPubBody)
        let keyID = Array(fingerprint.suffix(8))
        
        // Build User ID
        let userID = "\(name) <\(email)>"
        let userIDBytes = Array(userID.utf8)
        
        // Build self-signature (type 0x13 = positive certification)
        let selfSignature = try buildCertificationSignature(
            signingKey: signingKey,
            primaryKeyBody: primaryPubBody,
            userIDBytes: userIDBytes,
            creationTime: creationTime,
            expirationInterval: expirationInterval,
            keyID: keyID
        )
        
        // Build encryption subkey packet body
        let subkeyPubBody = buildECDHPublicKeyBody(
            creationTime: creationTime,
            publicKey: encryptionPublicBytes
        )
        
        // Build subkey binding signature
        let subkeyBindingSig = try buildSubkeyBindingSignature(
            signingKey: signingKey,
            primaryKeyBody: primaryPubBody,
            subkeyBody: subkeyPubBody,
            creationTime: creationTime,
            keyID: keyID
        )
        
        // Assemble transferable public key
        var publicKeyPackets = Data()
        publicKeyPackets.append(buildPacket(tag: 6, body: Data(primaryPubBody)))  // Public-Key
        publicKeyPackets.append(buildPacket(tag: 13, body: Data(userIDBytes)))     // User ID
        publicKeyPackets.append(buildPacket(tag: 2, body: Data(selfSignature)))    // Signature
        publicKeyPackets.append(buildPacket(tag: 14, body: Data(subkeyPubBody)))   // Public-Subkey
        publicKeyPackets.append(buildPacket(tag: 2, body: Data(subkeyBindingSig))) // Signature
        
        // Build secret key bodies
        let primarySecretBody = buildEdDSASecretKeyBody(
            publicBody: primaryPubBody,
            privateKey: signingPrivateBytes,
            passphrase: passphrase
        )
        
        let subkeySecretBody = buildECDHSecretKeyBody(
            publicBody: subkeyPubBody,
            privateKey: encryptionPrivateBytes,
            passphrase: passphrase
        )
        
        // Assemble transferable secret key
        var secretKeyPackets = Data()
        secretKeyPackets.append(buildPacket(tag: 5, body: Data(primarySecretBody)))  // Secret-Key
        secretKeyPackets.append(buildPacket(tag: 13, body: Data(userIDBytes)))        // User ID
        secretKeyPackets.append(buildPacket(tag: 2, body: Data(selfSignature)))       // Signature
        secretKeyPackets.append(buildPacket(tag: 7, body: Data(subkeySecretBody)))    // Secret-Subkey
        secretKeyPackets.append(buildPacket(tag: 2, body: Data(subkeyBindingSig)))    // Signature
        
        // Armor
        let armoredPublic = armorData(publicKeyPackets, type: .publicKey)
        let armoredSecret = armorData(secretKeyPackets, type: .secretKey)
        
        // Format fingerprint as hex string
        let fingerprintHex = fingerprint.map { String(format: "%02x", $0) }.joined()
        
        return Ed25519KeyGeneratorResult(
            fingerprint: fingerprintHex,
            publicKeyData: publicKeyPackets,
            privateKeyData: secretKeyPackets,
            armoredPublicKey: armoredPublic,
            armoredPrivateKey: armoredSecret
        )
    }
    
    // MARK: - Public Key Bodies
    
    /// Build EdDSA (Ed25519) public key packet body
    static func buildEdDSAPublicKeyBody(creationTime: UInt32, publicKey: [UInt8]) -> [UInt8] {
        var body: [UInt8] = []
        body.append(4)  // Version 4
        body.append(contentsOf: creationTime.bigEndianBytes)
        body.append(eddsaAlgorithm)  // Algorithm: EdDSA (22)
        
        // OID
        body.append(UInt8(ed25519OID.count))
        body.append(contentsOf: ed25519OID)
        
        // Public key MPI: 0x40 prefix + 32 bytes = 263 bits
        let qBytes: [UInt8] = [0x40] + publicKey
        let qBits = UInt16(qBytes.count * 8 - countLeadingZeroBits(qBytes))
        body.append(contentsOf: qBits.bigEndianBytes)
        body.append(contentsOf: qBytes)
        
        return body
    }
    
    /// Build ECDH (Cv25519) public key packet body
    static func buildECDHPublicKeyBody(creationTime: UInt32, publicKey: [UInt8]) -> [UInt8] {
        var body: [UInt8] = []
        body.append(4)  // Version 4
        body.append(contentsOf: creationTime.bigEndianBytes)
        body.append(ecdhAlgorithm)  // Algorithm: ECDH (18)
        
        // OID
        body.append(UInt8(cv25519OID.count))
        body.append(contentsOf: cv25519OID)
        
        // Public key MPI: 0x40 prefix + 32 bytes
        let qBytes: [UInt8] = [0x40] + publicKey
        let qBits = UInt16(qBytes.count * 8 - countLeadingZeroBits(qBytes))
        body.append(contentsOf: qBits.bigEndianBytes)
        body.append(contentsOf: qBytes)
        
        // KDF parameters: hash=SHA256, cipher=AES128
        body.append(3)     // Length of KDF params
        body.append(0x01)  // Reserved (always 1)
        body.append(8)     // SHA256
        body.append(7)     // AES128
        
        return body
    }
    
    // MARK: - Secret Key Bodies
    
    private static func buildEdDSASecretKeyBody(
        publicBody: [UInt8],
        privateKey: [UInt8],
        passphrase: String?
    ) -> [UInt8] {
        var body = publicBody
        
        if let passphrase = passphrase, !passphrase.isEmpty {
            // S2K-protected secret key
            body.append(contentsOf: buildS2KProtectedSecretMPI(
                privateKey: privateKey,
                passphrase: passphrase
            ))
        } else {
            // Unprotected
            body.append(0)  // S2K usage: 0 = not encrypted
            
            // Secret key MPI
            let dBits = UInt16(privateKey.count * 8 - countLeadingZeroBits(privateKey))
            body.append(contentsOf: dBits.bigEndianBytes)
            body.append(contentsOf: privateKey)
            
            // Two-octet checksum of all secret MPI bytes (MPI length + MPI data)
            let mpiData: [UInt8] = dBits.bigEndianBytes + privateKey
            let checksum = mpiData.reduce(UInt16(0)) { ($0 &+ UInt16($1)) }
            body.append(contentsOf: checksum.bigEndianBytes)
        }
        
        return body
    }
    
    private static func buildECDHSecretKeyBody(
        publicBody: [UInt8],
        privateKey: [UInt8],
        passphrase: String?
    ) -> [UInt8] {
        var body = publicBody
        
        if let passphrase = passphrase, !passphrase.isEmpty {
            // S2K-protected secret key
            body.append(contentsOf: buildS2KProtectedSecretMPI(
                privateKey: privateKey,
                passphrase: passphrase
            ))
        } else {
            // Unprotected
            body.append(0)  // S2K usage: 0 = not encrypted
            
            // Secret key MPI
            let dBits = UInt16(privateKey.count * 8 - countLeadingZeroBits(privateKey))
            body.append(contentsOf: dBits.bigEndianBytes)
            body.append(contentsOf: privateKey)
            
            // Two-octet checksum of all secret MPI bytes
            let mpiData: [UInt8] = dBits.bigEndianBytes + privateKey
            let checksum = mpiData.reduce(UInt16(0)) { ($0 &+ UInt16($1)) }
            body.append(contentsOf: checksum.bigEndianBytes)
        }
        
        return body
    }
    
    // MARK: - S2K Passphrase Protection
    
    /// Build S2K-protected secret key material per RFC 4880 §3.7.1.3
    /// Uses Iterated+Salted S2K (type 3) with SHA256 and AES-128 CFB
    private static func buildS2KProtectedSecretMPI(
        privateKey: [UInt8],
        passphrase: String
    ) -> [UInt8] {
        var result: [UInt8] = []
        
        // S2K usage: 254 = SHA-1 checksum on plaintext (modern convention)
        result.append(254)
        
        // Symmetric cipher: AES-128
        result.append(s2kCipherAES128)
        
        // S2K specifier
        result.append(s2kIteratedSalted)  // Type 3: Iterated+Salted
        result.append(s2kHashSHA256)       // Hash: SHA-256
        
        // 8-byte random salt
        var salt = [UInt8](repeating: 0, count: s2kSaltLength)
        _ = SecRandomCopyBytes(kSecRandomDefault, s2kSaltLength, &salt)
        result.append(contentsOf: salt)
        
        // Coded count byte (0x60 = 65536 iterations, GnuPG default)
        result.append(s2kCodedCount)
        
        // Generate AES-128 key from passphrase via S2K
        let derivedKey = deriveS2KKey(
            passphrase: passphrase,
            salt: salt,
            codedCount: s2kCodedCount,
            keySize: aes128KeySize
        )
        
        // Build plaintext: MPI data + SHA-1 hash of MPI data
        var plaintext: [UInt8] = []
        let dBits = UInt16(privateKey.count * 8 - countLeadingZeroBits(privateKey))
        plaintext.append(contentsOf: dBits.bigEndianBytes)
        plaintext.append(contentsOf: privateKey)
        
        // SHA-1 checksum of plaintext (for S2K usage byte 254)
        var sha1Hash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CC_SHA1(plaintext, CC_LONG(plaintext.count), &sha1Hash)
        plaintext.append(contentsOf: sha1Hash)
        
        // Random IV for AES-128 CFB
        var iv = [UInt8](repeating: 0, count: aes128BlockSize)
        _ = SecRandomCopyBytes(kSecRandomDefault, aes128BlockSize, &iv)
        result.append(contentsOf: iv)
        
        // Encrypt with AES-128 CFB (no padding — OpenPGP CFB is byte-aligned)
        let ciphertext = aesCFBEncrypt(plaintext: plaintext, key: derivedKey, iv: iv)
        result.append(contentsOf: ciphertext)
        
        return result
    }
    
    /// Derive encryption key from passphrase using Iterated+Salted S2K (RFC 4880 §3.7.1.3)
    private static func deriveS2KKey(
        passphrase: String,
        salt: [UInt8],
        codedCount: UInt8,
        keySize: Int
    ) -> [UInt8] {
        // Decode the coded count to actual byte count
        let expbias: UInt32 = 6
        let c = UInt32(codedCount)
        let count = Int((16 + (c & 15)) << ((c >> 4) + expbias))
        
        let passphraseBytes = Array(passphrase.utf8)
        let saltedPass = salt + passphraseBytes
        
        // Hash repeatedly until we have enough key material
        var keyMaterial: [UInt8] = []
        var prefixCount = 0
        
        while keyMaterial.count < keySize {
            var ctx = CC_SHA256_CTX()
            CC_SHA256_Init(&ctx)
            
            // Prefix with zero bytes for multi-block derivation
            if prefixCount > 0 {
                let prefix = [UInt8](repeating: 0, count: prefixCount)
                CC_SHA256_Update(&ctx, prefix, CC_LONG(prefix.count))
            }
            
            // Hash salt+passphrase repeatedly until count bytes processed
            var bytesHashed = 0
            while bytesHashed < count {
                let chunk = min(saltedPass.count, count - bytesHashed)
                CC_SHA256_Update(&ctx, Array(saltedPass[0..<chunk]), CC_LONG(chunk))
                bytesHashed += chunk
            }
            
            var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            CC_SHA256_Final(&hash, &ctx)
            keyMaterial.append(contentsOf: hash)
            
            prefixCount += 1
        }
        
        return Array(keyMaterial.prefix(keySize))
    }
    
    /// AES-128 CFB encryption (OpenPGP style — no padding, byte-aligned)
    private static func aesCFBEncrypt(plaintext: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8] {
        var ciphertext = [UInt8](repeating: 0, count: plaintext.count)
        var currentIV = iv
        
        // Process in 16-byte blocks
        var offset = 0
        while offset < plaintext.count {
            // Encrypt the IV/feedback to get keystream block
            var encryptedBlock = [UInt8](repeating: 0, count: aes128BlockSize)
            var outLen: Int = 0
            
            // Use CommonCrypto for AES-ECB (one block) to get keystream
            var cryptorRef: CCCryptorRef?
            CCCryptorCreate(
                CCOperation(kCCEncrypt),
                CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionECBMode),
                key, key.count,
                nil,
                &cryptorRef
            )
            
            if let cryptor = cryptorRef {
                CCCryptorUpdate(
                    cryptor,
                    currentIV, aes128BlockSize,
                    &encryptedBlock, aes128BlockSize,
                    &outLen
                )
                CCCryptorRelease(cryptor)
            }
            
            // XOR plaintext with keystream
            let blockEnd = min(offset + aes128BlockSize, plaintext.count)
            for i in offset..<blockEnd {
                ciphertext[i] = plaintext[i] ^ encryptedBlock[i - offset]
            }
            
            // Feedback: next IV = ciphertext block
            let blockLen = blockEnd - offset
            if blockLen == aes128BlockSize {
                currentIV = Array(ciphertext[offset..<blockEnd])
            } else {
                // Last partial block — fill remainder from previous IV
                currentIV = Array(ciphertext[offset..<blockEnd]) + Array(currentIV[blockLen...])
            }
            
            offset += aes128BlockSize
        }
        
        return ciphertext
    }
    
    // MARK: - Signatures
    
    /// Build a v4 positive certification signature (0x13) binding user ID to primary key
    private static func buildCertificationSignature(
        signingKey: Curve25519.Signing.PrivateKey,
        primaryKeyBody: [UInt8],
        userIDBytes: [UInt8],
        creationTime: UInt32,
        expirationInterval: TimeInterval?,
        keyID: [UInt8]
    ) throws -> [UInt8] {
        
        // Build hashed subpackets
        var hashedSubpackets = Data()
        
        // Signature creation time (subpacket type 2)
        hashedSubpackets.append(buildSubpacket(type: 2, data: creationTime.bigEndianBytes))
        
        // Key flags (subpacket type 27): certify (0x01) + sign (0x02)
        hashedSubpackets.append(buildSubpacket(type: 27, data: [0x03]))
        
        // Preferred symmetric algorithms (subpacket type 11): AES256, AES192, AES128
        hashedSubpackets.append(buildSubpacket(type: 11, data: [9, 8, 7]))
        
        // Preferred hash algorithms (subpacket type 21): SHA512, SHA384, SHA256
        hashedSubpackets.append(buildSubpacket(type: 21, data: [10, 9, 8]))
        
        // Preferred compression (subpacket type 22): ZLIB, BZip2, ZIP
        hashedSubpackets.append(buildSubpacket(type: 22, data: [2, 3, 1]))
        
        // Features (subpacket type 30): MDC (0x01)
        hashedSubpackets.append(buildSubpacket(type: 30, data: [0x01]))
        
        // Key expiration if set (subpacket type 9)
        if let expInterval = expirationInterval {
            let expSeconds = UInt32(expInterval)
            hashedSubpackets.append(buildSubpacket(type: 9, data: expSeconds.bigEndianBytes))
        }
        
        // Build unhashed subpackets
        var unhashedSubpackets = Data()
        
        // Issuer key ID (subpacket type 16)
        unhashedSubpackets.append(buildSubpacket(type: 16, data: keyID))
        
        // Compute signature hash
        let hashData = buildCertificationHashData(
            primaryKeyBody: primaryKeyBody,
            userIDBytes: userIDBytes,
            signatureType: 0x13,
            hashedSubpackets: Array(hashedSubpackets)
        )
        
        let digest = SHA256.hash(data: hashData)
        let digestBytes = Array(digest)
        
        // OpenPGP EdDSA: sign the SHA-256 digest, not the raw data
        // Per draft-koch-eddsa-for-openpgp: "a digest of the message is used as input"
        let signature = try signingKey.signature(for: Data(digestBytes))
        let sigBytes = Array(signature)
        
        // Build signature packet body
        var sigBody: [UInt8] = []
        sigBody.append(4)  // Version
        sigBody.append(0x13)  // Positive certification
        sigBody.append(eddsaAlgorithm)  // Public-key algorithm: EdDSA
        sigBody.append(8)  // Hash algorithm: SHA256
        
        // Hashed subpacket length + data
        let hashedLen = UInt16(hashedSubpackets.count)
        sigBody.append(contentsOf: hashedLen.bigEndianBytes)
        sigBody.append(contentsOf: hashedSubpackets)
        
        // Unhashed subpacket length + data
        let unhashedLen = UInt16(unhashedSubpackets.count)
        sigBody.append(contentsOf: unhashedLen.bigEndianBytes)
        sigBody.append(contentsOf: unhashedSubpackets)
        
        // Left 16 bits of hash
        sigBody.append(digestBytes[0])
        sigBody.append(digestBytes[1])
        
        // EdDSA signature: two MPIs (R and S, each 32 bytes)
        let rBytes = Array(sigBytes[0..<32])
        let sBytes = Array(sigBytes[32..<64])
        
        let rBits = UInt16(rBytes.count * 8 - countLeadingZeroBits(rBytes))
        sigBody.append(contentsOf: rBits.bigEndianBytes)
        sigBody.append(contentsOf: rBytes)
        
        let sBits = UInt16(sBytes.count * 8 - countLeadingZeroBits(sBytes))
        sigBody.append(contentsOf: sBits.bigEndianBytes)
        sigBody.append(contentsOf: sBytes)
        
        return sigBody
    }
    
    /// Build a v4 subkey binding signature (0x18)
    private static func buildSubkeyBindingSignature(
        signingKey: Curve25519.Signing.PrivateKey,
        primaryKeyBody: [UInt8],
        subkeyBody: [UInt8],
        creationTime: UInt32,
        keyID: [UInt8]
    ) throws -> [UInt8] {
        
        var hashedSubpackets = Data()
        
        // Signature creation time
        hashedSubpackets.append(buildSubpacket(type: 2, data: creationTime.bigEndianBytes))
        
        // Key flags: encrypt communications (0x04) + encrypt storage (0x08)
        hashedSubpackets.append(buildSubpacket(type: 27, data: [0x0C]))
        
        var unhashedSubpackets = Data()
        unhashedSubpackets.append(buildSubpacket(type: 16, data: keyID))
        
        // Compute hash
        let hashData = buildSubkeyBindingHashData(
            primaryKeyBody: primaryKeyBody,
            subkeyBody: subkeyBody,
            signatureType: 0x18,
            hashedSubpackets: Array(hashedSubpackets)
        )
        
        let digest = SHA256.hash(data: hashData)
        let digestBytes = Array(digest)
        
        // OpenPGP EdDSA: sign the SHA-256 digest, not the raw data
        let signature = try signingKey.signature(for: Data(digestBytes))
        let sigBytes = Array(signature)
        
        var sigBody: [UInt8] = []
        sigBody.append(4)
        sigBody.append(0x18)  // Subkey binding
        sigBody.append(eddsaAlgorithm)
        sigBody.append(8)  // SHA256
        
        let hashedLen = UInt16(hashedSubpackets.count)
        sigBody.append(contentsOf: hashedLen.bigEndianBytes)
        sigBody.append(contentsOf: hashedSubpackets)
        
        let unhashedLen = UInt16(unhashedSubpackets.count)
        sigBody.append(contentsOf: unhashedLen.bigEndianBytes)
        sigBody.append(contentsOf: unhashedSubpackets)
        
        sigBody.append(digestBytes[0])
        sigBody.append(digestBytes[1])
        
        let rBytes = Array(sigBytes[0..<32])
        let sBytes = Array(sigBytes[32..<64])
        
        let rBits = UInt16(rBytes.count * 8 - countLeadingZeroBits(rBytes))
        sigBody.append(contentsOf: rBits.bigEndianBytes)
        sigBody.append(contentsOf: rBytes)
        
        let sBits = UInt16(sBytes.count * 8 - countLeadingZeroBits(sBytes))
        sigBody.append(contentsOf: sBits.bigEndianBytes)
        sigBody.append(contentsOf: sBytes)
        
        return sigBody
    }
    
    // MARK: - Hash Data Construction
    
    /// Build hash data for certification signature (type 0x10-0x13)
    private static func buildCertificationHashData(
        primaryKeyBody: [UInt8],
        userIDBytes: [UInt8],
        signatureType: UInt8,
        hashedSubpackets: [UInt8]
    ) -> Data {
        var data = Data()
        
        // Primary key: 0x99 + 2-byte length + key body
        let keyLen = UInt16(primaryKeyBody.count)
        data.append(0x99)
        data.append(contentsOf: keyLen.bigEndianBytes)
        data.append(contentsOf: primaryKeyBody)
        
        // User ID: 0xB4 + 4-byte length + UID bytes
        let uidLen = UInt32(userIDBytes.count)
        data.append(0xB4)
        data.append(contentsOf: uidLen.bigEndianBytes)
        data.append(contentsOf: userIDBytes)
        
        // Signature trailer
        data.append(contentsOf: buildSignatureTrailer(
            signatureType: signatureType,
            hashedSubpackets: hashedSubpackets
        ))
        
        return data
    }
    
    /// Build hash data for subkey binding signature (type 0x18)
    private static func buildSubkeyBindingHashData(
        primaryKeyBody: [UInt8],
        subkeyBody: [UInt8],
        signatureType: UInt8,
        hashedSubpackets: [UInt8]
    ) -> Data {
        var data = Data()
        
        // Primary key
        let keyLen = UInt16(primaryKeyBody.count)
        data.append(0x99)
        data.append(contentsOf: keyLen.bigEndianBytes)
        data.append(contentsOf: primaryKeyBody)
        
        // Subkey
        let subLen = UInt16(subkeyBody.count)
        data.append(0x99)
        data.append(contentsOf: subLen.bigEndianBytes)
        data.append(contentsOf: subkeyBody)
        
        // Signature trailer
        data.append(contentsOf: buildSignatureTrailer(
            signatureType: signatureType,
            hashedSubpackets: hashedSubpackets
        ))
        
        return data
    }
    
    /// Build the v4 signature trailer that gets appended before hashing
    private static func buildSignatureTrailer(
        signatureType: UInt8,
        hashedSubpackets: [UInt8]
    ) -> [UInt8] {
        var trailer: [UInt8] = []
        
        // Signature packet header for hashing
        trailer.append(4)  // Version
        trailer.append(signatureType)
        trailer.append(eddsaAlgorithm)  // Public-key algorithm
        trailer.append(8)  // Hash algorithm (SHA256)
        
        let hashedLen = UInt16(hashedSubpackets.count)
        trailer.append(contentsOf: hashedLen.bigEndianBytes)
        trailer.append(contentsOf: hashedSubpackets)
        
        // V4 final trailer: version (4) + 0xFF + 4-byte count of hashed data
        // Count = version(1) + sigType(1) + pubAlgo(1) + hashAlgo(1) + hashedLen(2) + hashedSubpackets
        let totalHashedLen = UInt32(6 + hashedSubpackets.count)
        trailer.append(4)
        trailer.append(0xFF)
        trailer.append(contentsOf: totalHashedLen.bigEndianBytes)
        
        return trailer
    }
    
    // MARK: - Packet Building
    
    /// Build an OpenPGP packet with new-format header (RFC 4880 §4.2.2)
    private static func buildPacket(tag: UInt8, body: Data) -> Data {
        var packet = Data()
        
        // New-format CTB: bit 7 = 1, bit 6 = 1, bits 5-0 = tag
        packet.append(0xC0 | tag)
        
        let len = body.count
        if len < 192 {
            // One-octet length
            packet.append(UInt8(len))
        } else if len < 8384 {
            // Two-octet length
            let adjusted = len - 192
            packet.append(UInt8((adjusted >> 8) + 192))
            packet.append(UInt8(adjusted & 0xFF))
        } else {
            // Five-octet length
            packet.append(0xFF)
            packet.append(UInt8((len >> 24) & 0xFF))
            packet.append(UInt8((len >> 16) & 0xFF))
            packet.append(UInt8((len >> 8) & 0xFF))
            packet.append(UInt8(len & 0xFF))
        }
        
        packet.append(body)
        return packet
    }
    
    /// Build a signature subpacket
    private static func buildSubpacket(type: UInt8, data: [UInt8]) -> Data {
        var subpacket = Data()
        let totalLen = data.count + 1  // +1 for the type byte
        
        if totalLen < 192 {
            subpacket.append(UInt8(totalLen))
        } else if totalLen < 16576 {
            let adjusted = totalLen - 192
            subpacket.append(UInt8((adjusted >> 8) + 192))
            subpacket.append(UInt8(adjusted & 0xFF))
        }
        
        subpacket.append(type)
        subpacket.append(contentsOf: data)
        return subpacket
    }
    
    // MARK: - Fingerprint
    
    /// Calculate V4 fingerprint: SHA-1(0x99 + 2-byte key body length + key body)
    static func calculateV4Fingerprint(keyBody: [UInt8]) -> [UInt8] {
        var data: [UInt8] = []
        data.append(0x99)
        let len = UInt16(keyBody.count)
        data.append(contentsOf: len.bigEndianBytes)
        data.append(contentsOf: keyBody)
        
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CC_SHA1(data, CC_LONG(data.count), &hash)
        return hash
    }

    // MARK: - B1: On-card key parts
    //
    // Build the OpenPGP public-key packet body + v4 fingerprint for a key the CARD
    // generated, from the raw 32-byte point it returned (leading 0x40 already
    // stripped by OpenPGPCardService.generateKeyPair). This reuses the exact body
    // layout used for software keygen, so the fingerprint matches gpg byte-for-byte
    // (verified against gpg-generated Ed25519/Cv25519 keys). B1c writes the
    // fingerprint to the card, builds the card-signed self-signatures, and stores
    // the result in the keyring as a card key.

    /// One generated key part (primary or subkey): its packet body, v4 fingerprint,
    /// the 32-byte point, and the creation time used to compute them.
    struct CardGeneratedKeyPart {
        let body: [UInt8]
        let fingerprint: [UInt8]
        let point: [UInt8]
        let creationTime: UInt32
    }

    /// Ed25519 signing primary (card sign slot, algo 22) from the card's point.
    static func cardEd25519PrimaryPart(point: [UInt8], creationTime: UInt32) -> CardGeneratedKeyPart {
        let body = buildEdDSAPublicKeyBody(creationTime: creationTime, publicKey: point)
        return CardGeneratedKeyPart(
            body: body,
            fingerprint: calculateV4Fingerprint(keyBody: body),
            point: point,
            creationTime: creationTime
        )
    }

    /// Cv25519 ECDH subkey (card decrypt slot, algo 18) from the card's point.
    static func cardCv25519SubkeyPart(point: [UInt8], creationTime: UInt32) -> CardGeneratedKeyPart {
        let body = buildECDHPublicKeyBody(creationTime: creationTime, publicKey: point)
        return CardGeneratedKeyPart(
            body: body,
            fingerprint: calculateV4Fingerprint(keyBody: body),
            point: point,
            creationTime: creationTime
        )
    }

    // MARK: - B1c: On-card key generation (full NFC flow)
    //
    // Generates an Ed25519 signing primary + Cv25519 ECDH subkey ON the card and
    // returns the assembled, self-signed transferable PUBLIC key (the secret never
    // leaves the card). The certification + subkey-binding signatures are produced
    // BY THE CARD (the primary key lives there), using the exact packet layout of
    // the software keygen above. Verified offline against gpg: keys assembled this
    // way import with valid (sig:!) certification + binding signatures and matching
    // fingerprints.
    //
    // PIN sequence, one NFC session: PW3 (admin) to set algorithm attributes,
    // generate, and write fingerprints; then PW1 (signing) re-verified before EACH
    // self-signature (covers cards that reset PW1 after each PSO:CDS).

    struct CardKeyGenResult {
        let armoredPublicKey: String
        let publicKeyData: Data           // binary transferable public key (for Keychain)
        let primaryFingerprint: [UInt8]   // 20-byte v4, sign slot (C7)
        let subkeyFingerprint: [UInt8]    // 20-byte v4, decrypt slot (C8)
        let creationTime: UInt32
        let keyID: [UInt8]                // last 8 bytes of primary fingerprint
    }

    enum CardKeyGenError: LocalizedError {
        case unexpectedAlgorithm
        var errorDescription: String? {
            switch self {
            case .unexpectedAlgorithm:
                return "The card returned an unexpected key type. Expected Ed25519 / Cv25519."
            }
        }
    }

    /// Algorithm-attributes value for an Ed25519 (EdDSA) key: algo id 22 + curve OID.
    private static let ed25519AlgoAttributes: [UInt8] = [22] + ed25519OID
    /// Algorithm-attributes value for a Cv25519 (ECDH) key: algo id 18 + curve OID.
    private static let cv25519AlgoAttributes: [UInt8] = [18] + cv25519OID

    /// Full on-card generation flow. `card` must be connected (applet selected).
    /// DESTRUCTIVE: overwrites the sign + decrypt slots. The generated secret keys
    /// live only on the card and cannot be backed up.
    static func generateOnCard(
        card: OpenPGPCardService,
        name: String,
        email: String,
        expirationInterval: TimeInterval?,
        adminPIN: String,
        userPIN: String
    ) async throws -> CardKeyGenResult {
        let creationTime = UInt32(Date().timeIntervalSince1970)

        // --- PW3 (admin): set algorithms, generate, write fingerprints ---
        try await card.verify(pin: adminPIN, mode: .admin)

        // Point both slots at the Curve25519 algorithms (safe even if already set).
        try await card.setAlgorithmAttributes(slot: .signature, ed25519AlgoAttributes)
        try await card.setAlgorithmAttributes(slot: .decryption, cv25519AlgoAttributes)

        // Generate the key pairs on the card; collect the public points.
        let signMaterial = try await card.generateKeyPair(slot: .signature)
        let decMaterial = try await card.generateKeyPair(slot: .decryption)
        guard case let .ec(signPoint) = signMaterial,
              case let .ec(decPoint) = decMaterial else {
            throw CardKeyGenError.unexpectedAlgorithm
        }

        let primary = cardEd25519PrimaryPart(point: signPoint, creationTime: creationTime)
        let subkey = cardCv25519SubkeyPart(point: decPoint, creationTime: creationTime)
        let keyID = Array(primary.fingerprint.suffix(8))

        // Write the computed fingerprints to the card (still under PW3).
        try await card.writeKeyFingerprint(slot: .signature, primary.fingerprint)
        try await card.writeKeyFingerprint(slot: .decryption, subkey.fingerprint)

        // --- PW1 (signing): self-signatures, produced by the card's sign key ---
        let userIDBytes = Array("\(name) <\(email)>".utf8)

        try await card.verify(pin: userPIN, mode: .signing)
        let certSig = try await buildCardCertificationSignature(
            card: card, primaryKeyBody: primary.body, userIDBytes: userIDBytes,
            creationTime: creationTime, expirationInterval: expirationInterval, keyID: keyID
        )
        try await card.verify(pin: userPIN, mode: .signing)
        let bindSig = try await buildCardSubkeyBindingSignature(
            card: card, primaryKeyBody: primary.body, subkeyBody: subkey.body,
            creationTime: creationTime, keyID: keyID
        )

        // Assemble + armor the transferable public key (no secret packets).
        var pkt = Data()
        pkt.append(buildPacket(tag: 6, body: Data(primary.body)))   // Public-Key
        pkt.append(buildPacket(tag: 13, body: Data(userIDBytes)))   // User ID
        pkt.append(buildPacket(tag: 2, body: Data(certSig)))        // Certification
        pkt.append(buildPacket(tag: 14, body: Data(subkey.body)))   // Public-Subkey
        pkt.append(buildPacket(tag: 2, body: Data(bindSig)))        // Subkey binding
        let armored = armorData(pkt, type: .publicKey)

        return CardKeyGenResult(
            armoredPublicKey: armored,
            publicKeyData: pkt,
            primaryFingerprint: primary.fingerprint,
            subkeyFingerprint: subkey.fingerprint,
            creationTime: creationTime,
            keyID: keyID
        )
    }

    /// Card-signed positive certification (0x13). Identical layout to
    /// `buildCertificationSignature`; the 64-byte EdDSA signature comes from the
    /// card. PW1 (.signing) must be verified before calling.
    private static func buildCardCertificationSignature(
        card: OpenPGPCardService,
        primaryKeyBody: [UInt8],
        userIDBytes: [UInt8],
        creationTime: UInt32,
        expirationInterval: TimeInterval?,
        keyID: [UInt8]
    ) async throws -> [UInt8] {
        var hashedSubpackets = Data()
        hashedSubpackets.append(buildSubpacket(type: 2, data: creationTime.bigEndianBytes))
        hashedSubpackets.append(buildSubpacket(type: 27, data: [0x03]))
        hashedSubpackets.append(buildSubpacket(type: 11, data: [9, 8, 7]))
        hashedSubpackets.append(buildSubpacket(type: 21, data: [10, 9, 8]))
        hashedSubpackets.append(buildSubpacket(type: 22, data: [2, 3, 1]))
        hashedSubpackets.append(buildSubpacket(type: 30, data: [0x01]))
        if let interval = expirationInterval {
            let expSeconds = UInt32(interval)
            hashedSubpackets.append(buildSubpacket(type: 9, data: expSeconds.bigEndianBytes))
        }

        var unhashedSubpackets = Data()
        unhashedSubpackets.append(buildSubpacket(type: 16, data: keyID))

        let hashData = buildCertificationHashData(
            primaryKeyBody: primaryKeyBody,
            userIDBytes: userIDBytes,
            signatureType: 0x13,
            hashedSubpackets: Array(hashedSubpackets)
        )
        let digestBytes = Array(SHA256.hash(data: hashData))
        let sigBytes = try await card.sign(digest: digestBytes)
        guard sigBytes.count == 64 else { throw CardKeyGenError.unexpectedAlgorithm }

        return assembleEdDSASignaturePacket(
            signatureType: 0x13,
            hashedSubpackets: Array(hashedSubpackets),
            unhashedSubpackets: Array(unhashedSubpackets),
            digestPrefix: [digestBytes[0], digestBytes[1]],
            sigBytes: sigBytes
        )
    }

    /// Card-signed subkey binding signature (0x18).
    private static func buildCardSubkeyBindingSignature(
        card: OpenPGPCardService,
        primaryKeyBody: [UInt8],
        subkeyBody: [UInt8],
        creationTime: UInt32,
        keyID: [UInt8]
    ) async throws -> [UInt8] {
        var hashedSubpackets = Data()
        hashedSubpackets.append(buildSubpacket(type: 2, data: creationTime.bigEndianBytes))
        hashedSubpackets.append(buildSubpacket(type: 27, data: [0x0C]))

        var unhashedSubpackets = Data()
        unhashedSubpackets.append(buildSubpacket(type: 16, data: keyID))

        let hashData = buildSubkeyBindingHashData(
            primaryKeyBody: primaryKeyBody,
            subkeyBody: subkeyBody,
            signatureType: 0x18,
            hashedSubpackets: Array(hashedSubpackets)
        )
        let digestBytes = Array(SHA256.hash(data: hashData))
        let sigBytes = try await card.sign(digest: digestBytes)
        guard sigBytes.count == 64 else { throw CardKeyGenError.unexpectedAlgorithm }

        return assembleEdDSASignaturePacket(
            signatureType: 0x18,
            hashedSubpackets: Array(hashedSubpackets),
            unhashedSubpackets: Array(unhashedSubpackets),
            digestPrefix: [digestBytes[0], digestBytes[1]],
            sigBytes: sigBytes
        )
    }

    /// Assemble a v4 EdDSA signature packet body from card-produced r||s (64 bytes).
    /// Mirrors the packet tail of `buildCertificationSignature` exactly.
    private static func assembleEdDSASignaturePacket(
        signatureType: UInt8,
        hashedSubpackets: [UInt8],
        unhashedSubpackets: [UInt8],
        digestPrefix: [UInt8],
        sigBytes: [UInt8]
    ) -> [UInt8] {
        var sigBody: [UInt8] = []
        sigBody.append(4)                  // Version
        sigBody.append(signatureType)
        sigBody.append(eddsaAlgorithm)     // EdDSA
        sigBody.append(8)                  // SHA256

        sigBody.append(contentsOf: UInt16(hashedSubpackets.count).bigEndianBytes)
        sigBody.append(contentsOf: hashedSubpackets)
        sigBody.append(contentsOf: UInt16(unhashedSubpackets.count).bigEndianBytes)
        sigBody.append(contentsOf: unhashedSubpackets)

        sigBody.append(contentsOf: digestPrefix)   // left 16 bits of hash

        let rBytes = Array(sigBytes[0..<32])
        let sBytes = Array(sigBytes[32..<64])
        let rBits = UInt16(rBytes.count * 8 - countLeadingZeroBits(rBytes))
        sigBody.append(contentsOf: rBits.bigEndianBytes)
        sigBody.append(contentsOf: rBytes)
        let sBits = UInt16(sBytes.count * 8 - countLeadingZeroBits(sBytes))
        sigBody.append(contentsOf: sBits.bigEndianBytes)
        sigBody.append(contentsOf: sBytes)
        return sigBody
    }

    // MARK: - ASCII Armor
    
    private enum ArmorType {
        case publicKey
        case secretKey
        
        var header: String {
            switch self {
            case .publicKey: return "-----BEGIN PGP PUBLIC KEY BLOCK-----"
            case .secretKey: return "-----BEGIN PGP PRIVATE KEY BLOCK-----"
            }
        }
        
        var footer: String {
            switch self {
            case .publicKey: return "-----END PGP PUBLIC KEY BLOCK-----"
            case .secretKey: return "-----END PGP PRIVATE KEY BLOCK-----"
            }
        }
    }
    
    private static func armorData(_ data: Data, type: ArmorType) -> String {
        let base64 = data.base64EncodedString(options: .lineLength76Characters)
        let crc = crc24(data)
        let crcBase64 = Data(crc).base64EncodedString()
        
        // No leading whitespace — armor lines must start at column 0
        return "\(type.header)\n\n\(base64)\n=\(crcBase64)\n\(type.footer)"
    }
    
    /// CRC-24 as used in OpenPGP ASCII Armor
    private static func crc24(_ data: Data) -> [UInt8] {
        var crc: UInt32 = 0xB704CE
        for byte in data {
            crc ^= UInt32(byte) << 16
            for _ in 0..<8 {
                crc <<= 1
                if crc & 0x1000000 != 0 {
                    crc ^= 0x1864CFB
                }
            }
        }
        crc &= 0xFFFFFF
        return [
            UInt8((crc >> 16) & 0xFF),
            UInt8((crc >> 8) & 0xFF),
            UInt8(crc & 0xFF)
        ]
    }
    
    // MARK: - Utilities
    
    private static func countLeadingZeroBits(_ bytes: [UInt8]) -> Int {
        for (i, byte) in bytes.enumerated() {
            if byte != 0 {
                return i * 8 + byte.leadingZeroBitCount
            }
        }
        return bytes.count * 8
    }
}

// MARK: - Byte Helpers

private extension UInt16 {
    var bigEndianBytes: [UInt8] {
        [UInt8((self >> 8) & 0xFF), UInt8(self & 0xFF)]
    }
}

private extension UInt32 {
    var bigEndianBytes: [UInt8] {
        [
            UInt8((self >> 24) & 0xFF),
            UInt8((self >> 16) & 0xFF),
            UInt8((self >> 8) & 0xFF),
            UInt8(self & 0xFF)
        ]
    }
}
