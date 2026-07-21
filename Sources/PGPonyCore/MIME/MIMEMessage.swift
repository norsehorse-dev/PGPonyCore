// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import Foundation

/// PGP/MIME (RFC 2045 / 2046 / 3156) presentation model. Pure data, no crypto.
///
/// The decrypt path hands us already-decrypted bytes. When those bytes are a
/// MIME entity (a PGP/MIME message from a desktop client such as Thunderbird),
/// `MIMEParser` turns them into this small tree, and `MIMEPresentation` flattens
/// the tree into something the result view can render: a readable body plus a
/// list of openable attachments.
///
/// Nothing here touches the network or any cryptography — the parser only ever
/// runs on bytes that were already decrypted in memory. This mirrors the shape
/// of the existing `PassEntryParser` / `PassModels` pair: a tolerant parser plus
/// plain value-type models.
///
/// NEW FILE — add to the **PGPony** app target (and tick **PGPonyAction** so the
/// share extension can share the parser when Phase 2 wires it in) in Xcode.

// MARK: - Content type

/// A parsed `Content-Type` header: `type/subtype` plus its parameters.
struct MIMEContentType: Equatable {
    /// Lowercased major type, e.g. `multipart`, `text`, `application`.
    let type: String
    /// Lowercased subtype, e.g. `mixed`, `plain`, `pgp-signature`.
    let subtype: String
    /// Parameters with lowercased keys (`boundary`, `charset`, `name`, …).
    let parameters: [String: String]

    /// Lowercased `type/subtype`, e.g. `text/plain`.
    var mimeType: String { "\(type)/\(subtype)" }

    var boundary: String? { parameters["boundary"] }
    var charset: String? { parameters["charset"] }
    var name: String? { parameters["name"] }

    var isMultipart: Bool { type == "multipart" }
    var isText: Bool { type == "text" }

    /// RFC 3676 `format=flowed` on a `text/plain` part.
    var isFlowed: Bool { (parameters["format"]?.lowercased() == "flowed") }
    /// RFC 3676 `delsp=yes` — the soft-break space is deleted on reflow.
    var isDelSp: Bool { (parameters["delsp"]?.lowercased() == "yes") }

    /// The default when no `Content-Type` header is present (RFC 2045 §5.2).
    static let defaultType = MIMEContentType(
        type: "text", subtype: "plain", parameters: ["charset": "us-ascii"]
    )
}

// MARK: - Transfer encoding

/// `Content-Transfer-Encoding` values we decode.
enum MIMETransferEncoding: Equatable {
    case sevenBit
    case eightBit
    case binary
    case base64
    case quotedPrintable
    case other(String)

    init(headerValue: String?) {
        switch (headerValue ?? "").trimmingCharacters(in: .whitespaces).lowercased() {
        case "", "7bit":            self = .sevenBit
        case "8bit":                self = .eightBit
        case "binary":              self = .binary
        case "base64":              self = .base64
        case "quoted-printable":    self = .quotedPrintable
        case let other:             self = .other(other)
        }
    }
}

// MARK: - Disposition

/// `Content-Disposition`: inline vs attachment, with an optional filename.
struct MIMEDisposition: Equatable {
    /// `inline`, `attachment`, or empty when the header is absent.
    let kind: String
    let filename: String?

    static let none = MIMEDisposition(kind: "", filename: nil)
}

// MARK: - Header

/// One raw (unfolded) header line.
struct MIMEHeader: Equatable {
    let name: String   // original case preserved
    let value: String  // unfolded, leading space trimmed
}

// MARK: - Entity

/// A node in the MIME tree: either a multipart container or a decoded leaf.
indirect enum MIMEContent {
    case multipart([MIMEEntity])
    /// Transfer-decoded bytes (after base64 / quoted-printable decoding).
    case leaf(Data)
}

/// A single MIME entity (the whole message is the root entity).
struct MIMEEntity: Identifiable {
    let id = UUID()
    let headers: [MIMEHeader]
    let contentType: MIMEContentType
    let transferEncoding: MIMETransferEncoding
    let disposition: MIMEDisposition
    let contentID: String?
    let content: MIMEContent

    /// True when this part should be surfaced as an attachment rather than body:
    /// an explicit `attachment` disposition, or any part that carries a filename.
    var isAttachmentLike: Bool {
        if disposition.kind.lowercased() == "attachment" { return true }
        if disposition.filename != nil { return true }
        if contentType.name != nil { return true }
        return false
    }

    /// The best filename we can offer, decoding RFC 2047 encoded-words.
    var resolvedFilename: String? {
        let raw = disposition.filename ?? contentType.name
        return raw.map { MIMEParser.decodeEncodedWords($0) }
    }

    /// Decoded text, honouring charset and (for flowed text/plain) RFC 3676.
    func decodedText() -> String? {
        guard case .leaf(let data) = content, contentType.isText else { return nil }
        let text = MIMEParser.decodeText(Array(data), charset: contentType.charset)
        if contentType.subtype == "plain" && contentType.isFlowed {
            return MIMEParser.applyFormatFlowed(text, delSp: contentType.isDelSp)
        }
        return text
    }
}

// MARK: - Attachment

/// A decoded attachment ready to be written to a temp file for QuickLook / share.
struct MIMEAttachment: Identifiable {
    let id = UUID()
    let filename: String
    let mimeType: String
    let data: Data

    var byteCount: Int { data.count }
}

// MARK: - Presentation

/// The flattened, view-ready form of a parsed PGP/MIME message:
/// a readable body (plain preferred, HTML kept for an opt-in toggle) and the
/// set of attachments. `isSigned` notes that the message carried a MIME-level
/// PGP signature (`multipart/signed`); it does **not** claim the signature was
/// verified — that honesty matches the existing `.notIntrospected` banner case.
struct MIMEPresentation {
    var plainText: String?
    var htmlText: String?
    var attachments: [MIMEAttachment]
    var isSigned: Bool

    init(root: MIMEEntity) {
        var acc = Accumulator()
        MIMEPresentation.collect(root, into: &acc)
        self.plainText = acc.plain
        self.htmlText = acc.html
        self.attachments = acc.attachments
        self.isSigned = acc.isSigned
    }

    private struct Accumulator {
        var plain: String?
        var html: String?
        var attachments: [MIMEAttachment] = []
        var isSigned = false

        mutating func addPlain(_ e: MIMEEntity) {
            guard plain == nil, let t = e.decodedText() else { return }
            plain = t
        }
        mutating func addHTML(_ e: MIMEEntity) {
            guard html == nil, let t = e.decodedText() else { return }
            html = t
        }
        mutating func addAttachment(_ e: MIMEEntity, index: Int) {
            guard case .leaf(let data) = e.content else { return }
            let name = e.resolvedFilename ?? MIMEPresentation.fallbackName(for: e, index: index)
            attachments.append(
                MIMEAttachment(filename: name, mimeType: e.contentType.mimeType, data: data)
            )
        }
    }

    /// Depth-first walk that classifies each entity per RFC 3156 shapes:
    /// `multipart/signed` -> recurse into the protected subtree, note signed;
    /// `multipart/alternative` -> prefer text/plain for the body, keep text/html;
    /// `multipart/mixed` (and relatives) -> first text is body, filename'd parts
    /// are attachments; an `application/pgp-signature` leaf is the signature, not
    /// an attachment.
    private static func collect(_ e: MIMEEntity, into acc: inout Accumulator) {
        switch e.content {
        case .multipart(let children):
            switch e.contentType.subtype {
            case "signed":
                acc.isSigned = true
                // Recurse into the first non-signature child (the protected body).
                for child in children where child.contentType.mimeType != "application/pgp-signature" {
                    collect(child, into: &acc)
                    break
                }
                // Still note any signature part so isSigned is set even if ordering varies.
                for child in children where child.contentType.mimeType == "application/pgp-signature" {
                    acc.isSigned = true
                }

            case "alternative":
                // Prefer plain for the body; keep html for the opt-in toggle.
                if let plain = children.first(where: {
                    $0.contentType.mimeType == "text/plain" && !$0.isAttachmentLike
                }) { acc.addPlain(plain) }
                if let html = children.first(where: {
                    $0.contentType.mimeType == "text/html" && !$0.isAttachmentLike
                }) { acc.addHTML(html) }
                // Walk anything that isn't one of those two body candidates
                // (nested multiparts, sibling attachments).
                for child in children {
                    let mt = child.contentType.mimeType
                    if (mt == "text/plain" || mt == "text/html") && !child.isAttachmentLike { continue }
                    collect(child, into: &acc)
                }

            default:
                // mixed / related / report / unknown multiparts: walk every child.
                for child in children { collect(child, into: &acc) }
            }

        case .leaf:
            let mt = e.contentType.mimeType
            if mt == "application/pgp-signature" {
                acc.isSigned = true
                return
            }
            if e.isAttachmentLike {
                acc.addAttachment(e, index: acc.attachments.count)
                return
            }
            switch mt {
            case "text/plain": acc.addPlain(e)
            case "text/html":  acc.addHTML(e)
            default:
                // A non-text inline leaf with no disposition is still surfaced
                // as an attachment so nothing is silently dropped.
                acc.addAttachment(e, index: acc.attachments.count)
            }
        }
    }

    private static func fallbackName(for e: MIMEEntity, index: Int) -> String {
        let ext: String
        switch e.contentType.mimeType {
        case "application/pgp-keys":      ext = "asc"
        case "application/pgp-encrypted": ext = "asc"
        case "application/pdf":           ext = "pdf"
        case "text/plain":                ext = "txt"
        case "text/html":                 ext = "html"
        default:                          ext = e.contentType.subtype
        }
        return "attachment-\(index + 1).\(ext)"
    }
}

// MARK: - Message

/// A parsed PGP/MIME message. `presentation` is the view-ready projection.
struct MIMEMessage {
    let root: MIMEEntity
    var presentation: MIMEPresentation { MIMEPresentation(root: root) }
}
