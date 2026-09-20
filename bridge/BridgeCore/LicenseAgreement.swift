import Foundation

/// Versioned, non-identifying metadata for the 0-Sky end-user agreement.
/// Acceptance is intentionally local and contains no device or account data.
public enum LicenseAgreementMetadata: Sendable {
    public static let schemaVersion = 1
    public static let currentVersion = "1.0"
    public static let effectiveDate = "September 20, 2026"
    public static let acceptedVersionKey = "com.liquidsky.0sky.license.accepted-version"
    public static let acceptedAtKey = "com.liquidsky.0sky.license.accepted-at"

    public static let requiredAuthorizationStatement =
        "I certify that each Apple device or other system on which I use 0-Sky " +
        "is owned by me or that I have explicit authorization from the lawful " +
        "owner to perform the security research I intend to conduct."

    public static func isCurrent(acceptedVersion: String?) -> Bool {
        acceptedVersion == currentVersion
    }
}

public struct LicenseAcceptanceRecord: Codable, Hashable, Sendable {
    public let schema: Int
    public let agreementVersion: String
    public let effectiveDate: String
    public let acceptedAt: Date

    public init(acceptedAt: Date = Date()) {
        self.schema = LicenseAgreementMetadata.schemaVersion
        self.agreementVersion = LicenseAgreementMetadata.currentVersion
        self.effectiveDate = LicenseAgreementMetadata.effectiveDate
        self.acceptedAt = acceptedAt
    }
}
