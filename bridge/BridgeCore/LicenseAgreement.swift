import Foundation

/// Version and digest come from the bundled Legal/EULA.json resource.
/// Application and EULA versions are intentionally independent.
public struct LicenseAgreementMetadata: Codable, Hashable, Sendable {
    public struct LegacyAcceptance: Codable, Hashable, Sendable {
        public let eulaVersion: String
        public let sha256: String

        enum CodingKeys: String, CodingKey {
            case eulaVersion = "eula_version"
            case sha256
        }
    }

    public let schema: Int
    public let eulaVersion: String
    public let effectiveDate: String
    public let sha256: String
    public let legacyAcceptance: LegacyAcceptance?

    enum CodingKeys: String, CodingKey {
        case schema
        case eulaVersion = "eula_version"
        case effectiveDate = "effective_date"
        case sha256
        case legacyAcceptance = "legacy_acceptance"
    }

    public init(data: Data) throws {
        let decoded = try JSONDecoder().decode(Self.self, from: data)
        guard decoded.schema == 1,
              decoded.eulaVersion.range(of: #"^[0-9]+(\.[0-9]+){1,2}$"#, options: .regularExpression) != nil,
              ISO8601DateFormatter().date(from: decoded.effectiveDate + "T00:00:00Z") != nil,
              decoded.sha256.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil else {
            throw LicenseAgreementError.invalidMetadata
        }
        self = decoded
    }

    public static let acceptedRecordKey = "com.liquidsky.0sky.license.acceptance-record"
    public static let legacyAcceptedVersionKey = "com.liquidsky.0sky.license.accepted-version"
    public static let legacyAcceptedAtKey = "com.liquidsky.0sky.license.accepted-at"

    public static let requiredAuthorizationStatement =
        "I certify that each Apple device or other system on which I use 0-Sky " +
        "is owned by me or that I have explicit authorization from the lawful " +
        "owner to perform the security research I intend to conduct."

    public func isCurrent(_ record: LicenseAcceptanceRecord?) -> Bool {
        record?.accepted == true && record?.schema == 1
            && record?.eulaVersion == eulaVersion && record?.sha256 == sha256
    }
}

public enum LicenseAgreementError: Error {
    case invalidMetadata
}

/// Minimal local evidence of an explicit affirmative action.
public struct LicenseAcceptanceRecord: Codable, Hashable, Sendable {
    public let schema: Int
    public let eulaVersion: String
    public let sha256: String
    public let accepted: Bool
    public let acceptedAt: Date

    public init(metadata: LicenseAgreementMetadata, acceptedAt: Date = Date()) {
        self.schema = 1
        self.eulaVersion = metadata.eulaVersion
        self.sha256 = metadata.sha256
        self.accepted = true
        self.acceptedAt = acceptedAt
    }
}

public struct LicenseAcceptanceStore {
    private let defaults: UserDefaults

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    public func record() -> LicenseAcceptanceRecord? {
        guard let data = defaults.data(forKey: LicenseAgreementMetadata.acceptedRecordKey) else {
            return nil
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(LicenseAcceptanceRecord.self, from: data)
    }

    public func isAccepted(_ metadata: LicenseAgreementMetadata) -> Bool {
        if metadata.isCurrent(record()) { return true }
        guard record() == nil,
              metadata.legacyAcceptance?.eulaVersion == metadata.eulaVersion,
              metadata.legacyAcceptance?.sha256 == metadata.sha256,
              defaults.string(forKey: LicenseAgreementMetadata.legacyAcceptedVersionKey) == metadata.eulaVersion,
              let timestamp = defaults.string(forKey: LicenseAgreementMetadata.legacyAcceptedAtKey),
              let acceptedAt = ISO8601DateFormatter().date(from: timestamp) else {
            return false
        }
        return accept(metadata, at: acceptedAt)
    }

    @discardableResult
    public func accept(_ metadata: LicenseAgreementMetadata, at date: Date = Date()) -> Bool {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(LicenseAcceptanceRecord(metadata: metadata, acceptedAt: date)) else {
            return false
        }
        defaults.set(data, forKey: LicenseAgreementMetadata.acceptedRecordKey)
        return metadata.isCurrent(record())
    }
}
