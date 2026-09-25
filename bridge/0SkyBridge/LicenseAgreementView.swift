import AppKit
import BridgeCore
import CryptoKit
import Foundation
import SwiftUI

struct LicenseAgreementDocument {
    let url: URL
    let text: String
    let metadata: LicenseAgreementMetadata

    static func load() -> Self? {
        var bundles = [Bundle.main]
        #if SWIFT_PACKAGE
        bundles.append(Bundle.module)
        #endif
        for bundle in bundles {
            let legalText = bundle.url(forResource: "EULA", withExtension: "md", subdirectory: "Legal")
            let legalMetadata = bundle.url(forResource: "EULA", withExtension: "json", subdirectory: "Legal")
            guard let legalText, let legalMetadata,
                  let bytes = try? Data(contentsOf: legalText),
                  let metadataBytes = try? Data(contentsOf: legalMetadata),
                  let metadata = try? LicenseAgreementMetadata(data: metadataBytes),
                  let text = String(data: bytes, encoding: .utf8) else { continue }
            let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            guard digest == metadata.sha256,
                  text.contains("**Version:** \(metadata.eulaVersion)"),
                  text.contains(LicenseAgreementMetadata.requiredAuthorizationStatement)
            else { continue }
            return Self(url: legalText, text: text, metadata: metadata)
        }
        return nil
    }

    static func openExternally() -> Bool {
        guard let document = load() else { return false }
        return NSWorkspace.shared.open(document.url)
    }
}

struct LicenseAgreementView: View {
    let document: LicenseAgreementDocument?
    let onAccept: () -> Bool
    @State private var acceptsAgreement = false
    @State private var certifiesAuthorization = false
    @State private var acceptanceError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "checkmark.shield.fill")
                    .font(.system(size: 38))
                    .foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 3) {
                    Text("0-Sky End User License Agreement")
                        .font(.title.bold())
                    Text(document.map {
                        "Agreement version \($0.metadata.eulaVersion) • Effective \($0.metadata.effectiveDate)"
                    } ?? "Agreement unavailable")
                        .foregroundStyle(.secondary)
                }
            }

            GroupBox {
                ScrollView {
                    Text(renderedAgreement)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(12)
                }
                .accessibilityIdentifier("EULAFullText")
                .frame(minHeight: 360)
            }

            Toggle("I have read and agree to the End User License Agreement and Authorized Security Research Terms.",
                   isOn: $acceptsAgreement)
                .toggleStyle(.checkbox)
                .accessibilityIdentifier("AcceptAgreementCheckbox")

            Toggle(LicenseAgreementMetadata.requiredAuthorizationStatement,
                   isOn: $certifiesAuthorization)
                .toggleStyle(.checkbox)
                .accessibilityIdentifier("AuthorizationCertificationCheckbox")

            if let acceptanceError {
                Text(acceptanceError).foregroundStyle(.red)
                    .accessibilityIdentifier("EULAAcceptanceError")
            }

            HStack {
                Text("Acceptance is recorded only on this Mac as the agreement version and timestamp. No device identifier or credential is included.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Decline and Quit", role: .cancel) {
                    NSApplication.shared.terminate(nil)
                }
                .accessibilityIdentifier("DeclineAgreementButton")
                Button("Accept and Continue") {
                    if !onAccept() {
                        acceptanceError = "Acceptance could not be saved. Check this account's preferences and try again."
                    }
                }
                    .buttonStyle(.borderedProminent)
                    .disabled(document == nil || !acceptsAgreement || !certifiesAuthorization)
                    .accessibilityIdentifier("AcceptAndContinueButton")
            }
        }
        .padding(22)
        .frame(minWidth: 820, minHeight: 700)
    }

    private var renderedAgreement: AttributedString {
        guard let document else {
            return AttributedString(
                "The bundled agreement could not be loaded or validated. Reinstall 0-Sky Bridge before continuing."
            )
        }
        return (try? AttributedString(
            markdown: document.text,
            options: .init(interpretedSyntax: .full)
        )) ?? AttributedString(document.text)
    }
}
