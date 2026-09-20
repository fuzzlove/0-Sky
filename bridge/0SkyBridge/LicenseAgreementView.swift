import AppKit
import BridgeCore
import Foundation
import SwiftUI

enum LicenseAgreementDocument {
    static var resourceURL: URL? {
        if let direct = Bundle.main.url(forResource: "EULA", withExtension: "md") {
            return direct
        }
        let candidates = (Bundle.allBundles + Bundle.allFrameworks).compactMap {
            $0.url(forResource: "EULA", withExtension: "md")
        }
        if let bundled = candidates.first { return bundled }
        guard let resources = Bundle.main.resourceURL else { return nil }
        let packageBundle = resources.appendingPathComponent(
            "0SkyBridge_0SkyBridge.bundle/EULA.md", isDirectory: false
        )
        return FileManager.default.isReadableFile(atPath: packageBundle.path)
            ? packageBundle : nil
    }

    static var text: String? {
        guard let url = resourceURL,
              let value = try? String(contentsOf: url, encoding: .utf8),
              value.contains("**Version:** \(LicenseAgreementMetadata.currentVersion)"),
              value.contains(LicenseAgreementMetadata.requiredAuthorizationStatement)
        else { return nil }
        return value
    }

    static func openExternally() -> Bool {
        guard let resourceURL else { return false }
        return NSWorkspace.shared.open(resourceURL)
    }
}

struct LicenseAgreementView: View {
    let onAccept: () -> Void
    @State private var acceptsAgreement = false
    @State private var certifiesAuthorization = false

    private let agreementText = LicenseAgreementDocument.text

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "checkmark.shield.fill")
                    .font(.system(size: 38))
                    .foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 3) {
                    Text("0-Sky Authorized Security Research Terms")
                        .font(.title.bold())
                    Text("Agreement version \(LicenseAgreementMetadata.currentVersion) • Effective \(LicenseAgreementMetadata.effectiveDate)")
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
                .frame(minHeight: 360)
            }

            Toggle("I have read and agree to the End User License Agreement and Authorized Security Research Terms.",
                   isOn: $acceptsAgreement)
                .accessibilityIdentifier("AcceptAgreementCheckbox")

            Toggle(LicenseAgreementMetadata.requiredAuthorizationStatement,
                   isOn: $certifiesAuthorization)
                .accessibilityIdentifier("AuthorizationCertificationCheckbox")

            HStack {
                Text("Acceptance is recorded only on this Mac as the agreement version and timestamp. No device identifier or credential is included.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Decline and Quit", role: .cancel) {
                    NSApplication.shared.terminate(nil)
                }
                Button("Accept and Continue") { onAccept() }
                    .buttonStyle(.borderedProminent)
                    .disabled(agreementText == nil || !acceptsAgreement || !certifiesAuthorization)
                    .accessibilityIdentifier("AcceptAndContinueButton")
            }
        }
        .padding(22)
        .frame(minWidth: 820, minHeight: 700)
    }

    private var renderedAgreement: AttributedString {
        guard let agreementText else {
            return AttributedString(
                "The bundled agreement could not be loaded or validated. Reinstall 0-Sky Bridge before continuing."
            )
        }
        return (try? AttributedString(
            markdown: agreementText,
            options: .init(interpretedSyntax: .full)
        )) ?? AttributedString(agreementText)
    }
}
