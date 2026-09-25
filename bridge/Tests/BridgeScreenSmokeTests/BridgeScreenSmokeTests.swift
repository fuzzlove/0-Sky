import XCTest

final class BridgeScreenSmokeTests: XCTestCase {
    private var app: XCUIApplication!

    override func setUpWithError() throws {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchArguments += ["--ui-smoke-test"]
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20), "Bridge window did not appear")
        acceptAgreementIfRequired()
        dismissInformationalAlertIfPresent()
    }

    override func tearDownWithError() throws {
        app.terminate()
        app = nil
    }

    func testAllPrimaryScreensAndSafeControls() throws {
        openSection("Dashboard")
        assertText("Dashboard")
        assertText("0-Sky Bridge")
        assertButton("Refresh")
        capture("01-dashboard")
        app.buttons["Refresh"].firstMatch.click()
        waitForIdle()
        dismissInformationalAlertIfPresent()

        openSection("Devices")
        assertText("Devices")
        XCTAssertTrue(
            app.buttons["Verify Pairing"].firstMatch.waitForExistence(timeout: 10)
                || app.staticTexts["No Device"].firstMatch.exists,
            "Devices screen showed neither device controls nor its empty state"
        )
        capture("02-devices")

        openSection("Bridge")
        assertText("Bridge Control")
        assertButton("Check CoreDevice")
        assertButton("Test Device Ports")
        capture("03-bridge-before-operation")
        app.buttons["Check CoreDevice"].firstMatch.click()
        waitForIdle(timeout: 30)
        dismissInformationalAlertIfPresent()
        capture("04-bridge-after-coredevice-check")

        openSection("Diagnostics")
        assertText("Diagnostics")
        assertButton("Run Diagnostics")
        app.buttons["Run Diagnostics"].firstMatch.click()
        waitForIdle(timeout: 30)
        dismissInformationalAlertIfPresent()
        capture("05-diagnostics")

        openSection("Logs")
        assertText("Structured Logs")
        assertButton("Copy Output")
        app.buttons["Copy Output"].firstMatch.click()
        capture("06-logs")

        openSection("Settings")
        assertText("Settings")
        assertButton("Open Setup Assistant")
        assertButton("View License Agreement")
        let reconnect = app.checkBoxes["Automatically reconnect devices"].firstMatch
        XCTAssertTrue(reconnect.waitForExistence(timeout: 10), "Automatic reconnect control is missing")
        let originalValue = reconnect.value as? String
        reconnect.click()
        reconnect.click()
        XCTAssertEqual(reconnect.value as? String, originalValue, "Automatic reconnect did not restore")
        capture("07-settings")

        app.buttons["Open Setup Assistant"].firstMatch.click()
        assertText("Welcome to 0-Sky Bridge")
        capture("08-setup-assistant-start")
        for _ in 0..<9 {
            let next = app.buttons["Continue"].firstMatch
            XCTAssertTrue(next.waitForExistence(timeout: 5), "Setup Assistant Continue button is missing")
            next.click()
        }
        assertText("Complete")
        capture("09-setup-assistant-complete")
        assertButton("Done")
        app.buttons["Done"].firstMatch.click()
        XCTAssertFalse(app.staticTexts["Welcome to 0-Sky Bridge"].firstMatch.waitForExistence(timeout: 5))
    }

    private func openSection(_ name: String) {
        let item = app.staticTexts[name].firstMatch
        XCTAssertTrue(item.waitForExistence(timeout: 10), "Missing sidebar section: \(name)")
        item.click()
        dismissInformationalAlertIfPresent()
    }

    private func assertText(_ value: String) {
        XCTAssertTrue(app.staticTexts[value].firstMatch.waitForExistence(timeout: 10), "Missing text: \(value)")
    }

    private func assertButton(_ value: String) {
        XCTAssertTrue(app.buttons[value].firstMatch.waitForExistence(timeout: 10), "Missing button: \(value)")
    }

    private func waitForIdle(timeout: TimeInterval = 20) {
        let progress = app.progressIndicators.firstMatch
        if progress.exists {
            let disappeared = XCTNSPredicateExpectation(
                predicate: NSPredicate(format: "exists == false"), object: progress
            )
            XCTAssertEqual(
                XCTWaiter.wait(for: [disappeared], timeout: timeout), .completed,
                "Operation did not return to idle"
            )
        } else {
            _ = app.buttons["Refresh"].firstMatch.waitForExistence(timeout: timeout)
        }
    }

    private func dismissInformationalAlertIfPresent() {
        let alert = app.alerts.firstMatch
        if alert.waitForExistence(timeout: 1) {
            let ok = alert.buttons["OK"].firstMatch
            if ok.exists { ok.click() }
        }
    }

    private func acceptAgreementIfRequired() {
        let accept = app.buttons["AcceptAndContinueButton"].firstMatch
        guard accept.waitForExistence(timeout: 2) else { return }
        let agreement = app.checkBoxes["AcceptAgreementCheckbox"].firstMatch
        let authorization = app.checkBoxes["AuthorizationCertificationCheckbox"].firstMatch
        XCTAssertTrue(agreement.exists, "Agreement acceptance checkbox is missing")
        XCTAssertTrue(authorization.exists, "Authorization certification checkbox is missing")
        XCTAssertTrue(app.buttons["DeclineAgreementButton"].exists,
                      "Explicit decline action is missing")
        XCTAssertTrue(app.scrollViews["EULAFullText"].exists,
                      "Bundled EULA text is not visible")
        XCTAssertFalse(accept.isEnabled, "EULA acceptance was enabled before affirmative action")
        agreement.click()
        authorization.click()
        XCTAssertTrue(accept.isEnabled, "Accept and Continue did not enable after certification")
        accept.click()
        XCTAssertTrue(app.staticTexts["Dashboard"].firstMatch.waitForExistence(timeout: 10),
                      "Bridge did not continue after agreement acceptance")
    }

    private func capture(_ name: String) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
