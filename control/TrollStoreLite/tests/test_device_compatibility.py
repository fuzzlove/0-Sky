#!/usr/bin/env python3
"""Regression checks for one 0-Sky Control build serving iPhone and iPad."""
import pathlib, plistlib, re, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT.parent / "TrollStore" / "TSAppTableViewController.m"
ROOT_CONTROLLER = ROOT.parent / "TrollStore" / "TSRootViewController.m"
HEALTH_CONTROLLER = ROOT.parent / "TrollStore" / "TSHealthTableViewController.m"
ACTIVITY_CONTROLLER = ROOT.parent / "TrollStore" / "TSActivityTableViewController.m"
RECOVERY_CONTROLLER = ROOT.parent / "TrollStore" / "TSRecoveryTableViewController.m"
SNAPSHOT_CONTROLLER = ROOT.parent / "TrollStore" / "TSSnapshotsTableViewController.m"
AUTOMATION_CONTROLLER = ROOT.parent / "TrollStore" / "TSAutomationTableViewController.m"
INTELLIGENCE_CONTROLLER = ROOT.parent / "TrollStore" / "TSIntelligenceTableViewController.m"
CONTROL_CENTER = ROOT.parent / "TrollStore" / "TSControlCenterTableViewController.m"
INVENTORY_CONTROLLER = ROOT.parent / "TrollStore" / "TSInventoryTableViewController.m"
COMPATIBILITY_CONTROLLER = ROOT.parent / "TrollStore" / "TSCompatibilityTableViewController.m"
CRANE_CONTROLLER = ROOT.parent / "TrollStore" / "TSCraneSettingsViewController.m"
SCENE_DELEGATE = ROOT.parent / "TrollStore" / "TSSceneDelegate.m"
BLUETOOTH_FALLBACK = ROOT.parent / "TrollStore" / "TSBluetoothFallback.m"
INFO_PLIST = ROOT / "Resources" / "Info.plist"
CONTROL = ROOT / "control"

class DeviceCompatibilityTests(unittest.TestCase):
    def test_declares_iphone_and_ipad(self):
        info = plistlib.loads(INFO_PLIST.read_bytes())
        self.assertEqual(info["CFBundleIdentifier"], "com.liquidsky.CrypStore")
        self.assertEqual(info["CFBundleExecutable"], "CrypStore")
        self.assertEqual(info["CFBundleDisplayName"], "0-Sky Control")
        self.assertEqual(info["CFBundleName"], "0-Sky Control")
        package_version = re.search(r"(?m)^Version:\s*(\S+)$", CONTROL.read_text()).group(1)
        self.assertEqual(info["CFBundleShortVersionString"], package_version)
        self.assertRegex(info["CFBundleVersion"],
                         r"^" + re.escape(info["CFBundleShortVersionString"]) + r"\.\d+$")
        self.assertEqual(set(info["UIDeviceFamily"]), {1, 2})
        self.assertIn("Crane", info.get("NSFaceIDUsageDescription", ""))

    def test_table_reload_uses_one_bounded_snapshot(self):
        source = SOURCE.read_text()
        self.assertIn("appInfoForIndexPath", source)
        self.assertIn("indexPath.row >= appInfos.count", source)
        self.assertNotIn("indexPath.row > (_cachedAppInfos.count - 1)", source)
        direct = re.findall(r"_cachedAppInfos\s*\[\s*indexPath\.row\s*\]", source)
        self.assertEqual(direct, [], "event handlers must use the bounded snapshot helper")

    def test_async_icon_reload_handles_disappearing_row(self):
        source = SOURCE.read_text()
        self.assertIn("if(row == NSNotFound) return;", source)

    def test_inventory_merges_runtime_health_with_local_metadata_and_icons(self):
        source = INVENTORY_CONTROLLER.read_text()
        self.assertIn("arrayByAddingObjectsFromArray:localTweaks", source)
        self.assertIn('@"name", @"version", @"description", @"preference_title"', source)
        self.assertIn("TSPreferenceIconPath", source)
        self.assertIn("imageWithContentsOfFile:iconPath", source)

    def test_crane_container_delete_uses_verified_bridge_cleanup(self):
        source = CRANE_CONTROLLER.read_text()
        self.assertIn("TSInstallCraneDeleteAdapter", source)
        self.assertIn("deleteContainerWithIdentifier:forApplicationWithIdentifier:", source)
        self.assertIn('coreRequestOperation:@"cleanupCraneContainer"', source)
        self.assertIn("Container cleanup requires attention", source)

    def test_crane_targets_use_paired_mcm_handoffs(self):
        source = CRANE_CONTROLLER.read_text()
        self.assertIn('@"dataRoots": dataRoots', source)
        self.assertIn("TSValidatedMCMDataRoot", source)
        self.assertIn('pathsAssociatedToContainerWithIdentifier:@"DEFAULT"', source)
        load_targets = source[source.index("- (void)loadTargets"):
                              source.index("- (NSInteger)numberOfSections")]
        self.assertNotIn('coreRequestOperation:@"setTweakTargets"', load_targets)

    def test_crane_home_icon_has_a_deterministic_control_route(self):
        info = plistlib.loads(INFO_PLIST.read_bytes())
        schemes = {
            scheme
            for url_type in info.get("CFBundleURLTypes", [])
            for scheme in url_type.get("CFBundleURLSchemes", [])
        }
        self.assertIn("zerosky-control", schemes)
        scene = SCENE_DELEGATE.read_text()
        root = ROOT_CONTROLLER.read_text()
        self.assertIn('@"zerosky-control"', scene)
        self.assertIn('@"tweaks"', scene)
        self.assertIn('@"/crane"', scene)
        self.assertIn("openCraneSettings]", scene)
        self.assertIn("- (void)openCraneSettings", root)
        self.assertIn("self.selectedIndex = 2", root)
        self.assertIn("TSCraneSettingsViewController", root)
        self.assertIn("dismissViewControllerAnimated:NO completion:route", root)
        self.assertIn("[controller openNativeContainerManager]", root)
        crane = CRANE_CONTROLLER.read_text()
        self.assertIn('@"Native Crane Settings"', crane)
        self.assertNotIn("TSInlinePreferenceTableViewController", crane)

    def test_bluetooth_fallback_requires_explicit_opt_in(self):
        source = BLUETOOTH_FALLBACK.read_text()
        self.assertIn("setBool:NO forKey:TSBLEEnabledKey", source)
        self.assertNotIn("setBool:YES forKey:TSBLEEnabledKey];\n    if(!", source)

    def test_health_dashboard_is_shared_by_phone_and_ipad(self):
        root = ROOT_CONTROLLER.read_text()
        center = CONTROL_CENTER.read_text()
        health = HEALTH_CONTROLLER.read_text()
        self.assertIn("TSControlCenterTableViewController", root)
        self.assertIn("TSHealthTableViewController", center)
        self.assertIn("UITableViewStyleInsetGrouped", health)
        self.assertIn("dispatch_get_global_queue", health)
        self.assertIn("UIApplicationDidBecomeActiveNotification", health)
        self.assertNotIn("scheduledTimer", health)
        self.assertIn("never substitutes fake readings", health)
        self.assertIn('getHealthTimeline', health)
        self.assertIn('@[@"Today", @"7 Days", @"30 Days"]', health)
        self.assertIn('@"Battery Impact"', health)
        self.assertIn('Correlated estimate', health)
        self.assertIn('@"Charging Management"', health)
        self.assertIn('Monitor Only', health)
        self.assertIn('publishPowerTelemetry', health)
        self.assertIn('batteryMonitoringEnabled = YES', health)
        self.assertIn('UIDeviceBatteryStateUnknown', health)
        self.assertIn('NSProcessInfo.processInfo.thermalState', health)
        self.assertIn('NSProcessInfo.processInfo.lowPowerModeEnabled', health)
        self.assertNotIn('@"levelPercent": @0', health)
        self.assertIn('publishPowerTelemetry', center)
        self.assertIn('UIDeviceBatteryStateUnknown', center)

    def test_activity_dashboard_is_observation_only_and_shared(self):
        center = CONTROL_CENTER.read_text()
        activity = ACTIVITY_CONTROLLER.read_text()
        self.assertIn("TSActivityTableViewController", center)
        self.assertIn('@[@"Network", @"Privacy"]', activity)
        self.assertIn('@"getConnections"', activity)
        self.assertIn('@"getPrivacyEvents"', activity)
        self.assertIn("TSPrivacyHistoryTableViewController", activity)
        self.assertIn("didSelectRowAtIndexPath", activity)
        self.assertIn("UITableViewCellAccessoryDisclosureIndicator", activity)
        self.assertIn("No firewall control is presented", activity)
        self.assertIn("Unsupported never means zero accesses", activity)
        self.assertNotIn("scheduledTimer", activity)

    def test_recovery_and_package_health_are_shared_by_phone_and_ipad(self):
        center = CONTROL_CENTER.read_text()
        recovery = RECOVERY_CONTROLLER.read_text()
        inventory = INVENTORY_CONTROLLER.read_text()
        self.assertIn("TSRecoveryTableViewController", center)
        for operation in ("restartNormally", "disableRecentTweaks",
                          "disableSelectedTweak", "startWithoutTweaks"):
            self.assertIn(operation, recovery)
        self.assertIn("No package will be deleted", recovery)
        self.assertIn("popoverPresentationController.sourceView", recovery)
        self.assertNotIn("scheduledTimer", recovery)
        self.assertIn('getRecoveryOptions', recovery)
        self.assertIn('Database reset is never exposed', recovery)
        self.assertIn('@"getPackages"', inventory)
        self.assertIn('@"getPackageDetail"', inventory)
        self.assertIn('[@"health"]', inventory)

    def test_snapshot_rollback_ui_is_shared_and_ipad_safe(self):
        center = CONTROL_CENTER.read_text()
        snapshots = SNAPSHOT_CONTROLLER.read_text()
        self.assertIn("TSSnapshotsTableViewController", center)
        for operation in ("getSnapshotCapability", "getSnapshotApps", "getSnapshots",
                          "createSnapshot", "restoreSnapshot", "deleteSnapshot",
                          "undoChange"):
            self.assertIn(operation, snapshots)
        self.assertIn("popoverPresentationController", snapshots)
        self.assertIn("keychain databases", snapshots.lower())
        self.assertIn("creates a safety snapshot", snapshots)
        self.assertNotIn("scheduledTimer", snapshots)

    def test_profiles_automation_and_freeze_are_shared_and_ipad_safe(self):
        center = CONTROL_CENTER.read_text()
        automation = AUTOMATION_CONTROLLER.read_text()
        self.assertIn("TSAutomationTableViewController", center)
        for operation in ("getProfileCapability", "getProfiles", "applyProfile",
                          "getFrozenApps", "freezeApp", "temporarilyActivateApp",
                          "unfreezeApp", "getAutomationRules", "getAutomationHistory"):
            self.assertIn(operation, automation)
        self.assertIn("popoverPresentationController", automation)
        self.assertIn("Arbitrary commands", automation)
        self.assertIn("App data is never modified", automation)
        self.assertNotIn("scheduledTimer", automation)

    def test_storage_notification_and_permission_ui_is_shared_and_safe(self):
        center = CONTROL_CENTER.read_text()
        intelligence = INTELLIGENCE_CONTROLLER.read_text()
        self.assertIn("TSIntelligenceTableViewController", center)
        for operation in ("getStorageIntelligence", "getNotificationAnalytics",
                          "getPermissionTimeouts", "setTemporaryPermission",
                          "revertPermissionTimeout"):
            self.assertIn(operation, intelligence)
        self.assertIn("popoverPresentationController", intelligence)
        self.assertIn("never recursively deletes", intelligence)
        self.assertIn("never stored or uploaded", intelligence)
        self.assertIn("Controls remain disabled", intelligence)
        self.assertNotIn("scheduledTimer", intelligence)

    def test_control_center_is_problem_first_accessible_and_compact(self):
        root = ROOT_CONTROLLER.read_text()
        center = CONTROL_CENTER.read_text()
        self.assertIn('coreRequestOperation:@"getControlCenterSummary"', center)
        for heading in ("CURRENT STATUS", "DEVICE", "SECURITY", "APPLICATIONS",
                        "JAILBREAK", "AUTOMATION", "SYSTEM"):
            self.assertIn(heading, center)
        self.assertIn("preferredFontForTextStyle", center)
        self.assertIn("adjustsFontForContentSizeCategory", center)
        self.assertIn("accessibilityLabel", center)
        self.assertIn("accessibilityHint", center)
        self.assertIn("UIAccessibilityIsReduceMotionEnabled", center)
        self.assertIn("Missing telemetry is shown as unavailable", center)
        self.assertNotIn("scheduledTimer", center)
        self.assertIn("self.viewControllers = @[controlCenterNavigationController", root)
        self.assertNotIn("healthNavigationController", root)

    def test_compatibility_view_handles_json_null_values(self):
        source = COMPATIBILITY_CONTROLLER.read_text()
        self.assertIn("TSCompatibilityString", source)
        self.assertIn("TSCompatibilityDictionary", source)
        self.assertIn("TSCompatibilityArray", source)
        self.assertNotIn('component[@"compatibility_state"] ?:', source)
        self.assertNotIn('component[@"runtime_validation"][@"communication"]', source)

if __name__ == "__main__":
    unittest.main()
