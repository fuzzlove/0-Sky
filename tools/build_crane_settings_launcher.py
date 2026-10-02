#!/usr/bin/env python3
"""Build the private iOS 27 Crane settings launcher and adapted Debian package."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PACKAGE = (ROOT / "converted/crane-paid-ios27" /
                   "com.opa334.crane_1.3.9+0sky8_iphoneos-arm64.deb")
VERSION = "1.3.9+0sky11"
BUILD_NUMBER = "11"

CRANE_HELPER_SERVICE = "var/jb/Library/LaunchDaemons/com.opa334.cranehelperd.plist"
RUNTIME_MANAGER = "/var/jb/usr/local/libexec/srd-runtime-manager.py"
CRANE_HELPER = "/var/jb/usr/local/libexec/cranehelperd"

SOURCE = r'''
#import <UIKit/UIKit.h>

static NSURL *CraneControlURL(void) {
    return [NSURL URLWithString:@"zerosky-control://tweaks/crane"];
}

@interface CraneLauncherViewController : UIViewController
@end

@implementation CraneLauncherViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    UILabel *title = [[UILabel alloc] init];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = @"Crane";
    title.font = [UIFont preferredFontForTextStyle:UIFontTextStyleLargeTitle];
    title.adjustsFontForContentSizeCategory = YES;

    UILabel *detail = [[UILabel alloc] init];
    detail.translatesAutoresizingMaskIntoConstraints = NO;
    detail.text = @"Crane settings and application containers are managed by 0-Sky Control on this research device.";
    detail.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    detail.adjustsFontForContentSizeCategory = YES;
    detail.numberOfLines = 0;
    detail.textAlignment = NSTextAlignmentCenter;

    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.translatesAutoresizingMaskIntoConstraints = NO;
    [button setTitle:@"Open Crane Settings" forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
    [button addTarget:self action:@selector(openSettings) forControlEvents:UIControlEventTouchUpInside];
    button.accessibilityHint = @"Opens Crane container management in 0-Sky Control";

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[title, detail, button]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.alignment = UIStackViewAlignmentCenter;
    stack.spacing = 24.0;
    [self.view addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [stack.centerXAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.centerXAnchor],
        [stack.centerYAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.centerYAnchor],
        [stack.leadingAnchor constraintGreaterThanOrEqualToAnchor:self.view.safeAreaLayoutGuide.leadingAnchor constant:24.0],
        [stack.trailingAnchor constraintLessThanOrEqualToAnchor:self.view.safeAreaLayoutGuide.trailingAnchor constant:-24.0],
        [detail.widthAnchor constraintLessThanOrEqualToConstant:420.0],
    ]];
}

- (void)openSettings {
    [UIApplication.sharedApplication openURL:CraneControlURL() options:@{} completionHandler:^(BOOL success) {
        if (!success) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"0-Sky Control unavailable"
                message:@"Open 0-Sky Control, then choose Tweaks and Crane."
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"Close" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        }
    }];
}
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@property(nonatomic) BOOL openedControl;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [[CraneLauncherViewController alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    if (self.openedControl) return;
    self.openedControl = YES;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [(CraneLauncherViewController *)self.window.rootViewController openSettings];
    });
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    self.openedControl = NO;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(AppDelegate.class));
    }
}
'''


def run(arguments: list[str], *, timeout: int = 240) -> None:
    completed = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                               capture_output=True, check=False,
                               timeout=timeout)
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", "replace")[-2000:]
        raise RuntimeError(f"{Path(arguments[0]).name} failed: {detail}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def adapt_helper_service(package_root: Path) -> None:
    """Launch Crane's helper through its code-trusted runtime copy.

    A writable-root `/var/jb` executable has no CMS blob on an SRD and AMFI
    rejects it before `main`.  The runtime manager resolves the exact helper
    hash from the active sealed ElleKit Cryptex, then replaces itself with
    those admitted bytes.  Keeping the MachServices in this launchd job gives
    the upstream helper its original XPC endpoints.
    """
    service_path = package_root / CRANE_HELPER_SERVICE
    if not service_path.is_file() or service_path.is_symlink():
        raise ValueError("source package does not contain Crane's helper service")
    service = plistlib.loads(service_path.read_bytes())
    expected_services = {
        "com.opa334.cranehelperd.preferences.xpc": True,
        "com.opa334.cranehelperd.xpc": True,
    }
    if (service.get("Label") != "com.opa334.cranehelperd" or
            service.get("MachServices") != expected_services):
        raise ValueError("Crane helper launch contract differs from the reviewed package")
    service["Program"] = "/var/jb/usr/bin/python3"
    service["ProgramArguments"] = [
        "/var/jb/usr/bin/python3", RUNTIME_MANAGER, "launch-companion",
        "com.opa334.crane", CRANE_HELPER,
    ]
    service_path.write_bytes(plistlib.dumps(service, fmt=plistlib.FMT_BINARY,
                                             sort_keys=True))


def deterministic_ipa(app: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as archive:
        for path in sorted(app.rglob("*")):
            if not path.is_file():
                continue
            relative = Path("Payload") / app.name / path.relative_to(app)
            info = zipfile.ZipInfo(str(relative), (2024, 1, 1, 0, 0, 0))
            info.external_attr = ((0o755 if path.stat().st_mode & 0o111 else 0o644) << 16)
            archive.writestr(info, path.read_bytes())


def build(source_package: Path, output: Path) -> dict[str, str]:
    if not source_package.is_file() or source_package.is_symlink():
        raise FileNotFoundError(source_package)
    output.mkdir(parents=True, exist_ok=True)
    sdk = subprocess.check_output(
        ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
    clang = subprocess.check_output(
        ["xcrun", "--sdk", "iphoneos", "--find", "clang"], text=True).strip()

    with tempfile.TemporaryDirectory(prefix="0sky-crane-launcher-") as raw:
        work = Path(raw)
        package_root = work / "package"
        run(["dpkg-deb", "-R", str(source_package), str(package_root)])
        app = package_root / "var/jb/Applications/CraneApplication.app"
        executable = app / "CraneApplication"
        if not executable.is_file() or not (app / "Info.plist").is_file():
            raise ValueError("source package does not contain CraneApplication.app")

        # This derivative is a settings launcher. The upstream Siri Shortcuts
        # extension controls Crane directly and requires separate extension
        # registration and entitlements that the launcher neither uses nor
        # claims. Excluding it also prevents a partially registered helper
        # bundle when the SRD installs the launcher through appregistrard.
        plugins = app / "PlugIns"
        if plugins.exists():
            if plugins.is_symlink() or not plugins.is_dir():
                raise ValueError("Crane launcher PlugIns path is unsafe")
            shutil.rmtree(plugins)

        source = work / "CraneLauncher.m"
        source.write_text(SOURCE, encoding="utf-8")
        run([clang, "-fobjc-arc", "-target", "arm64-apple-ios17.0",
             "-isysroot", sdk, "-Os", "-framework", "UIKit", "-framework",
             "Foundation", str(source), "-o", str(executable)])
        run(["codesign", "--force", "--sign", "-", "--timestamp=none", str(executable)])

        info_path = app / "Info.plist"
        info = plistlib.loads(info_path.read_bytes())
        for key in ("BuildMachineOSBuild", "DTCompiler", "DTPlatformBuild",
                    "DTPlatformName", "DTPlatformVersion", "DTSDKBuild",
                    "DTSDKName", "DTXcode", "DTXcodeBuild", "SBAppTags",
                    "UIApplicationSceneManifest", "UIMainStoryboardFile"):
            info.pop(key, None)
        info.update({
            "CFBundleDisplayName": "Crane",
            "CFBundleExecutable": "CraneApplication",
            "CFBundleIdentifier": "com.opa334.CraneApplication",
            "CFBundleShortVersionString": "1.3.9",
            "CFBundleVersion": BUILD_NUMBER,
            "MinimumOSVersion": "17.0",
            "NSHumanReadableCopyright": "Crane by opa334; iOS 27 launcher adapted by 0-Sky",
        })
        info_path.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY,
                                             sort_keys=True))
        run(["codesign", "--force", "--sign", "-", "--timestamp=none", str(app)])

        # Upstream CranePrefs contains local build paths in removable Mach-O
        # debug records. Strip only debug symbols, then restore its ad-hoc seal;
        # executable code and runtime symbols remain unchanged.
        preferences = (package_root / "var/jb/Library/PreferenceBundles" /
                       "CranePrefs.bundle/CranePrefs")
        if preferences.is_file():
            run(["xcrun", "install_name_tool", "-id", "@rpath/CranePrefs",
                 str(preferences)])
            run(["xcrun", "strip", "-S", str(preferences)])
            run(["codesign", "--force", "--sign", "-", "--timestamp=none",
                 "--preserve-metadata=entitlements", str(preferences)])

        adapt_helper_service(package_root)

        control_path = package_root / "DEBIAN/control"
        control = control_path.read_text(encoding="utf-8")
        lines = []
        for line in control.splitlines():
            if line.startswith("Version:"):
                line = f"Version: {VERSION}"
            elif line.startswith("Installed-Size:"):
                continue
            elif line.startswith(("X-0-Sky-Launcher-Adapter:",
                                  "X-0-Sky-Launcher-Source-SHA256:")):
                continue
            lines.append(line)
        lines += [
            "X-0-Sky-Launcher-Adapter: control-route-v1",
            f"X-0-Sky-Launcher-Source-SHA256: {sha256(source_package)}",
        ]
        control_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        deb = output / f"com.opa334.crane_{VERSION}_iphoneos-arm64.deb"
        run(["dpkg-deb", "--root-owner-group", "-b", str(package_root), str(deb)])
        ipa = output / f"CraneApplication-{VERSION}.ipa"
        deterministic_ipa(app, ipa)

        manifest = {
            "adapter": "crane-settings-control-route-v1",
            "bundle_identifier": "com.opa334.CraneApplication",
            "control_url": "zerosky-control://tweaks/crane",
            "helper_service_adapter": "sealed-companion-launch-v1",
            "removed_launcher_components": ["CraneShortcuts.appex"],
            "original_package": source_package.name,
            "original_sha256": sha256(source_package),
            "converted_package": deb.name,
            "converted_sha256": sha256(deb),
            "launcher_ipa": ipa.name,
            "launcher_ipa_sha256": sha256(ipa),
            "version": VERSION,
        }
        manifest_path = output / f"com.opa334.crane_{VERSION}.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        return {key: str(value) for key, value in manifest.items()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-package", type=Path, default=DEFAULT_PACKAGE)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "converted/crane-paid-ios27")
    args = parser.parse_args()
    print(json.dumps(build(args.source_package.resolve(), args.output.resolve()),
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
