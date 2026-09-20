#!/usr/bin/env python3
"""Generate the checked-in 0SkyBridge.xcodeproj without external packages."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "0SkyBridge.xcodeproj"


def oid(name: str) -> str:
    return hashlib.sha1(name.encode()).hexdigest().upper()[:24]


core = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "BridgeCore").glob("*.swift"))
app = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "0SkyBridge").glob("*.swift"))
helper = ["0SkyBridgeHelper/main.swift"]
service = ["0SkyBridgeService/main.swift"]
ui_tests = ["Tests/BridgeScreenSmokeTests/BridgeScreenSmokeTests.swift"]
resources = [
    "0SkyBridge/Resources/bridge-operations.json",
    "0SkyBridge/Resources/AppIcon.icns",
]
daemon = "0SkyBridge/Resources/com.liquidsky.0sky.bridge.helper.plist"
agent = "0SkyBridge/Resources/com.liquidsky.0sky.bridge.service.plist"
all_files = core + app + helper + service + ui_tests + resources + [daemon, agent]

objects: list[str] = []


def obj(identifier: str, body: str) -> None:
    objects.append(f"\t\t{identifier} = {{\n{body}\n\t\t}};")


refs: dict[str, str] = {}
for path in all_files:
    ident = oid("fileref:" + path)
    refs[path] = ident
    ext = Path(path).suffix
    file_type = {
        ".swift": "sourcecode.swift",
        ".json": "text.json",
        ".plist": "text.plist.xml",
        ".icns": "image.icns",
    }[ext]
    relative_name = ("Resources/" + Path(path).name
                     if path.startswith("0SkyBridge/Resources/") else Path(path).name)
    obj(ident, f"\t\t\tisa = PBXFileReference; lastKnownFileType = {file_type}; path = \"{relative_name}\"; sourceTree = \"<group>\";")

product_app = oid("product:app")
product_helper = oid("product:helper")
product_service = oid("product:service")
product_core = oid("product:core")
product_ui_tests = oid("product:ui-tests")
obj(product_app, "\t\t\tisa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = 0SkyBridge.app; sourceTree = BUILT_PRODUCTS_DIR;")
obj(product_helper, "\t\t\tisa = PBXFileReference; explicitFileType = \"compiled.mach-o.executable\"; includeInIndex = 0; path = 0SkyBridgeHelper; sourceTree = BUILT_PRODUCTS_DIR;")
obj(product_service, "\t\t\tisa = PBXFileReference; explicitFileType = \"compiled.mach-o.executable\"; includeInIndex = 0; path = 0SkyBridgeService; sourceTree = BUILT_PRODUCTS_DIR;")
obj(product_core, "\t\t\tisa = PBXFileReference; explicitFileType = archive.ar; includeInIndex = 0; path = libBridgeCore.a; sourceTree = BUILT_PRODUCTS_DIR;")
obj(product_ui_tests, "\t\t\tisa = PBXFileReference; explicitFileType = wrapper.cfbundle; includeInIndex = 0; path = 0SkyBridgeScreenSmokeTests.xctest; sourceTree = BUILT_PRODUCTS_DIR;")


def build_file(key: str, file_ref: str, settings: str = "") -> str:
    ident = oid("build:" + key)
    suffix = f" settings = {{{settings}}};" if settings else ""
    obj(ident, f"\t\t\tisa = PBXBuildFile; fileRef = {file_ref};{suffix}")
    return ident


core_build = [build_file("core:" + p, refs[p]) for p in core]
app_build = [build_file("app:" + p, refs[p]) for p in app]
helper_build = [build_file("helper:" + p, refs[p]) for p in helper]
service_build = [build_file("service:" + p, refs[p]) for p in service]
ui_test_build = [build_file("ui-test:" + p, refs[p]) for p in ui_tests]
resource_build = [build_file("resource:" + p, refs[p]) for p in resources]
app_core_link = build_file("app:core-link", product_core)
helper_core_link = build_file("helper:core-link", product_core)
helper_embed = build_file("app:helper-embed", product_helper, "ATTRIBUTES = (CodeSignOnCopy, ); ")
service_embed = build_file("app:service-embed", product_service, "ATTRIBUTES = (CodeSignOnCopy, ); ")
daemon_embed = build_file("app:daemon-embed", refs[daemon])
agent_embed = build_file("app:agent-embed", refs[agent])


def group(name: str, paths: list[str], parent_path: str | None = None) -> str:
    ident = oid("group:" + name)
    children = ",\n".join(f"\t\t\t\t{refs[p]} /* {Path(p).name} */" for p in paths)
    path_line = f"\n\t\t\tpath = {parent_path};" if parent_path else ""
    obj(ident, f"\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n{children},\n\t\t\t);{path_line}\n\t\t\tsourceTree = \"<group>\";")
    return ident


core_group = group("BridgeCore", core, "BridgeCore")
app_group = group("0SkyBridge", app + resources + [daemon, agent], "0SkyBridge")
helper_group = group("0SkyBridgeHelper", helper, "0SkyBridgeHelper")
service_group = group("0SkyBridgeService", service, "0SkyBridgeService")
ui_test_group = group("BridgeScreenSmokeTests", ui_tests, "Tests/BridgeScreenSmokeTests")
products_group = oid("group:Products")
obj(products_group, f"\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t{product_app},\n\t\t\t\t{product_helper},\n\t\t\t\t{product_service},\n\t\t\t\t{product_core},\n\t\t\t\t{product_ui_tests},\n\t\t\t);\n\t\t\tname = Products;\n\t\t\tsourceTree = \"<group>\";")
main_group = oid("group:main")
obj(main_group, f"\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t{app_group},\n\t\t\t\t{helper_group},\n\t\t\t\t{service_group},\n\t\t\t\t{core_group},\n\t\t\t\t{ui_test_group},\n\t\t\t\t{products_group},\n\t\t\t);\n\t\t\tsourceTree = \"<group>\";")


def phase(kind: str, key: str, files: list[str], extra: str = "") -> str:
    ident = oid(f"phase:{key}:{kind}")
    file_lines = ",\n".join(f"\t\t\t\t{x}" for x in files)
    rendered_files = f"{file_lines},\n" if file_lines else ""
    obj(ident, f"\t\t\tisa = {kind};\n\t\t\tbuildActionMask = 2147483647;\n{extra}\t\t\tfiles = (\n{rendered_files}\t\t\t);\n\t\t\trunOnlyForDeploymentPostprocessing = 0;")
    return ident


core_sources = phase("PBXSourcesBuildPhase", "core", core_build)
core_frameworks = phase("PBXFrameworksBuildPhase", "core", [])
app_sources = phase("PBXSourcesBuildPhase", "app", app_build)
app_frameworks = phase("PBXFrameworksBuildPhase", "app", [app_core_link])
app_resources = phase("PBXResourcesBuildPhase", "app", resource_build)
helper_sources = phase("PBXSourcesBuildPhase", "helper", helper_build)
helper_frameworks = phase("PBXFrameworksBuildPhase", "helper", [helper_core_link])
service_sources = phase("PBXSourcesBuildPhase", "service", service_build)
service_core_link = build_file("service:core-link", product_core)
service_frameworks = phase("PBXFrameworksBuildPhase", "service", [service_core_link])
ui_test_sources = phase("PBXSourcesBuildPhase", "ui-tests", ui_test_build)
ui_test_frameworks = phase("PBXFrameworksBuildPhase", "ui-tests", [])
copy_helper = phase(
    "PBXCopyFilesBuildPhase", "helper-embed", [helper_embed],
    "\t\t\tdstPath = \"Contents/Library/LaunchServices\";\n\t\t\tdstSubfolderSpec = 1;\n\t\t\tname = \"Embed Privileged Helper\";\n",
)
copy_daemon = phase(
    "PBXCopyFilesBuildPhase", "daemon-embed", [daemon_embed],
    "\t\t\tdstPath = \"Contents/Library/LaunchDaemons\";\n\t\t\tdstSubfolderSpec = 1;\n\t\t\tname = \"Embed Helper Registration\";\n",
)
copy_service = phase(
    "PBXCopyFilesBuildPhase", "service-embed", [service_embed],
    "\t\t\tdstPath = \"Contents/MacOS\";\n\t\t\tdstSubfolderSpec = 1;\n\t\t\tname = \"Embed Bridge Service\";\n",
)
copy_agent = phase(
    "PBXCopyFilesBuildPhase", "agent-embed", [agent_embed],
    "\t\t\tdstPath = \"Contents/Library/LaunchAgents\";\n\t\t\tdstSubfolderSpec = 1;\n\t\t\tname = \"Embed Bridge Service Registration\";\n",
)
kit_phase = oid("phase:kit")
script = "KIT=\\\"${SRCROOT}/exploitdev/srdsh-work/components/zero-sky/kit\\\"\\n[[ -d \\\"${KIT}/host-mac\\\" ]] || KIT=\\\"${SRCROOT}/kit\\\"\\n[[ -d \\\"${KIT}/host-mac\\\" ]] || KIT=\\\"${SRCROOT}/../kit\\\"\\n[[ -d \\\"${KIT}/host-mac\\\" ]] || { echo 'verified 0-Sky kit not found' >&2; exit 1; }\\nHOST=\\\"${SRCROOT}\\\"\\n[[ -f \\\"${HOST}/macos_host_setup.py\\\" ]] || HOST=\\\"${SRCROOT}/..\\\"\\n[[ -f \\\"${HOST}/macos_host_setup.py\\\" ]] || { echo 'macOS host setup sources not found' >&2; exit 1; }\\nRES=\\\"${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/Resources\\\"\\nmkdir -p \\\"${RES}/Kit\\\" \\\"${RES}/Scripts\\\"\\n/usr/bin/ditto --noqtn \\\"${KIT}\\\" \\\"${RES}/Kit\\\"\\n/usr/bin/ditto --noqtn \\\"${HOST}/macos_host_setup.py\\\" \\\"${RES}/Scripts/macos_host_setup.py\\\"\\n/usr/bin/ditto --noqtn \\\"${HOST}/zero_sky_user_config.py\\\" \\\"${RES}/Scripts/zero_sky_user_config.py\\\"\\n/usr/bin/ditto --noqtn \\\"${SRCROOT}/0SkyBridge/Resources/Scripts/Install 0-Sky Dependencies.command\\\" \\\"${RES}/Scripts/Install 0-Sky Dependencies.command\\\"\\nchmod -R u=rwX,go=rX \\\"${RES}\\\""
obj(kit_phase, f"\t\t\tisa = PBXShellScriptBuildPhase;\n\t\t\talwaysOutOfDate = 1;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = ();\n\t\t\tinputPaths = ();\n\t\t\tname = \"Embed Verified Enrollment Kit\";\n\t\t\toutputPaths = ();\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n\t\t\tshellPath = \"/bin/zsh\";\n\t\t\tshellScript = \"{script}\";")

core_target = oid("target:core")
app_target = oid("target:app")
helper_target = oid("target:helper")
service_target = oid("target:service")
ui_test_target = oid("target:ui-tests")


def dependency(owner: str, target: str, target_id: str) -> str:
    proxy = oid(f"proxy:{owner}:{target}")
    dep = oid(f"dependency:{owner}:{target}")
    obj(proxy, f"\t\t\tisa = PBXContainerItemProxy;\n\t\t\tcontainerPortal = {oid('project')};\n\t\t\tproxyType = 1;\n\t\t\tremoteGlobalIDString = {target_id};\n\t\t\tremoteInfo = {target};")
    obj(dep, f"\t\t\tisa = PBXTargetDependency; target = {target_id}; targetProxy = {proxy};")
    return dep


app_core_dep = dependency("app", "BridgeCore", core_target)
app_helper_dep = dependency("app", "0SkyBridgeHelper", helper_target)
app_service_dep = dependency("app", "0SkyBridgeService", service_target)
helper_core_dep = dependency("helper", "BridgeCore", core_target)
service_core_dep = dependency("service", "BridgeCore", core_target)
ui_test_app_dep = dependency("ui-tests", "0SkyBridge", app_target)


def config(key: str, name: str, settings: dict[str, str]) -> str:
    ident = oid(f"config:{key}:{name}")
    lines = "\n".join(f"\t\t\t\t{k} = {v};" for k, v in settings.items())
    obj(ident, f"\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = {{\n{lines}\n\t\t\t}};\n\t\t\tname = {name};")
    return ident


def config_list(key: str, debug: str, release: str) -> str:
    ident = oid("configlist:" + key)
    obj(ident, f"\t\t\tisa = XCConfigurationList;\n\t\t\tbuildConfigurations = (\n\t\t\t\t{debug},\n\t\t\t\t{release},\n\t\t\t);\n\t\t\tdefaultConfigurationIsVisible = 0;\n\t\t\tdefaultConfigurationName = Release;")
    return ident


base = {
    "CLANG_ENABLE_MODULES": "YES",
    "MACOSX_DEPLOYMENT_TARGET": "15.0",
    "SDKROOT": "macosx",
    "SWIFT_VERSION": "6.0",
}
project_debug = config("project", "Debug", {**base, "SWIFT_OPTIMIZATION_LEVEL": '"-Onone"'})
project_release = config("project", "Release", {**base, "SWIFT_COMPILATION_MODE": "wholemodule"})
project_configs = config_list("project", project_debug, project_release)

core_settings = {
    "DEFINES_MODULE": "YES", "MACH_O_TYPE": "staticlib",
    "PRODUCT_BUNDLE_IDENTIFIER": "com.liquidsky.0sky.bridge.core",
    "PRODUCT_NAME": "BridgeCore", "SKIP_INSTALL": "YES",
}
core_configs = config_list("core", config("core", "Debug", core_settings), config("core", "Release", core_settings))
app_settings = {
    "CODE_SIGN_ENTITLEMENTS": '"0SkyBridge/0SkyBridge.entitlements"',
    "CODE_SIGN_STYLE": "Automatic", "CURRENT_PROJECT_VERSION": "1",
    "GENERATE_INFOPLIST_FILE": "NO", "INFOPLIST_FILE": '"0SkyBridge/Info.plist"',
    "MARKETING_VERSION": "1.0.0", "PRODUCT_BUNDLE_IDENTIFIER": "com.liquidsky.0sky.bridge",
    "PRODUCT_NAME": "0SkyBridge",
}
app_configs = config_list("app", config("app", "Debug", app_settings), config("app", "Release", app_settings))
helper_settings = {
    "CODE_SIGN_ENTITLEMENTS": '"0SkyBridgeHelper/0SkyBridgeHelper.entitlements"',
    "CODE_SIGN_STYLE": "Automatic", "GENERATE_INFOPLIST_FILE": "YES",
    "LD_RUNPATH_SEARCH_PATHS": '"@executable_path/../../Frameworks"',
    "PRODUCT_BUNDLE_IDENTIFIER": "com.liquidsky.0sky.bridge.helper",
    "PRODUCT_NAME": "0SkyBridgeHelper", "SKIP_INSTALL": "YES",
}
helper_configs = config_list("helper", config("helper", "Debug", helper_settings), config("helper", "Release", helper_settings))
service_settings = {
    "CODE_SIGN_ENTITLEMENTS": '"0SkyBridgeService/0SkyBridgeService.entitlements"',
    "CODE_SIGN_STYLE": "Automatic", "GENERATE_INFOPLIST_FILE": "YES",
    "LD_RUNPATH_SEARCH_PATHS": '"@executable_path/../../Frameworks"',
    "PRODUCT_BUNDLE_IDENTIFIER": "com.liquidsky.0sky.bridge.service",
    "PRODUCT_NAME": "0SkyBridgeService", "SKIP_INSTALL": "YES",
}
service_configs = config_list("service", config("service", "Debug", service_settings), config("service", "Release", service_settings))
ui_test_settings = {
    "CODE_SIGN_STYLE": "Automatic", "GENERATE_INFOPLIST_FILE": "YES",
    "PRODUCT_BUNDLE_IDENTIFIER": "com.liquidsky.0sky.bridge.screen-smoke-tests",
    "PRODUCT_NAME": "0SkyBridgeScreenSmokeTests", "TEST_TARGET_NAME": "0SkyBridge",
}
ui_test_configs = config_list("ui-tests", config("ui-tests", "Debug", ui_test_settings), config("ui-tests", "Release", ui_test_settings))

obj(core_target, f"\t\t\tisa = PBXNativeTarget;\n\t\t\tbuildConfigurationList = {core_configs};\n\t\t\tbuildPhases = ({core_sources}, {core_frameworks}, );\n\t\t\tbuildRules = ();\n\t\t\tdependencies = ();\n\t\t\tname = BridgeCore;\n\t\t\tproductName = BridgeCore;\n\t\t\tproductReference = {product_core};\n\t\t\tproductType = \"com.apple.product-type.library.static\";")
obj(helper_target, f"\t\t\tisa = PBXNativeTarget;\n\t\t\tbuildConfigurationList = {helper_configs};\n\t\t\tbuildPhases = ({helper_sources}, {helper_frameworks}, );\n\t\t\tbuildRules = ();\n\t\t\tdependencies = ({helper_core_dep}, );\n\t\t\tname = 0SkyBridgeHelper;\n\t\t\tproductName = 0SkyBridgeHelper;\n\t\t\tproductReference = {product_helper};\n\t\t\tproductType = \"com.apple.product-type.tool\";")
obj(service_target, f"\t\t\tisa = PBXNativeTarget;\n\t\t\tbuildConfigurationList = {service_configs};\n\t\t\tbuildPhases = ({service_sources}, {service_frameworks}, );\n\t\t\tbuildRules = ();\n\t\t\tdependencies = ({service_core_dep}, );\n\t\t\tname = 0SkyBridgeService;\n\t\t\tproductName = 0SkyBridgeService;\n\t\t\tproductReference = {product_service};\n\t\t\tproductType = \"com.apple.product-type.tool\";")
obj(app_target, f"\t\t\tisa = PBXNativeTarget;\n\t\t\tbuildConfigurationList = {app_configs};\n\t\t\tbuildPhases = ({app_sources}, {app_frameworks}, {app_resources}, {copy_helper}, {copy_daemon}, {copy_service}, {copy_agent}, {kit_phase}, );\n\t\t\tbuildRules = ();\n\t\t\tdependencies = ({app_core_dep}, {app_helper_dep}, {app_service_dep}, );\n\t\t\tname = 0SkyBridge;\n\t\t\tproductName = 0SkyBridge;\n\t\t\tproductReference = {product_app};\n\t\t\tproductType = \"com.apple.product-type.application\";")
obj(ui_test_target, f"\t\t\tisa = PBXNativeTarget;\n\t\t\tbuildConfigurationList = {ui_test_configs};\n\t\t\tbuildPhases = ({ui_test_sources}, {ui_test_frameworks}, );\n\t\t\tbuildRules = ();\n\t\t\tdependencies = ({ui_test_app_dep}, );\n\t\t\tname = 0SkyBridgeScreenSmokeTests;\n\t\t\tproductName = 0SkyBridgeScreenSmokeTests;\n\t\t\tproductReference = {product_ui_tests};\n\t\t\tproductType = \"com.apple.product-type.bundle.ui-testing\";")

project_id = oid("project")
obj(project_id, f"\t\t\tisa = PBXProject;\n\t\t\tattributes = {{ BuildIndependentTargetsInParallel = 1; LastSwiftUpdateCheck = 2660; LastUpgradeCheck = 2660; TargetAttributes = {{ {ui_test_target} = {{ TestTargetID = {app_target}; }}; }}; }};\n\t\t\tbuildConfigurationList = {project_configs};\n\t\t\tcompatibilityVersion = \"Xcode 16.0\";\n\t\t\tdevelopmentRegion = en;\n\t\t\thasScannedForEncodings = 0;\n\t\t\tknownRegions = (en, Base, );\n\t\t\tmainGroup = {main_group};\n\t\t\tproductRefGroup = {products_group};\n\t\t\tprojectDirPath = \"\";\n\t\t\tprojectRoot = \"\";\n\t\t\ttargets = ({app_target}, {helper_target}, {service_target}, {core_target}, {ui_test_target}, );")

contents = "// !$*UTF8*$!\n{\n\tarchiveVersion = 1;\n\tclasses = {};\n\tobjectVersion = 77;\n\tobjects = {\n" + "\n".join(objects) + f"\n\t}};\n\trootObject = {project_id};\n}}\n"
PROJECT.mkdir(exist_ok=True)
(PROJECT / "project.pbxproj").write_text(contents)

scheme_dir = PROJECT / "xcshareddata/xcschemes"
scheme_dir.mkdir(parents=True, exist_ok=True)
scheme_dir.joinpath("0SkyBridge.xcscheme").write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="2660" version="1.7">
  <BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES">
    <BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{app_target}" BuildableName="0SkyBridge.app" BlueprintName="0SkyBridge" ReferencedContainer="container:0SkyBridge.xcodeproj"/></BuildActionEntry><BuildActionEntry buildForTesting="YES" buildForRunning="NO" buildForProfiling="NO" buildForArchiving="NO" buildForAnalyzing="NO"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{ui_test_target}" BuildableName="0SkyBridgeScreenSmokeTests.xctest" BlueprintName="0SkyBridgeScreenSmokeTests" ReferencedContainer="container:0SkyBridge.xcodeproj"/></BuildActionEntry></BuildActionEntries>
  </BuildAction>
  <TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.DebuggerFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES"><Testables><TestableReference skipped="NO"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{ui_test_target}" BuildableName="0SkyBridgeScreenSmokeTests.xctest" BlueprintName="0SkyBridgeScreenSmokeTests" ReferencedContainer="container:0SkyBridge.xcodeproj"/></TestableReference></Testables></TestAction>
  <RunAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.DebuggerFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" debugServiceExtension="internal" allowLocationSimulation="YES"><BuildableProductRunnable runnableDebuggingMode="0"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{app_target}" BuildableName="0SkyBridge.app" BlueprintName="0SkyBridge" ReferencedContainer="container:0SkyBridge.xcodeproj"/></BuildableProductRunnable></RunAction>
  <ProfileAction buildConfiguration="Release" shouldUseLaunchSchemeArgsEnv="YES" savedToolIdentifier="" useCustomWorkingDirectory="NO" debugDocumentVersioning="YES"><BuildableProductRunnable runnableDebuggingMode="0"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{app_target}" BuildableName="0SkyBridge.app" BlueprintName="0SkyBridge" ReferencedContainer="container:0SkyBridge.xcodeproj"/></BuildableProductRunnable></ProfileAction>
  <AnalyzeAction buildConfiguration="Debug"/><ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>\n''')
print(PROJECT)
