// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "0SkyBridge",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "BridgeCore", targets: ["BridgeCore"]),
        .executable(name: "0SkyBridge", targets: ["0SkyBridge"]),
        .executable(name: "0SkyBridgeHelper", targets: ["0SkyBridgeHelper"]),
        .executable(name: "0SkyBridgeService", targets: ["0SkyBridgeService"]),
        .executable(name: "0SkyBridgeCLI", targets: ["0SkyBridgeCLI"]),
    ],
    targets: [
        .target(
            name: "BridgeCore",
            path: "BridgeCore",
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("ServiceManagement"),
            ]
        ),
        .executableTarget(
            name: "0SkyBridge",
            dependencies: ["BridgeCore"],
            path: "0SkyBridge",
            exclude: ["Info.plist", "0SkyBridge.entitlements", "Resources/Scripts/kit",
                      "Resources/Scripts/__pycache__"],
            resources: [
                .process("Resources/AppIcon.icns"),
                .process("Resources/bridge-operations.json"),
                .process("Resources/com.liquidsky.0sky.bridge.helper.plist"),
                .process("Resources/com.liquidsky.0sky.bridge.service.plist"),
                .process("Resources/Scripts/0sky_project_setup.py"),
                .process("Resources/Scripts/Install 0-Sky Dependencies.command"),
                .copy("Resources/Legal"),
            ],
            linkerSettings: [
                .linkedFramework("SwiftUI"),
                .linkedFramework("AppKit"),
            ]
        ),
        .executableTarget(
            name: "0SkyBridgeHelper",
            dependencies: ["BridgeCore"],
            path: "0SkyBridgeHelper",
            exclude: ["0SkyBridgeHelper.entitlements"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .executableTarget(
            name: "0SkyBridgeService",
            dependencies: ["BridgeCore"],
            path: "0SkyBridgeService",
            exclude: ["0SkyBridgeService.entitlements"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .executableTarget(
            name: "0SkyBridgeCLI",
            dependencies: ["BridgeCore"],
            path: "Scripts/BridgeCLI"
        ),
        .executableTarget(
            name: "BridgeCoreTests",
            dependencies: ["BridgeCore"],
            path: "Tests/BridgeCoreTests"
        ),
    ]
)
