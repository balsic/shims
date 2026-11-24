// swift-tools-version: 5.10
import PackageDescription

let package = Package(
  name: "Metal",
  platforms: [.macOS(.v14)],
  products: [
    .executable(name: "MetalBridge", targets: ["MetalBridgeDaemon"]),
    .executable(name: "MetalAppLauncher", targets: ["MetalAppLauncher"]),
    .library(name: "AttestBridge", targets: ["AttestBridge"]),
  ],
  targets: [
    .target(
      name: "MetalBridgeLoader",
      dependencies: [
        .target(name: "NativeShims", condition: .when(platforms: [.macOS]))
      ], publicHeadersPath: "include"),
    .target(
      name: "NativeShims", publicHeadersPath: "include",
      linkerSettings: [
        .linkedFramework("Metal"), .linkedFramework("QuartzCore"),
        .linkedFramework("AppKit"), .linkedFramework("GameController"),
      ]),
    .target(name: "AttestBridge"),
    .executableTarget(name: "MetalAppLauncher", linkerSettings: [.linkedFramework("Foundation")]),
    .executableTarget(
      name: "MetalBridgeDaemon",
      dependencies: ["MetalBridgeLoader", "NativeShims", "AttestBridge"]),
  ],
  cxxLanguageStandard: .cxx20
)
