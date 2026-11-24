import AttestBridge
import Foundation
import MetalBridgeLoader

struct LaunchContext {
  let image: PEInspector
  let prefix: URL
  let profile: LaunchProfile
  let waitForPrevious: Bool
}

protocol ExecutionBackend {
  var name: String { get }
  func runtimeFiles(for context: LaunchContext) throws -> [URL]
  func run(_ context: LaunchContext) throws -> Int32
}

struct NativeInProcessBackend: ExecutionBackend {
  let name = "native-inproc"
  func runtimeFiles(for context: LaunchContext) throws -> [URL] { [] }  // statically linked
  func unsupported(_ context: LaunchContext) -> String? {
    guard let bytes = context.image.data else { return "MSI requires Windows Installer" }
    return bytes.withUnsafeBytes { raw in
      mb_native_probe(raw.bindMemory(to: UInt8.self).baseAddress, raw.count).map {
        String(cString: $0)
      }
    }
  }

  func run(_ context: LaunchContext) throws -> Int32 {
    guard let bytes = context.image.data else { throw BridgeError("Native backend requires PE") }
    var status: Int32 = 0
    try bytes.withUnsafeBytes { raw in
      if let error = mb_native_run(raw.bindMemory(to: UInt8.self).baseAddress, raw.count, &status) {
        throw BridgeError(String(cString: error))
      }
    }
    return status
  }
}

@discardableResult
func process(
  _ tool: URL, _ arguments: [String], environment: [String: String]? = nil,
  directory: URL? = nil
) throws -> Int32 {
  let p = Process()
  p.executableURL = tool
  p.arguments = arguments
  p.environment = environment
  p.currentDirectoryURL = directory
  try p.run()
  p.waitUntilExit()
  return p.terminationReason == .uncaughtSignal ? 128 + p.terminationStatus : p.terminationStatus
}

struct Wine11FEXChildBackend: ExecutionBackend {
  let name = "wine11-fex"
  static let contents = PrefixManager.root.appendingPathComponent(
    "runtime/MetalSharp-Wine.app/Contents")
  let wine = contents.appendingPathComponent("MacOS/wine")
  let server = contents.appendingPathComponent("MacOS/wineserver")

  func runtimeFiles(for context: LaunchContext) throws -> [URL] {
    guard #available(macOS 15, *) else { throw BridgeError("The Wine runtime requires macOS 15+") }
    if context.profile.environment["METALBRIDGE_GRAPHICS"] == "d3dmetal" {
      throw BridgeError(
        "The pinned ARM64/FEX runtime supplies Mullion (DXMT fork). Its D3DMetal build requires Rosetta."
      )
    }
    if context.image.info?.machine == 0x14c,
      !ProcessInfo.processInfo.isOperatingSystemAtLeast(
        OperatingSystemVersion(majorVersion: 26, minorVersion: 4, patchVersion: 0))
    {
      throw BridgeError("The signed i386 FEX runtime requires macOS 26.4+")
    }
    for url in [wine, server] where !FileManager.default.isExecutableFile(atPath: url.path) {
      throw BridgeError("Missing \(url.path). Run scripts/bootstrap_runtime.sh first.")
    }
    let manifest = PrefixManager.root.appendingPathComponent("runtime/components.json")
    let relative = try JSONDecoder().decode([String].self, from: Data(contentsOf: manifest))
    guard !relative.isEmpty else { throw BridgeError("Empty runtime inventory") }
    let machines: [UInt16] = context.image.info.map { [$0.machine] } ?? [0x14c, 0x8664]
    for machine in machines where machine == 0x14c || machine == 0x8664 {
      let module = machine == 0x14c ? "libwow64fex.dll" : "libarm64ecfex.dll"
      let path = "lib/wine/aarch64-windows/" + module
      guard relative.contains(path) else { throw BridgeError("Runtime is missing " + module) }
      let bytes = try Data(contentsOf: Self.contents.appendingPathComponent(path))
      try bytes.withUnsafeBytes { raw in
        if let error = mb_fex_validate(
          machine, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        {
          throw BridgeError(module + ": " + String(cString: error))
        }
      }
    }
    return [wine, server] + relative.map { Self.contents.appendingPathComponent($0) }
  }

  func run(_ c: LaunchContext) throws -> Int32 {
    let arch = URL(fileURLWithPath: "/usr/bin/arch")
    if c.waitForPrevious {
      let rc = try process(arch, ["-arm64", server.path, "-w"], environment: c.profile.environment)
      guard rc == 0 else { throw BridgeError("wineserver -w exited with \(rc)") }
    }
    let target = c.image.url
    var args = ["-arm64", wine.path]
    if c.image.info == nil {
      let path = target.path
      let homePrefix = PrefixManager.home.path + "/"
      let windows =
        path.hasPrefix(homePrefix)
        ? "Z:\\"
          + String(path.dropFirst(homePrefix.count)).replacingOccurrences(of: "/", with: "\\")
        : "\\\\?\\unix" + path.replacingOccurrences(of: "/", with: "\\")
      args += ["msiexec", "/i", windows]
    } else {
      args.append(target.path)
    }
    return try process(
      arch, args + c.profile.arguments, environment: c.profile.environment,
      directory: target.deletingLastPathComponent())
  }
}

@MainActor
func launch(_ url: URL, id: String, choice: String, arguments: [String], wait: Bool) async throws
  -> Int32
{
  #if !arch(arm64)
    throw BridgeError("Metal requires native Apple Silicon")
  #else
    let image = try PEInspector(url)
    try image.requireLaunchable()
    let prefix = try PrefixManager.prefix(id)
    let profile = try LaunchProfile(
      id: id, prefix: prefix, executable: image.url, arguments: arguments)
    let c = LaunchContext(image: image, prefix: prefix, profile: profile, waitForPrevious: wait)
    let native = NativeInProcessBackend()
    let backend: any ExecutionBackend
    switch choice {
    case "native-inproc":
      if let reason = native.unsupported(c) { throw BridgeError(reason) }
      backend = native
    case "wine11-fex": backend = Wine11FEXChildBackend()
    case "auto":
      if native.unsupported(c) == nil {
        backend = native
      } else {
        backend = Wine11FEXChildBackend()
      }
    default: throw BridgeError("Unknown backend \(choice)")
    }
    let files = try RuntimeMonitor.snapshot(
      target: image.url, bytes: image.data, runtime: backend.runtimeFiles(for: c))
    let nonce: Data
    if let challenge = profile.environment["METALBRIDGE_CHALLENGE"] {
      guard let bytes = Data(base64Encoded: challenge), (16...128).contains(bytes.count) else {
        throw BridgeError("METALBRIDGE_CHALLENGE requires 16–128 bytes encoded as base64")
      }
      nonce = bytes
    } else {
      nonce = try AttestationService.nonce()
    }
    let payload = try AttestationService.payload(nonce: nonce, backend: backend.name, files: files)
    let report: Data
    if let id = profile.environment["METALBRIDGE_APP_ATTEST_KEY_ID"] {
      guard profile.environment["METALBRIDGE_CHALLENGE"] != nil else {
        throw BridgeError("App Attest assertions require a verifier-issued METALBRIDGE_CHALLENGE")
      }
      let assertion = try await AttestationService.assertion(keyID: id, payload: payload)
      report = try JSONSerialization.data(
        withJSONObject: [
          "kind": "apple-app-attest", "keyID": id, "assertion": assertion.base64EncodedString(),
          "payload": payload.base64EncodedString(),
        ], options: [.sortedKeys])
    } else if QuoteVerifier.canSign {
      let key = try QuoteVerifier.localKey(in: PrefixManager.root)
      report = try JSONEncoder().encode(QuoteVerifier.sign(payload, wrappedKey: key))
    } else {
      guard profile.environment["METALBRIDGE_REQUIRE_QUOTE"] != "1" else {
        throw BridgeError("A hardware-signed quote was required but Secure Enclave is unavailable")
      }
      report = payload
    }
    try report.write(to: prefix.appendingPathComponent("last-prelaunch.json"), options: .atomic)
    let watcher = try AppWatcher(prefix: prefix, id: id)
    defer { watcher.stop() }
    let status = try backend.run(c)
    watcher.reconcile()
    return status
  #endif
}
