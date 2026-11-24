import AppKit
import AttestBridge
import Darwin
import NativeShims

private let usage = """
  MetalBridge run [--backend auto|native-inproc|wine11-fex] [--app-id ID] [--wait] [--] FILE [ARG ...]
  MetalBridge inspect FILE
  MetalBridge bundle FILE [APPID]
  MetalBridge watch [APPID]
  MetalBridge doctor [--present]
  MetalBridge keygen DIRECTORY
  MetalBridge quote NONCE_BASE64 WRAPPED_KEY FILE
  MetalBridge verify NONCE_BASE64 PUBLIC_KEY QUOTE_JSON
  MetalBridge app-attest-enroll NONCE_BASE64 NEW_ENROLLMENT_JSON
  """

private func json(_ object: Any) throws {
  var data = try JSONSerialization.data(
    withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
  data.append(10)
  FileHandle.standardOutput.write(data)
}

@MainActor private func run(_ args: ArraySlice<String>) async throws -> Int32 {
  var args = args
  var backend = "auto"
  var id = "default"
  var wait = false
  while let flag = args.first, flag.hasPrefix("-") {
    args = args.dropFirst()
    if flag == "--" { break }
    if flag == "--wait" {
      wait = true
      continue
    }
    guard ["--backend", "--app-id"].contains(flag), let value = args.popFirst()
    else { throw BridgeError("Invalid option \(flag)\n\(usage)") }
    if flag == "--backend" { backend = value } else { id = value }
  }
  guard let file = args.popFirst() else { throw BridgeError(usage) }
  return try await launch(
    URL(fileURLWithPath: file), id: id, choice: backend, arguments: Array(args), wait: wait)
}

private func report(_ error: Error) {
  FileHandle.standardError.write(Data(("MetalBridge: " + error.localizedDescription + "\n").utf8))
}

@MainActor private func alert(_ error: Error) {
  NSApplication.shared.setActivationPolicy(.accessory)
  NSApplication.shared.activate(ignoringOtherApps: true)
  NSAlert(error: error).runModal()
}

@MainActor private final class FinderDelegate: NSObject, NSApplicationDelegate {
  func application(_ application: NSApplication, open urls: [URL]) {
    for url in urls {
      guard let host = Bundle.main.executableURL else { continue }
      let p = Process()
      p.executableURL = host
      p.arguments = ["open-target", "--", url.path]
      do { try p.run() } catch { alert(error) }
    }
  }
}

@MainActor private func cli(_ args: [String]) async throws -> Int32 {
  let values = Array(args.dropFirst())
  let url: (String) -> URL = { URL(fileURLWithPath: $0) }
  switch args.first {
  case "run", "open-target": return try await run(values[...])
  case "inspect" where values.count == 1: try json(PEInspector(url(values[0])).describe())
  case "bundle" where (1...2).contains(values.count):
    let id = values.count == 2 ? values[1] : "default"
    _ = try PrefixManager.prefix(id)
    print(try AppBundler.create(url(values[0]), id: id).path)
  case "watch" where values.count <= 1:
    let id = values.first ?? "default"
    let watcher = try AppWatcher(prefix: PrefixManager.prefix(id), id: id)
    withExtendedLifetime(watcher) { RunLoop.main.run() }
    watcher.stop()
  case "doctor" where values.isEmpty || values == ["--present"]:
    if !values.isEmpty, let error = mb_present_window() {
      throw BridgeError(String(cString: error))
    }
    try json([
      "metal3": mb_metal3_available(), "metal4": mb_metal4_available(),
      "displayScale": mb_main_display_scale(), "controllers": mb_connected_controllers(),
      "winePath": Wine11FEXChildBackend().wine.path,
      "wineInstalled": FileManager.default.isExecutableFile(
        atPath: Wine11FEXChildBackend().wine.path),
    ])
  case "keygen" where values.count == 1:
    let directory = url(values[0])
    try FileManager.default.createDirectory(
      at: directory, withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700])
    let keys = try QuoteVerifier.createKey()
    try keys.wrapped.write(
      to: directory.appendingPathComponent("enclave.key"), options: .withoutOverwriting)
    try keys.publicKey.write(
      to: directory.appendingPathComponent("public.x963"), options: .withoutOverwriting)
  case "quote" where values.count == 3:
    guard let nonce = Data(base64Encoded: values[0]) else {
      throw BridgeError("Invalid base64 nonce")
    }
    let image = try PEInspector(url(values[2]))
    let files = try RuntimeMonitor.snapshot(target: image.url, bytes: image.data, runtime: [])
    let payload = try AttestationService.payload(
      nonce: nonce, backend: "measurement-only", files: files)
    let signed = try QuoteVerifier.sign(payload, wrappedKey: Data(contentsOf: url(values[1])))
    FileHandle.standardOutput.write(try JSONEncoder().encode(signed))
  case "verify" where values.count == 3:
    guard let nonce = Data(base64Encoded: values[0]) else {
      throw BridgeError("Invalid base64 nonce")
    }
    let quote = try JSONDecoder().decode(SignedQuote.self, from: Data(contentsOf: url(values[2])))
    let evidence = try QuoteVerifier.verify(
      quote, publicKey: Data(contentsOf: url(values[1])), nonce: nonce)
    FileHandle.standardOutput.write(try JSONEncoder().encode(evidence))
  case "app-attest-enroll" where values.count == 2:
    guard let nonce = Data(base64Encoded: values[0]), (16...128).contains(nonce.count) else {
      throw BridgeError("Expected 16–128 bytes of base64 challenge data")
    }
    guard !FileManager.default.fileExists(atPath: values[1]) else {
      throw BridgeError("Enrollment destination already exists")
    }
    let result = try await AttestationService.enroll(payload: nonce)
    let record = try JSONSerialization.data(withJSONObject: [
      "keyID": result.keyID,
      "challenge": nonce.base64EncodedString(),
      "attestation": result.attestation.base64EncodedString(),
    ])
    try record.write(to: url(values[1]), options: .withoutOverwriting)
  case "--help", "-h", "help": print(usage)
  default: throw BridgeError(usage)
  }
  return 0
}

let arguments = Array(CommandLine.arguments.dropFirst())
if arguments.isEmpty || arguments.first?.hasPrefix("-psn_") == true {
  if Bundle.main.bundleURL.pathExtension == "app" {
    let application = NSApplication.shared
    let delegate = FinderDelegate()
    application.delegate = delegate
    application.setActivationPolicy(.accessory)
    withExtendedLifetime(delegate) { application.run() }
  } else {
    print(usage)
  }
} else {
  do { exit(try await cli(arguments)) } catch {
    report(error)
    if arguments.first == "open-target" { alert(error) }
    exit(1)
  }
}
