import AppKit
import CoreServices
import CryptoKit
import ImageIO
import UniformTypeIdentifiers

private let fm = FileManager.default
private let apps = PrefixManager.home.appendingPathComponent("Applications/MetalBridge Apps")

enum AppBundler {
  static func identifier(_ target: URL, _ id: String) -> String {
    SHA256.hash(data: Data((id + "/" + target.path).utf8)).prefix(10)
      .map { String(format: "%02x", $0) }.joined()
  }

  static func create(_ target: URL, id: String) throws -> URL {
    let target = target.resolvingSymlinksInPath().standardizedFileURL
    let key = identifier(target, id)
    let name = String(target.deletingPathExtension().lastPathComponent.prefix(64))
    let destination = apps.appendingPathComponent("\(name) (\(key)).app")
    if fm.fileExists(atPath: destination.path) { return destination }
    let image = try PEInspector(target)
    guard let info = image.info, info.characteristics & 0x2002 == 2 else {
      throw BridgeError("Bundle target must be a PE executable")
    }
    guard let host = Bundle.main.executableURL?.resolvingSymlinksInPath() else {
      throw BridgeError("Cannot locate the MetalBridge host")
    }
    let stub = host.deletingLastPathComponent().appendingPathComponent("MetalAppLauncher")
    let stage = apps.appendingPathComponent(".\(UUID().uuidString).app")
    let contents = stage.appendingPathComponent("Contents")
    let bin = contents.appendingPathComponent("MacOS")
    let resources = contents.appendingPathComponent("Resources")
    try fm.createDirectory(at: bin, withIntermediateDirectories: true)
    defer { try? fm.removeItem(at: stage) }
    try fm.createDirectory(at: resources, withIntermediateDirectories: true)
    try fm.copyItem(at: stub, to: bin.appendingPathComponent("Launcher"))
    var plist: [String: Any] = [
      "CFBundleIdentifier": "org.metalbridge.game." + key, "CFBundleDisplayName": name,
      "CFBundleName": name, "CFBundleVersion": "1", "CFBundlePackageType": "APPL",
      "CFBundleExecutable": "Launcher", "CFBundleInfoDictionaryVersion": "6.0",
      "LSMinimumSystemVersion": "14.0", "MetalBridgeTarget": target.path,
      "MetalBridgeHost": host.path, "MetalBridgeAppID": id,
    ]
    if let data = image.icon(), let source = CGImageSourceCreateWithData(data as CFData, nil),
      let cg = CGImageSourceCreateImageAtIndex(source, 0, nil)
    {
      let iconset = contents.appendingPathComponent("App.iconset")
      try fm.createDirectory(at: iconset, withIntermediateDirectories: false)
      for points in [16, 32, 128, 256, 512] {
        for scale in [1, 2] {
          let size = points * scale
          guard
            let ctx = CGContext(
              data: nil, width: size, height: size, bitsPerComponent: 8,
              bytesPerRow: 0, space: CGColorSpaceCreateDeviceRGB(),
              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
          else {
            throw BridgeError("Could not allocate icon bitmap")
          }
          ctx.interpolationQuality = .high
          ctx.draw(cg, in: CGRect(x: 0, y: 0, width: CGFloat(size), height: CGFloat(size)))
          let suffix = scale == 1 ? "" : "@2x"
          let url = iconset.appendingPathComponent("icon_\(points)x\(points)\(suffix).png")
          guard
            let png = CGImageDestinationCreateWithURL(
              url as CFURL, UTType.png.identifier as CFString, 1, nil),
            let scaled = ctx.makeImage()
          else { throw BridgeError("Could not encode icon") }
          CGImageDestinationAddImage(png, scaled, nil)
          guard CGImageDestinationFinalize(png) else { throw BridgeError("Could not write icon") }
        }
      }
      let rc = try process(
        URL(fileURLWithPath: "/usr/bin/iconutil"),
        ["-c", "icns", "-o", resources.appendingPathComponent("App.icns").path, iconset.path])
      guard rc == 0 else { throw BridgeError("iconutil exited with \(rc)") }
      try fm.removeItem(at: iconset)
      plist["CFBundleIconFile"] = "App.icns"
    }
    let bytes = try PropertyListSerialization.data(
      fromPropertyList: plist, format: .xml, options: 0)
    try bytes.write(to: contents.appendingPathComponent("Info.plist"))
    let rc = try process(
      URL(fileURLWithPath: "/usr/bin/codesign"), ["--force", "--sign", "-", stage.path])
    guard rc == 0 else { throw BridgeError("Wrapper signature failed") }
    do { try fm.moveItem(at: stage, to: destination) } catch {
      if !fm.fileExists(atPath: destination.path) { throw error }
    }
    return destination
  }
}

final class AppWatcher {
  let queue = DispatchQueue(label: "org.metalbridge.app-discovery")
  private let roots: [URL]
  private let drive: URL
  private let id: String
  private var stream: FSEventStreamRef?
  private var pending: DispatchWorkItem?

  init(prefix: URL, id: String) throws {
    let drive = prefix.appendingPathComponent("drive_c")
    self.drive = drive
    roots = ["Program Files", "Program Files (x86)", "ProgramData/Microsoft/Windows/Start Menu"]
      .map { drive.appendingPathComponent($0) }
    self.id = id
    var context = FSEventStreamContext(
      version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
      retain: nil, release: nil, copyDescription: nil)
    // Watching the common parent also observes creation of the roots by wineboot.
    let callback: FSEventStreamCallback = { _, opaque, _, _, _, _ in
      guard let opaque else { return }
      let watcher = Unmanaged<AppWatcher>.fromOpaque(opaque).takeUnretainedValue()
      watcher.schedule()
    }
    guard
      let stream = FSEventStreamCreate(
        nil, callback, &context, [drive.path] as CFArray,
        FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 1.0, 0)
    else {
      throw BridgeError("Cannot create FSEvents stream")
    }
    self.stream = stream
    FSEventStreamSetDispatchQueue(stream, queue)
    guard FSEventStreamStart(stream) else {
      FSEventStreamInvalidate(stream)
      FSEventStreamRelease(stream)
      self.stream = nil
      throw BridgeError("Cannot start FSEvents stream")
    }
    queue.async { self.schedule() }
  }

  private func schedule() {
    pending?.cancel()
    let job = DispatchWorkItem { [weak self] in self?.scan() }
    pending = job
    queue.asyncAfter(deadline: .now() + 1.5, execute: job)
  }

  func reconcile() { queue.sync { scan() } }

  private func scan() {
    var installed = [String: [URL]]()
    var shortcuts = Set<URL>()
    func primaryCandidate(_ url: URL) -> Bool {
      let name = url.lastPathComponent.lowercased()
      return name.hasSuffix(".exe")
        && ![
          "unins", "uninstall", "vcredist", "vc_redist", "dxsetup", "setup", "crashreport",
          "crashpad", "unitycrashhandler",
        ].contains(where: { name.hasPrefix($0) })
    }
    for root in roots {
      guard
        let walker = fm.enumerator(
          at: root, includingPropertiesForKeys: [.isSymbolicLinkKey],
          options: [.skipsHiddenFiles, .skipsPackageDescendants])
      else { continue }
      for case let url as URL in walker {
        if (try? url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true {
          walker.skipDescendants()
          continue
        }
        let name = url.lastPathComponent.lowercased()
        if ["_commonredist", "redist", "redistributables"].contains(name) {
          walker.skipDescendants()
          continue
        }
        if name.hasSuffix(".lnk"), let target = StartMenuLink.target(url, drive: drive),
          primaryCandidate(target)
        {
          shortcuts.insert(target)
        }
        if primaryCandidate(url) {
          let parts = url.pathComponents.dropFirst(root.pathComponents.count)
          guard let folder = parts.first else { continue }
          installed[root.appendingPathComponent(folder).path, default: []].append(url)
        }
      }
    }
    var targets = shortcuts
    for (folder, urls) in installed {
      guard !shortcuts.contains(where: { $0.path.hasPrefix(folder + "/") }) else { continue }
      // Without a shortcut, prefer the shallowest executable in the install tree.
      if let first = urls.min(by: {
        ($0.pathComponents.count, $0.path) < ($1.pathComponents.count, $1.path)
      }) {
        targets.insert(first)
      }
    }
    for url in targets {
      do { _ = try AppBundler.create(url, id: id) } catch {
        NSLog("MetalBridge bundle %@: %@", url.path, error.localizedDescription)
      }
    }
  }

  func stop() {
    guard let stream else { return }
    FSEventStreamStop(stream)
    FSEventStreamInvalidate(stream)
    queue.sync {
      pending?.cancel()
      pending = nil
    }
    FSEventStreamRelease(stream)
    self.stream = nil
  }
}
