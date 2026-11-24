import Foundation

#if canImport(Darwin)
  import Darwin
#else
  import Glibc
#endif

enum PrefixManager {
  static let home = FileManager.default.homeDirectoryForCurrentUser
  static let root = home.appendingPathComponent(".local/share/MetalBridge", isDirectory: true)

  static func prefix(_ id: String, homeDirectory: URL = home) throws -> URL {
    guard
      id == "default"
        || (!id.isEmpty && id.count <= 20 && id.utf8.allSatisfy({ (48...57).contains($0) }))
    else {
      throw BridgeError("AppID must be a decimal Steam ID or default")
    }
    let url = homeDirectory.appendingPathComponent(
      ".local/share/MetalBridge/prefixes/" + id, isDirectory: true)
    let drives = url.appendingPathComponent("dosdevices", isDirectory: true)
    let fm = FileManager.default
    try fm.createDirectory(
      at: drives, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    try fm.createDirectory(
      at: url.appendingPathComponent("drive_c"), withIntermediateDirectories: true)
    let z = drives.appendingPathComponent("z:")
    if (try? fm.destinationOfSymbolicLink(atPath: z.path)) != homeDirectory.path {
      let temporary = drives.appendingPathComponent(UUID().uuidString)
      try fm.createSymbolicLink(at: temporary, withDestinationURL: homeDirectory)
      defer { try? fm.removeItem(at: temporary) }
      var st = stat()
      if lstat(z.path, &st) == 0 && (st.st_mode & mode_t(S_IFMT)) != mode_t(S_IFLNK) {
        throw BridgeError("Existing Z: mapping is not a symlink at \(z.path)")
      }
      guard rename(temporary.path, z.path) == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
      }
    }
    let c = drives.appendingPathComponent("c:")
    if symlink("../drive_c", c.path) != 0 && errno != EEXIST {
      throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    return url
  }
}

struct LaunchProfile {
  var environment: [String: String]
  var arguments: [String]

  init(id: String, prefix: URL, executable: URL, arguments: [String]) throws {
    self.arguments = arguments
    environment = ProcessInfo.processInfo.environment
    environment["WINEPREFIX"] = prefix.path
    var overrides = [String]()
    switch environment["METALBRIDGE_GRAPHICS"] ?? "auto" {
    case "auto", "d3dmetal": break
    case "dxmt": environment.removeValue(forKey: "GRAPHICS_BACKEND")
    default: throw BridgeError("METALBRIDGE_GRAPHICS must be auto, dxmt, or d3dmetal")
    }
    switch id {
    case "271590", "3240220":
      if !arguments.contains("-nobattleye") { self.arguments.append("-nobattleye") }
      environment["DXMT_METALFX_SPATIAL"] = "1"
      overrides.append("d3dcompiler_47=n,b")
    case "3061570":
      environment["WINE_LARGE_ADDRESS_AWARE"] = "1"
      overrides.append("d3d11,dxgi,winhttp,wininet=n,b")
    default: break
    }
    let game = executable.deletingPathExtension().lastPathComponent.lowercased()
    if ["zenlesszonezero", "genshinimpact", "yuanshen"].contains(game) {
      environment["WINEMSYNC"] = "1"
      overrides += ["crypt32=b", "winhttp=n,b"]
    }
    let supplied = environment["WINEDLLOVERRIDES"] ?? ""
    environment["WINEDLLOVERRIDES"] = ([supplied] + overrides).filter { !$0.isEmpty }.joined(
      separator: ";")
  }
}
