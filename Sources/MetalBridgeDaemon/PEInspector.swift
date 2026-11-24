import Foundation
import MetalBridgeLoader

struct BridgeError: LocalizedError {
  var errorDescription: String?
  init(_ text: String) { errorDescription = text }
}

struct PEInspector {
  let url: URL
  let data: Data?
  let info: MBImageInfo?

  init(_ input: URL) throws {
    url = input.standardizedFileURL.resolvingSymlinksInPath()
    guard try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true else {
      throw BridgeError("Expected a regular file at \(url.path)")
    }
    if url.pathExtension.lowercased() == "msi" {
      let file = try FileHandle(forReadingFrom: url)
      defer { try? file.close() }
      let header = try file.read(upToCount: 512) ?? Data()
      let signature: [UInt8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]
      guard header.count == 512, header.prefix(8).elementsEqual(signature),
        header[28] == 0xfe, header[29] == 0xff,
        [9, 12].contains(header[30]), header[31] == 0
      else {
        throw BridgeError("Invalid compound document header for MSI")
      }
      let directory = (0..<4).reduce(UInt64(0)) { $0 | UInt64(header[48 + $1]) << (8 * $1) }
      try file.seek(toOffset: (directory + 1) << Int(header[30]))
      let root = try file.read(upToCount: 128) ?? Data()
      let installerCLSID: [UInt8] = [0x84, 0x10, 0x0c, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46]
      guard root.count == 128, root[66] == 5, root[80..<96].elementsEqual(installerCLSID) else {
        throw BridgeError("Compound document is not a Windows Installer database")
      }
      data = nil
      info = nil
      return
    }
    let bytes = try Data(contentsOf: url)
    var parsed = MBImageInfo()
    try bytes.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
      if let error = mb_inspect(raw.bindMemory(to: UInt8.self).baseAddress, raw.count, &parsed) {
        throw BridgeError(String(cString: error))
      }
    }
    info = parsed
    data = bytes
  }

  func requireLaunchable() throws {
    guard let info else { return }  // Windows Installer database
    guard info.characteristics & 0x2002 == 2 else {
      throw BridgeError("Expected a Windows executable image")
    }
    switch (info.machine, info.magic) {
    case (0x14c, 0x10b), (0x8664, 0x20b), (0xaa64, 0x20b), (0xa641, 0x20b), (0xa64e, 0x20b):
      return
    default:
      throw BridgeError(
        String(
          format: "Unsupported machine/header combination 0x%04x/0x%04x", info.machine, info.magic))
    }
  }

  func icon() -> Data? {
    data?.withUnsafeBytes { raw -> Data? in
      var size = 0
      guard let ptr = mb_copy_icon(raw.bindMemory(to: UInt8.self).baseAddress, raw.count, &size)
      else { return nil }
      defer { mb_free(ptr) }
      return Data(bytes: ptr, count: size)
    }
  }

  func describe() throws -> [String: Any] {
    guard let info, let data else { return ["format": "MSI compound document"] }
    var dirs = MBDirectoryInfo()
    try data.withUnsafeBytes { raw in
      if let error = mb_directories(raw.bindMemory(to: UInt8.self).baseAddress, raw.count, &dirs) {
        throw BridgeError(String(cString: error))
      }
    }
    return [
      "format": info.magic == 0x20b ? "PE32+" : "PE32",
      "machine": String(format: "0x%04x", info.machine), "sections": info.sections,
      "entryRVA": info.entry_rva, "imageBytes": info.image_size,
      "importModules": dirs.import_modules, "namedImports": dirs.import_names,
      "ordinalImports": dirs.import_ordinals, "exports": dirs.export_slots,
      "relocations": dirs.relocations,
    ]
  }
}
