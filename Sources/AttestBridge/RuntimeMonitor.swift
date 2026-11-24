import CryptoKit
import Foundation
import MachO

public struct Measurement: Codable {
  public let path: String
  public let origin: String
  public let sha256: String?
}

public enum RuntimeMonitor {
  public static func digest(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }

  private static func measure(_ url: URL, origin: String) throws -> Measurement {
    let file = try FileHandle(forReadingFrom: url)
    defer { try? file.close() }
    var hash = SHA256()
    while let block = try file.read(upToCount: 1024 * 1024), !block.isEmpty {
      hash.update(data: block)
    }
    let digest = hash.finalize().map { String(format: "%02x", $0) }.joined()
    return Measurement(path: url.path, origin: origin, sha256: digest)
  }

  public static func snapshot(target: URL, bytes: Data?, runtime: [URL]) throws -> [Measurement] {
    var result: [Measurement]
    if let bytes {
      result = [Measurement(path: target.path, origin: "guest-file", sha256: digest(bytes))]
    } else {
      result = [try measure(target, origin: "guest-file")]
    }
    for url in Set(runtime).sorted(by: { $0.path < $1.path }) {
      result.append(try measure(url, origin: "configured-runtime-file"))
    }
    var names = Set<String>()
    for i in 0..<_dyld_image_count() {
      if let ptr = _dyld_get_image_name(i) { names.insert(String(cString: ptr)) }
    }
    for name in names.sorted() {
      if FileManager.default.isReadableFile(atPath: name) {
        result.append(try measure(URL(fileURLWithPath: name), origin: "launcher-image-file"))
      } else {
        result.append(
          Measurement(path: name, origin: "launcher-image-no-readable-file", sha256: nil))
      }
    }
    return result
  }
}
