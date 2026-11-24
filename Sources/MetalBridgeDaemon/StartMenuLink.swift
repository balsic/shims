import Foundation

enum StartMenuLink {
  // Read MS-SHLLINK LinkInfo for local C: targets. Shortcuts are never executed.
  static func target(_ url: URL, drive: URL) -> URL? {
    guard let file = try? FileHandle(forReadingFrom: url) else { return nil }
    defer { try? file.close() }
    guard let data = try? file.read(upToCount: 1024 * 1024), data.count >= 76 else { return nil }
    func word(_ i: Int) -> Int { Int(data[i]) | Int(data[i + 1]) << 8 }
    func dword(_ i: Int) -> Int { word(i) | word(i + 2) << 16 }
    let clsid: [UInt8] = [1, 20, 2, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46]
    guard dword(0) == 76, data[4..<20].elementsEqual(clsid), dword(20) & 2 != 0 else { return nil }
    var offset = 76
    if dword(20) & 1 != 0 {
      guard data.count >= 78 else { return nil }
      offset += 2 + word(offset)
    }
    guard offset + 28 <= data.count else { return nil }
    let size = dword(offset)
    let header = dword(offset + 4)
    guard header >= 28, size >= header, offset + size <= data.count,
      dword(offset + 8) & 1 != 0
    else { return nil }
    func string(_ field: Int, unicode: Bool) -> String? {
      let relative = dword(offset + field)
      guard relative >= header, relative < size else { return nil }
      let start = offset + relative
      var end = start
      while end + (unicode ? 2 : 1) <= offset + size {
        if unicode ? word(end) == 0 : data[end] == 0 {
          return String(
            data: data[start..<end], encoding: unicode ? .utf16LittleEndian : .windowsCP1252)
        }
        end += unicode ? 2 : 1
      }
      return nil
    }
    let unicode = header >= 36 && dword(offset + 28) != 0
    guard var path = string(unicode ? 28 : 16, unicode: unicode) else { return nil }
    if let tail = string(unicode ? 32 : 24, unicode: unicode), !tail.isEmpty,
      !path.lowercased().hasSuffix(tail.lowercased())
    {
      path += (path.hasSuffix("\\") ? "" : "\\") + tail
    }
    guard path.lowercased().hasPrefix("c:\\") else { return nil }
    let relative = path.dropFirst(3).replacingOccurrences(of: "\\", with: "/")
    let result = drive.appendingPathComponent(relative).standardizedFileURL
      .resolvingSymlinksInPath()
    return result.path.hasPrefix(drive.resolvingSymlinksInPath().path + "/") ? result : nil
  }
}
