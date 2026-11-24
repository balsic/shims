import Foundation

@main
struct SharedCoreCheck {
  static func main() throws {
    let fm = FileManager.default
    let home = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try fm.createDirectory(at: home, withIntermediateDirectories: false)
    defer { try? fm.removeItem(at: home) }
    let file = URL(fileURLWithPath: CommandLine.arguments[1])
    let parsed = try PEInspector(file)
    let description = try parsed.describe()
    precondition(parsed.info?.machine == 0xaa64 && description["format"] as? String == "PE32+")
    let prefix = try PrefixManager.prefix("271590", homeDirectory: home)
    let other = try PrefixManager.prefix("3061570", homeDirectory: home)
    precondition(prefix != other)
    let mapping = try fm.destinationOfSymbolicLink(
      atPath: prefix.appendingPathComponent("dosdevices/z:").path)
    precondition(mapping == home.path)
    _ = try PrefixManager.prefix("271590", homeDirectory: home)
    do {
      _ = try PrefixManager.prefix("../escape", homeDirectory: home)
      fatalError("Invalid ID was accepted")
    } catch is BridgeError {}
    let gta = try LaunchProfile(id: "271590", prefix: prefix, executable: file, arguments: ["a b"])
    precondition(gta.arguments == ["a b", "-nobattleye"])
    precondition(gta.environment["DXMT_METALFX_SPATIAL"] == "1")
    let persona = try LaunchProfile(id: "3061570", prefix: other, executable: file, arguments: [])
    precondition(
      persona.environment["WINEDLLOVERRIDES"]?.contains("d3d11,dxgi,winhttp,wininet=n,b") == true)
    let genshin = try LaunchProfile(
      id: "default", prefix: prefix,
      executable: home.appendingPathComponent("GenshinImpact.exe"), arguments: [])
    precondition(genshin.environment["WINEMSYNC"] == "1")
    precondition(genshin.environment["WINEDLLOVERRIDES"]?.contains("crypt32=b") == true)
    let shortcut = home.appendingPathComponent("test.lnk")
    try Data(repeating: 0, count: 76).write(to: shortcut)
    precondition(StartMenuLink.target(shortcut, drive: home) == nil)
    let path = Array("C:\\Games\\Sample.exe\0".utf16)
    var link = Data(repeating: 0, count: 76 + 36 + path.count * 2 + 2)
    link[0] = 76
    link[4..<20] = Data([1, 20, 2, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46])
    link[20] = 2
    link[76] = UInt8(link.count - 76)
    link[80] = 36
    link[84] = 1
    link[104] = 36
    link[108] = UInt8(36 + path.count * 2)
    for (i, unit) in path.enumerated() {
      link[112 + 2 * i] = UInt8(truncatingIfNeeded: unit)
      link[113 + 2 * i] = UInt8(unit >> 8)
    }
    try link.write(to: shortcut)
    precondition(
      StartMenuLink.target(shortcut, drive: home)?.path
        == home.appendingPathComponent("Games/Sample.exe").path)

    let installer = home.appendingPathComponent("test.msi")
    var storage = Data(repeating: 0, count: 1024)
    storage[0..<8] = Data([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
    storage[26] = 3
    storage[28] = 0xfe
    storage[29] = 0xff
    storage[30] = 9
    storage[512 + 66] = 5
    storage[592..<608] = Data([0x84, 0x10, 0x0c, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46])
    try storage.write(to: installer)
    let msi = try PEInspector(installer)
    precondition(msi.info == nil)
    storage[592] = 0
    try storage.write(to: installer)
    do {
      _ = try PEInspector(installer)
      fatalError("Compound document of another type was admitted as MSI")
    } catch is BridgeError {}
    print(
      "Swift PE/MSI inspection, shortcut resolution, prefix isolation, and launch profiles passed")
  }
}
