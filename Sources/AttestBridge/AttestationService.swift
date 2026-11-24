import CryptoKit
import Darwin
import Foundation
import Security

#if canImport(DeviceCheck)
  import DeviceCheck
#endif

public struct PlatformEvidence: Codable {
  public let schema: String
  public let nonce: Data
  public let backend: String
  public let os: String
  public let sipObservation: String
  public let amfiObservation: String
  public let launcherSignatureValid: Bool?
  public let files: [Measurement]
}

public enum AttestationService {
  public static func nonce() throws -> Data {
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
      throw CocoaError(.coderInvalidValue)
    }
    return Data(bytes)
  }

  private static func sip() -> String {
    let p = Process()
    let pipe = Pipe()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/csrutil")
    p.arguments = ["status"]
    p.standardOutput = pipe
    p.standardError = FileHandle.nullDevice
    do {
      try p.run()
      let data = pipe.fileHandleForReading.readDataToEndOfFile()
      p.waitUntilExit()
      if p.terminationStatus == 0 {
        return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
      }
    } catch {}
    return "unknown"
  }

  private static func amfi() -> String {
    var size = 0
    guard sysctlbyname("kern.bootargs", nil, &size, nil, 0) == 0, size > 0, size <= 65536 else {
      return "unknown"
    }
    var bytes = [UInt8](repeating: 0, count: size)
    let status = bytes.withUnsafeMutableBytes { buffer in
      sysctlbyname("kern.bootargs", buffer.baseAddress, &size, nil, 0)
    }
    guard status == 0 else { return "unknown" }
    let arguments = String(decoding: bytes.prefix(while: { $0 != 0 }), as: UTF8.self).split(
      separator: " ")
    if arguments.contains("amfi_get_out_of_my_way=1")
      || arguments.contains("amfi_allow_any_signature=1")
    {
      return "permissive-boot-argument-observed"
    }
    return "unknown"
  }

  private static func hostSignature() -> Bool? {
    var code: SecCode?
    let flags = SecCSFlags(rawValue: 0)
    guard SecCodeCopySelf(flags, &code) == errSecSuccess, let code else { return nil }
    return SecCodeCheckValidity(code, flags, nil) == errSecSuccess
  }

  public static func payload(nonce: Data, backend: String, files: [Measurement]) throws -> Data {
    guard (16...128).contains(nonce.count) else { throw CocoaError(.coderInvalidValue) }
    let evidence = PlatformEvidence(
      schema: "org.metalbridge.prelaunch.v1", nonce: nonce,
      backend: backend, os: ProcessInfo.processInfo.operatingSystemVersionString,
      sipObservation: sip(), amfiObservation: amfi(), launcherSignatureValid: hostSignature(),
      files: files)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(evidence)
  }

  // Available only with an SDK exposing native Mac App Attest and an entitled app.
  // Persist the returned key ID at enrollment. The verifier owns challenge issuance.
  public static func enroll(payload: Data) async throws -> (keyID: String, attestation: Data) {
    #if compiler(>=6.4) && canImport(DeviceCheck)
      guard #available(macOS 27.0, *) else { throw CocoaError(.featureUnsupported) }
      let service = DCAppAttestService.shared
      guard service.isSupported else { throw CocoaError(.featureUnsupported) }
      let id = try await service.generateKey()
      let attestation = try await service.attestKey(
        id, clientDataHash: Data(SHA256.hash(data: payload)))
      return (id, attestation)
    #else
      throw CocoaError(.featureUnsupported)
    #endif
  }

  public static func assertion(keyID: String, payload: Data) async throws -> Data {
    #if compiler(>=6.4) && canImport(DeviceCheck)
      guard #available(macOS 27.0, *) else { throw CocoaError(.featureUnsupported) }
      let service = DCAppAttestService.shared
      guard service.isSupported else { throw CocoaError(.featureUnsupported) }
      return try await service.generateAssertion(
        keyID, clientDataHash: Data(SHA256.hash(data: payload)))
    #else
      throw CocoaError(.featureUnsupported)
    #endif
  }
}
