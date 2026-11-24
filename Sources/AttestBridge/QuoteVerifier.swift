import CryptoKit
import Foundation

public struct SignedQuote: Codable {
  public let payload: Data
  public let signature: Data
}

public enum QuoteVerifier {
  public static var canSign: Bool { SecureEnclave.isAvailable }

  public static func localKey(in parent: URL) throws -> Data {
    let fm = FileManager.default
    let identity = parent.appendingPathComponent("identity")
    let keyFile = identity.appendingPathComponent("enclave.key")
    if fm.fileExists(atPath: identity.path) { return try Data(contentsOf: keyFile) }
    let stage = parent.appendingPathComponent(".key-" + UUID().uuidString)
    try fm.createDirectory(
      at: stage, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? fm.removeItem(at: stage) }
    let key = try createKey()
    try key.wrapped.write(to: stage.appendingPathComponent("enclave.key"))
    try key.publicKey.write(to: stage.appendingPathComponent("public.x963"))
    do { try fm.moveItem(at: stage, to: identity) } catch {
      if !fm.fileExists(atPath: keyFile.path) { throw error }
    }
    return try Data(contentsOf: keyFile)
  }

  // The caller retains the wrapped key in Keychain or other local storage.
  public static func createKey() throws -> (wrapped: Data, publicKey: Data) {
    let key = try SecureEnclave.P256.Signing.PrivateKey()
    return (key.dataRepresentation, key.publicKey.x963Representation)
  }

  public static func sign(_ payload: Data, wrappedKey: Data) throws -> SignedQuote {
    let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: wrappedKey)
    return SignedQuote(
      payload: payload, signature: try key.signature(for: payload).derRepresentation)
  }

  // Enrollment must establish the trusted key independently of the report.
  public static func verify(_ quote: SignedQuote, publicKey: Data, nonce: Data) throws
    -> PlatformEvidence
  {
    let key = try P256.Signing.PublicKey(x963Representation: publicKey)
    let sig = try P256.Signing.ECDSASignature(derRepresentation: quote.signature)
    guard key.isValidSignature(sig, for: quote.payload) else {
      throw CocoaError(.coderInvalidValue)
    }
    let evidence = try JSONDecoder().decode(PlatformEvidence.self, from: quote.payload)
    guard evidence.schema == "org.metalbridge.prelaunch.v1", (16...128).contains(nonce.count),
      evidence.nonce == nonce
    else { throw CocoaError(.coderInvalidValue) }
    return evidence
  }
}
