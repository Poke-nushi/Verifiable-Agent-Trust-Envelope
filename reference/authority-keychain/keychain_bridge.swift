// Optional file-based macOS Keychain bridge. No private-key export, password,
// Keychain creation, unlock, ACL widening, or default/search-list mutation here.
import Foundation
import Security
import CryptoKit
import Darwin

let contract = "vate-keychain-es256-v1"
enum BridgeError: Error { case rejected }
func require(_ condition: Bool) throws { if !condition { throw BridgeError.rejected } }
func success(_ status: OSStatus) throws { try require(status == errSecSuccess) }

func emit(_ object: [String: Any]) throws {
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([10]))
}

func canonicalPath(_ path: String) throws -> String {
    guard let resolved = realpath(path, nil) else { throw BridgeError.rejected }
    defer { free(resolved) }
    return String(cString: resolved)
}

func openSelectedKeychain(_ path: String, _ tag: String) throws -> SecKeychain {
    try require(path.hasPrefix("/") && !path.utf8.contains(0) && path.utf8.count < 4096)
    try require((1...128).contains(tag.utf8.count) && tag.utf8.allSatisfy {
        (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0)
            || [45, 46, 58, 95].contains($0)
    })
    try require(try canonicalPath(path) == path)
    var info = stat()
    try require(lstat(path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFREG
                && info.st_uid == getuid() && (info.st_mode & 0o077) == 0)
    var reference: SecKeychain?
    try success(SecKeychainOpen(path, &reference))
    guard let keychain = reference else { throw BridgeError.rejected }
    var length: UInt32 = 4096
    var buffer = [CChar](repeating: 0, count: Int(length))
    try success(SecKeychainGetPath(keychain, &length, &buffer))
    try require(try canonicalPath(String(cString: buffer)) == path)
    var status: SecKeychainStatus = 0
    try success(SecKeychainGetStatus(keychain, &status))
    try require(status & UInt32(kSecUnlockStateStatus) != 0)
    return keychain
}

func lookup(_ keychain: SecKeychain, _ tag: String) -> (OSStatus, CFTypeRef?) {
    let query: [String: Any] = [kSecClass as String: kSecClassKey,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrApplicationTag as String: Data(tag.utf8),
        kSecMatchSearchList as String: [keychain], kSecMatchLimit as String: kSecMatchLimitAll,
        kSecReturnRef as String: true]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    return (status, result)
}

func selectedKey(_ keychain: SecKeychain, _ tag: String) throws -> (SecKey, P256.Signing.PublicKey) {
    let (status, result) = lookup(keychain, tag)
    try success(status)
    guard let keys = result as? [SecKey], keys.count == 1,
          let attrs = SecKeyCopyAttributes(keys[0]) as? [String: Any],
          let publicKey = SecKeyCopyPublicKey(keys[0]),
          let point = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
        throw BridgeError.rejected
    }
    try require(attrs[kSecAttrKeySizeInBits as String] as? Int == 256
                && attrs[kSecAttrIsExtractable as String] as? Bool == false
                && attrs[kSecAttrCanSign as String] as? Bool == true)
    return (keys[0], try P256.Signing.PublicKey(x963Representation: point))
}

func provision(_ keychain: SecKeychain, _ tag: String) throws {
    // Explicit administrative operation only. Existing keys, including invalid
    // or ambiguous ones, must never cause replacement or automatic recovery.
    let (status, _) = lookup(keychain, tag)
    try require(status == errSecItemNotFound)
    var publicKey: SecKey?, privateKey: SecKey?
    let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256, kSecUseKeychain as String: keychain,
        // File-based SecKeyGeneratePair requires this at the top level.
        kSecAttrIsExtractable as String: false,
        kSecPrivateKeyAttrs as String: [kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrIsExtractable as String: false, kSecAttrCanSign as String: true]]
    // This deprecated API explicitly selects a file-based Keychain. The bridge
    // is optional; application / KMS backends use the unchanged signer callback.
    try success(SecKeyGeneratePair(attributes as CFDictionary, &publicKey, &privateKey))
    _ = try selectedKey(keychain, tag)
}

func boundedInput() throws -> Data {
    var raw = Data()
    while let chunk = try FileHandle.standardInput.read(upToCount: 4096), !chunk.isEmpty {
        raw.append(chunk)
        try require(raw.count <= 128 * 1024)
    }
    return raw
}

func sign() throws {
    let raw = try boundedInput()
    guard let request = try JSONSerialization.jsonObject(with: raw) as? [String: String] else {
        throw BridgeError.rejected
    }
    try require(Set(request.keys) == ["contract", "keychain_path", "application_tag",
                                     "expected_public_key_spki_base64", "signing_input_base64"])
    try require(request["contract"] == contract)
    guard let encoded = request["signing_input_base64"], let input = Data(base64Encoded: encoded),
          let expected = request["expected_public_key_spki_base64"],
          let expectedKey = Data(base64Encoded: expected),
          let path = request["keychain_path"], let tag = request["application_tag"] else {
        throw BridgeError.rejected
    }
    try require(input.count > 0 && input.count + 87 <= 64 * 1024
                && input.base64EncodedString() == encoded
                && expectedKey.base64EncodedString() == expected)
    try require(input.filter { $0 == 46 }.count == 1
                && input.allSatisfy { (65...90).contains($0) || (97...122).contains($0)
                    || (48...57).contains($0) || $0 == 45 || $0 == 95 || $0 == 46 })
    let keychain = try openSelectedKeychain(path, tag)
    let (key, publicKey) = try selectedKey(keychain, tag)
    try require(publicKey.derRepresentation == expectedKey)
    try require(SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256))
    guard let der = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, input as CFData, nil) as Data? else {
        throw BridgeError.rejected
    }
    let signature = try P256.Signing.ECDSASignature(derRepresentation: der)
    try require(publicKey.isValidSignature(signature, for: input))
    try emit(["contract": contract,
        "request_sha256": SHA256.hash(data: raw).map { String(format: "%02x", $0) }.joined(),
        "signature_base64": signature.rawRepresentation.base64EncodedString()])
}

do {
    // Process-local suppression, not a change to any Keychain ACL or settings.
    try success(SecKeychainSetUserInteractionAllowed(false))
    let args = CommandLine.arguments
    if args.count == 2 && args[1] == "sign" {
        try sign()
    } else if args.count == 4 && ["provision", "public-key"].contains(args[1]) {
        let keychain = try openSelectedKeychain(args[2], args[3])
        if args[1] == "provision" { try provision(keychain, args[3]) }
        let (_, publicKey) = try selectedKey(keychain, args[3])
        try emit(["contract": contract, "public_key_spki_base64": publicKey.derRepresentation.base64EncodedString(),
                  "private_key_extractable": false])
    } else { throw BridgeError.rejected }
} catch {
    // No OS errors, claims, paths, credentials or key material in diagnostics.
    FileHandle.standardError.write(Data("KEYCHAIN_BRIDGE_FAILED\n".utf8))
    exit(1)
}
