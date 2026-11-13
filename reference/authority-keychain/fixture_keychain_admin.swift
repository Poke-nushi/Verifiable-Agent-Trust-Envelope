// Test-only lifecycle for one disposable Keychain. Never used by the signer.
import Foundation
import Security

func check(_ status: OSStatus) throws {
    if status != errSecSuccess { throw NSError(domain: "fixture", code: 1) }
}
do {
    let args = CommandLine.arguments
    guard args.count == 3 || args.count == 4 else { exit(2) }
    let path = URL(fileURLWithPath: args[2])
    guard path.lastPathComponent == "fixture.keychain-db",
          path.deletingLastPathComponent().lastPathComponent.hasPrefix("vate-keychain-test-") else { exit(2) }
    try check(SecKeychainSetUserInteractionAllowed(false))
    var reference: SecKeychain?
    if args[1] == "create" {
        let password = FileHandle.standardInput.readDataToEndOfFile()
        guard password.count == 64 else { exit(2) }
        try check(password.withUnsafeBytes {
            SecKeychainCreate(args[2], UInt32(password.count), $0.baseAddress, false, nil, &reference)
        })
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: args[2])
    } else {
        try check(SecKeychainOpen(args[2], &reference))
        guard let keychain = reference else { exit(2) }
        if args[1] == "delete" { try check(SecKeychainDelete(keychain)) }
        else if args[1] == "lock" { try check(SecKeychainLock(keychain)) }
        else if args[1] == "unlock" {
            let password = FileHandle.standardInput.readDataToEndOfFile()
            guard password.count == 64 else { exit(2) }
            try check(password.withUnsafeBytes {
                SecKeychainUnlock(keychain, UInt32(password.count), $0.baseAddress, true)
            })
        } else if args[1] == "add-extractable" && args.count == 4 {
            var publicKey: SecKey?, privateKey: SecKey?
            let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256, kSecUseKeychain as String: keychain,
                kSecAttrIsExtractable as String: true,
                kSecPrivateKeyAttrs as String: [kSecAttrApplicationTag as String: Data(args[3].utf8)]]
            try check(SecKeyGeneratePair(attrs as CFDictionary, &publicKey, &privateKey))
        } else { exit(2) }
    }
} catch { exit(1) }
