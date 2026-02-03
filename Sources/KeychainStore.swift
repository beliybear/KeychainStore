import Foundation
import Security

/// Encoding format for Codable values in Keychain.
public enum KeychainEncoding {
    case json
    case propertyList
}

/// Type-safe Keychain access: save/load/delete by key. Security framework only.
public final class KeychainStore {
    public static var defaultStore: KeychainStore = KeychainStore()

    public static func configureDefault(store: KeychainStore) {
        defaultStore = store
    }

    public let service: String
    public let accessGroup: String?
    public let accessible: KeychainAccessible
    public let encoding: KeychainEncoding
    private let _jsonEncoder: JSONEncoder
    private let _jsonDecoder: JSONDecoder
    private let _plistEncoder: PropertyListEncoder
    private let _plistDecoder: PropertyListDecoder

    public init(
        service: String = Bundle.main.bundleIdentifier ?? "KeychainStore",
        accessGroup: String? = nil,
        accessible: KeychainAccessible = .whenUnlocked,
        encoding: KeychainEncoding = .json
    ) {
        self.service = service
        self.accessGroup = accessGroup
        self.accessible = accessible
        self.encoding = encoding
        self._jsonEncoder = JSONEncoder()
        self._jsonDecoder = JSONDecoder()
        self._plistEncoder = PropertyListEncoder()
        self._plistDecoder = PropertyListDecoder()
    }

    /// Saves a Codable value for the given key. Uses the store's encoding (JSON or PropertyList); pass encoder to override for this call (JSON or PropertyList).
    public func save<T: Encodable>(_ value: T, forKey key: String, encoder: JSONEncoder? = nil, plistEncoder: PropertyListEncoder? = nil) throws {
        let data: Data
        if let enc = encoder {
            data = try enc.encode(value)
        } else if let plist = plistEncoder {
            data = try plist.encode(value)
        } else if encoding == .propertyList {
            data = try _plistEncoder.encode(value)
        } else {
            data = try _jsonEncoder.encode(value)
        }
        try save(data: data, forKey: key)
    }

    /// Loads the value for the given key, or nil if not found.
    public func load<T: Decodable>(forKey key: String, as type: T.Type, decoder: JSONDecoder? = nil, plistDecoder: PropertyListDecoder? = nil) throws -> T? {
        guard let data = try loadData(forKey: key) else { return nil }
        if let dec = decoder {
            return try dec.decode(T.self, from: data)
        }
        if let plist = plistDecoder {
            return try plist.decode(T.self, from: data)
        }
        if encoding == .propertyList {
            return try _plistDecoder.decode(T.self, from: data)
        }
        return try _jsonDecoder.decode(T.self, from: data)
    }

    /// Removes the item for the given key.
    public func delete(forKey key: String) throws {
        var query = baseQuery(forKey: key)
        query[kSecClass as String] = kSecClassGenericPassword
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainError.from(status)
        }
    }

    // MARK: - Async API

    /// Async: saves a Codable value for the given key.
    public func save<T: Encodable>(_ value: T, forKey key: String, encoder: JSONEncoder? = nil, plistEncoder: PropertyListEncoder? = nil) async throws {
        try await Task.detached(priority: .userInitiated) {
            try self.save(value, forKey: key, encoder: encoder, plistEncoder: plistEncoder)
        }.value
    }

    /// Async: loads the value for the given key, or nil if not found.
    public func load<T: Decodable>(forKey key: String, as type: T.Type, decoder: JSONDecoder? = nil, plistDecoder: PropertyListDecoder? = nil) async throws -> T? {
        try await Task.detached(priority: .userInitiated) {
            try self.load(forKey: key, as: type, decoder: decoder, plistDecoder: plistDecoder)
        }.value
    }

    /// Async: removes the item for the given key.
    public func delete(forKey key: String) async throws {
        try await Task.detached(priority: .userInitiated) {
            try self.delete(forKey: key)
        }.value
    }

    /// Async: saves raw Data.
    public func save(data: Data, forKey key: String) async throws {
        try await Task.detached(priority: .userInitiated) {
            try self.save(data: data, forKey: key)
        }.value
    }

    /// Async: loads raw Data for the given key.
    public func loadData(forKey key: String) async throws -> Data? {
        try await Task.detached(priority: .userInitiated) {
            try self.loadData(forKey: key)
        }.value
    }

    /// Async: saves a string.
    public func set(_ string: String, forKey key: String) async throws {
        try await Task.detached(priority: .userInitiated) {
            try self.set(string, forKey: key)
        }.value
    }

    /// Async: loads a string.
    public func string(forKey key: String) async throws -> String? {
        try await Task.detached(priority: .userInitiated) {
            try self.string(forKey: key)
        }.value
    }

    /// Async: saves a Bool (as byte 0/1).
    public func set(_ value: Bool, forKey key: String) async throws {
        try await Task.detached(priority: .userInitiated) {
            try self.set(value, forKey: key)
        }.value
    }

    /// Async: loads a Bool.
    public func bool(forKey key: String) async throws -> Bool? {
        try await Task.detached(priority: .userInitiated) {
            try self.bool(forKey: key)
        }.value
    }

    /// Saves raw Data (e.g. PIN or token as UTF-8 bytes). Pass `accessControl` (e.g. from `SecAccessControlCreateWithFlags`) to require Touch ID/Face ID when reading.
    public func save(data: Data, forKey key: String, accessControl: SecAccessControl? = nil) throws {
        var query = baseQuery(forKey: key)
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecValueData as String] = data
        if let ac = accessControl {
            query[kSecAttrAccessible as String] = nil
            query[kSecAttrAccessControl as String] = ac
        } else {
            query[kSecAttrAccessible as String] = accessible.rawValue
        }

        var status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            try delete(forKey: key)
            if let ac = accessControl {
                query[kSecAttrAccessControl as String] = ac
            }
            status = SecItemAdd(query as CFDictionary, nil)
        }
        if status != errSecSuccess {
            throw KeychainError.from(status)
        }
    }

    /// Loads raw Data for the given key, or nil if not found. Pass `authenticationPrompt` to show a custom message when the item is protected by Touch ID/Face ID.
    public func loadData(forKey key: String, authenticationPrompt: String? = nil) throws -> Data? {
        var query = baseQuery(forKey: key)
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        if let prompt = authenticationPrompt {
            query[kSecUseOperationPrompt as String] = prompt
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        if status != errSecSuccess {
            throw KeychainError.from(status)
        }
        return result as? Data
    }

    // MARK: - Convenience: String, Bool

    /// Saves a string (UTF-8). Shorthand for save(data:forKey:) with Data(string.utf8).
    public func set(_ string: String, forKey key: String) throws {
        try save(data: Data(string.utf8), forKey: key)
    }

    /// Loads a string, or nil if not found or not valid UTF-8.
    public func string(forKey key: String) throws -> String? {
        guard let data = try loadData(forKey: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Saves a Bool as a single byte (0/1) in Keychain so other apps see binary data, not a string.
    public func set(_ value: Bool, forKey key: String) throws {
        try save(data: Data([value ? 1 : 0]), forKey: key)
    }

    /// Loads a Bool; nil if not found. Supports both byte storage (0/1) and legacy "true"/"false" string.
    public func bool(forKey key: String) throws -> Bool? {
        guard let data = try loadData(forKey: key) else { return nil }
        if data.count == 1 { return data[0] != 0 }
        guard let s = String(data: data, encoding: .utf8) else { return nil }
        return s == "true"
    }

    // MARK: - Subscript (KeychainAccess-style)

    /// Subscript for string value. Get: returns stored string or nil. Set: saves UTF-8 data; set to nil to delete.
    public subscript(string key: String) -> String? {
        get { try? string(forKey: key) }
        set {
            if let v = newValue {
                try? set(v, forKey: key)
            } else {
                try? delete(forKey: key)
            }
        }
    }

    /// Subscript for raw Data. Get: returns stored data or nil. Set: saves data; set to nil to delete.
    public subscript(data key: String) -> Data? {
        get { try? loadData(forKey: key) }
        set {
            if let v = newValue {
                try? save(data: v, forKey: key)
            } else {
                try? delete(forKey: key)
            }
        }
    }

    /// Returns true if an item exists for the key (does not read data).
    public func has(key: String) -> Bool {
        var query = baseQuery(forKey: key)
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecReturnData as String] = false
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    // MARK: - Static API (default store)

    public static func save<T: Encodable>(_ value: T, forKey key: String, encoder: JSONEncoder? = nil, plistEncoder: PropertyListEncoder? = nil) throws {
        try defaultStore.save(value, forKey: key, encoder: encoder, plistEncoder: plistEncoder)
    }

    public static func load<T: Decodable>(forKey key: String, as type: T.Type, decoder: JSONDecoder? = nil, plistDecoder: PropertyListDecoder? = nil) throws -> T? {
        try defaultStore.load(forKey: key, as: type, decoder: decoder, plistDecoder: plistDecoder)
    }

    public static func delete(forKey key: String) throws {
        try defaultStore.delete(forKey: key)
    }

    public static func set(_ string: String, forKey key: String) throws {
        try defaultStore.set(string, forKey: key)
    }

    public static func string(forKey key: String) throws -> String? {
        try defaultStore.string(forKey: key)
    }

    public static func set(_ value: Bool, forKey key: String) throws {
        try defaultStore.set(value, forKey: key)
    }

    public static func bool(forKey key: String) throws -> Bool? {
        try defaultStore.bool(forKey: key)
    }

    public static func save(data: Data, forKey key: String) throws {
        try defaultStore.save(data: data, forKey: key)
    }

    public static func loadData(forKey key: String) throws -> Data? {
        try defaultStore.loadData(forKey: key)
    }

    public static func has(key: String) -> Bool {
        defaultStore.has(key: key)
    }

    public static func save<T: Encodable>(_ value: T, forKey key: String, encoder: JSONEncoder? = nil, plistEncoder: PropertyListEncoder? = nil) async throws {
        try await defaultStore.save(value, forKey: key, encoder: encoder, plistEncoder: plistEncoder)
    }

    public static func load<T: Decodable>(forKey key: String, as type: T.Type, decoder: JSONDecoder? = nil, plistDecoder: PropertyListDecoder? = nil) async throws -> T? {
        try await defaultStore.load(forKey: key, as: type, decoder: decoder, plistDecoder: plistDecoder)
    }

    public static func delete(forKey key: String) async throws {
        try await defaultStore.delete(forKey: key)
    }

    public static func save(data: Data, forKey key: String) async throws {
        try await defaultStore.save(data: data, forKey: key)
    }

    public static func loadData(forKey key: String) async throws -> Data? {
        try await defaultStore.loadData(forKey: key)
    }

    public static func set(_ string: String, forKey key: String) async throws {
        try await defaultStore.set(string, forKey: key)
    }

    public static func string(forKey key: String) async throws -> String? {
        try await defaultStore.string(forKey: key)
    }

    public static func set(_ value: Bool, forKey key: String) async throws {
        try await defaultStore.set(value, forKey: key)
    }

    public static func bool(forKey key: String) async throws -> Bool? {
        try await defaultStore.bool(forKey: key)
    }

    private func baseQuery(forKey key: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        return query
    }
}

// MARK: - Accessible

/// Keychain item accessibility (kSecAttrAccessible).
public enum KeychainAccessible: RawRepresentable {
    case whenUnlocked
    case whenUnlockedThisDeviceOnly
    case afterFirstUnlock
    case afterFirstUnlockThisDeviceOnly
    case whenPasscodeSetThisDeviceOnly

    public var rawValue: CFString {
        switch self {
        case .whenUnlocked: return kSecAttrAccessibleWhenUnlocked
        case .whenUnlockedThisDeviceOnly: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlock: return kSecAttrAccessibleAfterFirstUnlock
        case .afterFirstUnlockThisDeviceOnly: return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .whenPasscodeSetThisDeviceOnly: return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }

    public init?(rawValue: CFString) {
        switch rawValue {
        case kSecAttrAccessibleWhenUnlocked: self = .whenUnlocked
        case kSecAttrAccessibleWhenUnlockedThisDeviceOnly: self = .whenUnlockedThisDeviceOnly
        case kSecAttrAccessibleAfterFirstUnlock: self = .afterFirstUnlock
        case kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: self = .afterFirstUnlockThisDeviceOnly
        case kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly: self = .whenPasscodeSetThisDeviceOnly
        default: return nil
        }
    }
}

// MARK: - Errors

public enum KeychainError: Error, LocalizedError {
    case duplicateItem
    case itemNotFound
    case invalidItemFormat
    case unexpected(OSStatus)

    static func from(_ status: OSStatus) -> KeychainError {
        switch status {
        case errSecDuplicateItem: return .duplicateItem
        case errSecItemNotFound: return .itemNotFound
        case -26275: return .invalidItemFormat  // errSecInvalidAttributes
        default: return .unexpected(status)
        }
    }

    public var errorDescription: String? {
        switch self {
        case .duplicateItem: return "Duplicate keychain item"
        case .itemNotFound: return "Item not found"
        case .invalidItemFormat: return "Invalid item format"
        case .unexpected(let s): return "Keychain error: \(s)"
        }
    }
}
