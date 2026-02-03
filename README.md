# KeychainStore

A Swift DSL for Keychain: save/load/delete by key, Codable, async, no dependencies.

## Requirements

- iOS 15.0+ / macOS 12.0+
- Swift 5.9+
- Xcode 15.0+

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/beliybear/KeychainStore.git", from: "1.0.0")
]
```

## Usage

```swift
import KeychainStore

let store = KeychainStore(service: "com.myapp.auth")

struct Token: Codable { let accessToken: String; let refreshToken: String }
try store.save(Token(accessToken: "abc", refreshToken: "xyz"), forKey: "token")
let token = try store.load(forKey: "token", as: Token.self)

// String / subscript
store[string: "key"] = "value"
let s = store[string: "key"]
```

## Credits

- [beliybear](https://socprofile.com/beliy.bear/) (Ian Belyakov)

## License

MIT
