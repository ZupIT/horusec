// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package swift

const (
	SampleVulnerableHSSWIFT2 = `
class CoreDataManager {
    static let shared = CoreDataManager()
    private init() {}
    private lazy var persistentContainer: NSPersistentContainer = {
        let container = NSPersistentContainer(name: "PillReminder")
        container.loadPersistentStores(completionHandler: { _, error in
            _ = error.map { fatalError("Unresolved error \($0)") }
        })
        return container
    }()
    
    var mainContext: NSManagedObjectContext {
        return persistentContainer.viewContext
    }
    
    func backgroundContext() -> NSManagedObjectContext {
        return persistentContainer.newBackgroundContext()
    }
}
...
func savePill(pass: String) throws {
    let context = CoreDataManager.shared.backgroundContext()
    context.perform {
        let entity = Pill.entity()
        let pill = Pill(entity: entity, insertInto: context)
        pill.pass = pass
        pill.amount = 2
        pill.dozePerDay = 1
        pill.lastUpdate = Date()
        try context.save()
    }
}
`
	SampleVulnerableHSSWIFT3 = `
...
var tlsMinimumSupportedProtocolVersion: tls_protocol_version_t.DTLSv11
`
	SampleVulnerableHSSWIFT4 = `
...
var tlsMinimumSupportedProtocolVersion: tls_protocol_version_t.TLSv11
`
	SampleVulnerableHSSWIFT5 = `import PackageDescription
let package = Package(name: "Alamofire",
                      platforms: [.macOS(.v10_12),
                                  .iOS(.v10),
                                  .tvOS(.v10),
                                  .watchOS(.v3)],
                      products: [.library(name: "Alamofire", targets: ["Alamofire"]),
							 	 .library(name: "FridaGadget", targets: ["FridaGadget"]),
							 	 .library(name: "cynject", targets: ["cynject"]),
							 	 .library(name: "libcycript", targets: ["libcycript"])],
                      targets: [.target(name: "Alamofire",
                                        path: "Source",
                                        exclude: ["Info.plist"],
                                        linkerSettings: [.linkedFramework("CFNetwork",
                                                                          .when(platforms: [.iOS,
                                                                                            .macOS,
                                                                                            .tvOS,
                                                                                            .watchOS]))]),
                                .testTarget(name: "AlamofireTests",
                                            dependencies: ["Alamofire"],
                                            path: "Tests",
                                            exclude: ["Resources", "Info.plist"])],
                      swiftLanguageVersions: [.v5])`
	SampleVulnerableHSSWIFT6 = `import CryptoSwift

		"SwiftSummit".md5()
`
	SampleVulnerableHSSWIFT7 = `
import CommonCrypto

let algorithm = CCAlgorithm(kCCAlgorithmDES) // Noncompliant: 64 bits block size
`
	SampleVulnerableHSSWIFT8 = `
import IDZSwiftCommonCrypto

let cryptor = Cryptor(operation: .encrypt, algorithm: .des, options: [.ECBMode, .PKCS7Padding], key: key, iv:[UInt8]())
`
	SampleVulnerableHSSWIFT9 = `
import CryptoSwift

Blowfish(key: key, blockMode: CBC(iv: iv), padding: .pkcs7).encrypt(message)
`
	SampleVulnerableHSSWIFT10 = `
MD6( cStr, strlen(cStr), result );
`
	SampleVulnerableHSSWIFT11 = `
MD5( cStr, strlen(cStr), result );
`
	SampleVulnerableHSSWIFT12 = `
let digest = Insecure.SHA1.hash(data: data)
`
	SampleVulnerableHSSWIFT13 = `
	let fm = FileManager.default
	if(fm.fileExists(atPath: "/private/var/lib/apt")) || (fm.fileExists(atPath: "/Applications/Cydia.app")) {
	  ...
	}
`
	SampleVulnerableHSSWIFT14 = `
func loadPage(content) {
	let webView1 = UIWebView()
	webView1.loadHTMLString("<html><body><p>"+content+"</p></body></html>", baseURL: nil)
} 
`
	SampleVulnerableHSSWIFT15 = `
    let crypt = CkoCrypt2()

    // Specify 3DES for the encryption algorithm:
    crypt.CryptAlgorithm = "3des"
`
	SampleVulnerableHSSWIFT16 = `
try! realm.write {
  ...
}
`
	SampleVulnerableHSSWIFT17 = `
let config = URLSessionConfiguration.default
config.tlsMinimumSupportedProtocol = .tlsProtocol12
`
	SampleVulnerableHSSWIFT18 = `
// read from clipboard
let content = UIPasteboard.general.string
`
	SampleVulnerableHSSWIFT19 = `
    do {
        try data?.write(to: documentURL, options: .noFileProtection)
    } catch {
        print("Error...Cannot save data!!!See error:(error.localizedDescription)")
    }
`
	SampleVulnerableHSSWIFT20 = `
import SafariServices
func showTutorial(url: String) {
	let config = SFSafariViewController.Configuration()
	config.entersReaderIfAvailable = true

	let vc = SFSafariViewController(url: url, configuration: config)
	present(vc, animated: true)
}
`
	SampleVulnerableHSSWIFT21 = `
textField.autocorrectionType = .no
`
	SampleVulnerableHSSWIFT22 = `
CC_MD4( cStr, strlen(cStr), result );
`
	SampleVulnerableHSSWIFT23 = `
CC_MD2( cStr, strlen(cStr), result );
`
	SampleVulnerableHSSWIFT24 = `
let err = SD.executeChange("SELECT * FROM User where user="+ valuesFromInput) {
    //there was an error during the insert, handle it here
} else {
    //no error, the row was inserted successfully
}
`
)

const (
	SampleSafeHSSWIFT2 = `
class CoreDataManager {
    static let shared = CoreDataManager()
    private init() {}
    private lazy var persistentContainer: NSPersistentContainer = {
        let container = NSPersistentContainer(name: "PillReminder")
        container.loadPersistentStores(completionHandler: { _, error in
            _ = error.map { fatalError("Unresolved error \($0)") }
        })
        return container
    }()
    
    var mainContext: NSManagedObjectContext {
        return persistentContainer.viewContext
    }
    
    func backgroundContext() -> NSManagedObjectContext {
        return persistentContainer.newBackgroundContext()
    }
}
...
func savePill(pass: String) throws {
    let context = CoreDataManager.shared.backgroundContext()
    context.perform {
        let entity = Pill.entity()
        let pill = Pill(entity: entity, insertInto: context)
        pill.password = EncryptedDATAStack(passphraseKey:pass, modelName:"MyAppModel")
        pill.amount = 2
        pill.dozePerDay = 1
        pill.lastUpdate = Date()
        try context.save()
    }
}
`
	SampleSafeHSSWIFT3 = `var tlsMinimumSupportedProtocolVersion: tls_protocol_version_t.DTLSv12`
	SampleSafeHSSWIFT4 = `var tlsMinimumSupportedProtocolVersion: tls_protocol_version_t.TLSv12`
	SampleSafeHSSWIFT5 = `import PackageDescription
let package = Package(name: "Alamofire",
                      platforms: [.macOS(.v10_12),
                                  .iOS(.v10),
                                  .tvOS(.v10),
                                  .watchOS(.v3)],
                      products: [.library(name: "Alamofire", targets: ["Alamofire"])],
                      targets: [.target(name: "Alamofire",
                                        path: "Source",
                                        exclude: ["Info.plist"],
                                        linkerSettings: [.linkedFramework("CFNetwork",
                                                                          .when(platforms: [.iOS,
                                                                                            .macOS,
                                                                                            .tvOS,
                                                                                            .watchOS]))]),
                                .testTarget(name: "AlamofireTests",
                                            dependencies: ["Alamofire"],
                                            path: "Tests",
                                            exclude: ["Resources", "Info.plist"])],
                      swiftLanguageVersions: [.v5])`
	SampleSafeHSSWIFT6 = `import Foundation
import var CommonCrypto.CC_MD5_DIGEST_LENGTH
import func CommonCrypto.CC_MD5
import typealias CommonCrypto.CC_LONG

func MD5(string: String) -> Data {
        let length = Int(CC_MD5_DIGEST_LENGTH)
        let messageData = string.data(using:.utf8)!
        var digestData = Data(count: length)

        _ = digestData.withUnsafeMutableBytes { digestBytes -> UInt8 in
            messageData.withUnsafeBytes { messageBytes -> UInt8 in
                if let messageBytesBaseAddress = messageBytes.baseAddress, let digestBytesBlindMemory = digestBytes.bindMemory(to: UInt8.self).baseAddress {
                    let messageLength = CC_LONG(messageData.count)
                    CC_MD5(messageBytesBaseAddress, messageLength, digestBytesBlindMemory)
                }
                return 0
            }
        }
        return digestData
    }

//Test:
let md5Data = MD5(string:"Hello")`
	SampleSafeHSSWIFT7 = `
import Crypto

let sealedBox = try AES.GCM.seal(input, using: key) // Compliant`
	SampleSafeHSSWIFT8 = `
import Crypto

let sealedBox = try AES.GCM.seal(input, using: key) // Compliant`
	SampleSafeHSSWIFT9 = `
import Crypto

let encryptedBytes = try AES(key: [1,2,3,...,32], blockMode: CBC(iv: [1,2,3,...,16]), padding: .pkcs7)
`
	SampleSafeHSSWIFT10 = `
import Crypto

let encryptedBytes = try AES(key: [1,2,3,...,32], blockMode: CBC(iv: [1,2,3,...,16]), padding: .pkcs7)`
	SampleSafeHSSWIFT11 = `
import Crypto

let encryptedBytes = try AES(key: [1,2,3,...,32], blockMode: CBC(iv: [1,2,3,...,16]), padding: .pkcs7)`
	SampleSafeHSSWIFT12 = `
func sha256(data : Data) -> Data {
    var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
    }
    return Data(hash)
}
`
	SampleSafeHSSWIFT13 = `
do {
	try jailBreakTestText.write(toFile:"/private/jailBreakTestText.txt", atomically:true, encoding:String.Encoding.utf8)
	return true
} catch {
	return false
}
`
	SampleSafeHSSWIFT14 = `
func loadPage() {
	let webView1 = UIWebView()
	webView1.loadHTMLString("<html><body><p>Hello!</p></body></html>", baseURL: nil)
} 
`
	SampleSafeHSSWIFT15 = `
func sha256(data : Data) -> Data {
    var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
    }
    return Data(hash)
}
`
	SampleSafeHSSWIFT16 = `
realm.beginWrite()
...
try! realm.commitWrite()
`
	SampleSafeHSSWIFT17 = `
let config = URLSessionConfiguration.default
`
	SampleSafeHSSWIFT18 = `
let content = "Static content"
`
	SampleSafeHSSWIFT19 = `
    do {
        try data?.write(to: documentURL, options: null)
    } catch {
        print("Error...Cannot save data!!!See error:(error.localizedDescription)")
    }
`
	SampleSafeHSSWIFT20 = `
func showTutorial(url: String) {
	let vc = UIApplication.shared.openURL(url)
	present(vc, animated: true)
}
`
	SampleSafeHSSWIFT21 = `
textField.autocorrectionType = .yes
`
	SampleSafeHSSWIFT22 = `
import Crypto

let encryptedBytes = try AES(key: [1,2,3,...,32], blockMode: CBC(iv: [1,2,3,...,16]), padding: .pkcs7)`
	SampleSafeHSSWIFT23 = `
import Crypto

let encryptedBytes = try AES(key: [1,2,3,...,32], blockMode: CBC(iv: [1,2,3,...,16]), padding: .pkcs7)`
	SampleSafeHSSWIFT24 = `
if let err = SD.executeChange("SELECT * FROM User where user=?", withArgs: [name, population, isWarm, foundedIn]) {
    //there was an error during the insert, handle it here
} else {
    //no error, the row was inserted successfully
}
`

	Sample2SafeHSSWIFT24 = `
public extension Expression {
    func observe(
        view: UIView,
        controller: BeagleControllerProtocol?,
        updateFunction: @escaping (T?) -> Void
    ) {
        switch self {
        case let .expression(expression):
            controller?.addBinding(expression: expression, in: view, update: updateFunction)
        case let .value(value):
            updateFunction(value)
        }
    }

    func evaluate(with view: UIView?, implicitContext: Context? = nil) -> T? {
        switch self {
        case let .expression(expression):
            if let implicitContext = implicitContext {
                let auxView = UIView()
                auxView.parentContext = view
                auxView.setContext(implicitContext)
                return evaluate(with: auxView)
            }
            
            return view?.evaluateExpression(expression).transform()
        case let .value(value):
            return value
        }
    }
}

// MARK: - RepresentableByParsableString
extension ContextExpression: RepresentableByParsableString {
    public static var parser = singleOrMultipleExpression

    public var rawValue: String {
        switch self {
        case .multiple(let multiple):
            return multiple.rawValue
        case .single(let single):
            return single.rawValue
        }
    }
}

extension SingleExpression: RepresentableByParsableString {
    public static let parser = singleExpression
    
    public var rawValue: String {
        var result = "@{"
        switch self {
        case let .value(value):
            result += value.rawValue
        case let .operation(operation):
            result += operation.rawValue
        }
        
        result += "}"
        return result
    }
}

extension MultipleExpression: RepresentableByParsableString {
    public static let parser = multipleExpression

    public var rawValue: String {
        var result = ""
        for node in nodes {
            switch node {
            case let .string(string):
                result += string
            case let .expression(expression):
                result += expression.rawValue
            }
        }
        return result
    }
}
`
)
