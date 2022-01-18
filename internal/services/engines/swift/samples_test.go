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
	SampleVulnerableHSSWIFT6 = `import CryptoSwift

		"SwiftSummit".md5()
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
