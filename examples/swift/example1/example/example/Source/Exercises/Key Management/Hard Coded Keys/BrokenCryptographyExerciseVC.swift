import UIKit

func pathDocumentDirectory(fileName: String) -> String {
    let documentsPath = NSSearchPathForDirectoriesInDomains(.documentDirectory,
                                                            .userDomainMask, true)[0]
    return documentsPath + "/\(fileName)"
}

class BrokenCryptographyExerciseVC: UIViewController {
    var encryptionKey = "myencrytionkey"
    @IBOutlet weak var passwordTextField: UITextField!
    
    @IBAction func showItemPressed() {
        
         UIAlertController.showAlertWith(title: "BrokenCryptography", message: "Try Harder!")
 
       /* let encryptedFilePath = pathDocumentDirectory(fileName: "encrypted")
        let encryptedFilePathURL = URL(fileURLWithPath: encryptedFilePath)
        guard let encryptedData = try? Data(contentsOf: encryptedFilePathURL)  else {
            return
        }
        
        let encryptionKeyData = encryptionKey.data(using: .utf8)
        let decryptedData = encryptedData.aes(operation: kCCDecrypt, keyData: encryptionKeyData!)
        let decryptedPassword = String(data: decryptedData, encoding: .utf8) ?? ""
        print(decryptedPassword)
        UIAlertController.showAlertWith(title: "BrokenCryptography", message: decryptedPassword) */
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        let password = "b@nkP@ssword123"
        passwordTextField.text = password
        let data = password.data(using: .utf8)
        print(data!)
        
        let encryptionKeyData = encryptionKey.data(using: .utf8)
        let encryptedData = data?.aes(operation: kCCEncrypt, keyData: encryptionKeyData!)
        let url = URL(fileURLWithPath: pathDocumentDirectory(fileName: "encrypted"))
        try? encryptedData?.write(to: url, options: .atomic)
    }
}
