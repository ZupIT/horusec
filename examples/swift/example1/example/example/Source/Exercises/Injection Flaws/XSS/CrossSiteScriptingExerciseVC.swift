import UIKit

class CrossSiteScriptingExerciseVC: UIViewController {
    @IBOutlet weak var webview: UIWebView!
    @IBOutlet weak var textField: UITextField!
    
    @IBAction func loadItemPressed() {
        let webText = "Welcome to XSS Exercise !!! \n Here is UIWebView ! \(textField.text ?? "")"
        webview.loadHTMLString(webText, baseURL: nil)
    }
}
