//TODO: Make a generic HTML handler
import UIKit

class HTMLViewController: UIViewController {
    @IBOutlet weak var webView: UIWebView!
    
    var contentString: String? = nil {
        didSet {
            loadWebView(from: contentString ?? "")
        }
    }
    
    var contentHTMLFile: String? = nil {
        didSet {
            let filePath = Bundle.main.path(forResource: contentHTMLFile, ofType: nil) ?? ""
            let fileContents = (try? String(contentsOfFile: filePath, encoding: .utf8)) ?? ""
            loadWebView(from: fileContents)
        }
    }
}

extension HTMLViewController {
    func loadWebView(from content:String) {
        let baseURL = URL(fileURLWithPath: Bundle.main.resourcePath!, isDirectory: true)
        webView.loadHTMLString(content, baseURL: baseURL)
    }
    
    @IBAction func backItemPressed() {
        dismiss(animated: true, completion: nil)
    }
}
