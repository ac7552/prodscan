// Prodscan Dashboard -- native macOS app.
// Starts the local, token-gated dashboard server as a child process and shows
// its UI inside a native WKWebView window. No browser, no visible localhost
// URL. Quitting the app stops the server.

import Cocoa
import WebKit

final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate {
    var window: NSWindow!
    var web: WKWebView!
    var server: Process?
    let fm = FileManager.default

    // Where the Python engine lives: baked-in project path, else bundle Resources.
    func engineDir() -> String {
        // 1) explicit override, 2) engine bundled in Resources, 3) the .app
        // sitting inside the repo (dev), 4) current directory.
        if let e = ProcessInfo.processInfo.environment["PRODSCAN_ENGINE_DIR"],
           fm.fileExists(atPath: e + "/dashboard.py") { return e }
        if let r = Bundle.main.resourcePath,
           fm.fileExists(atPath: r + "/dashboard.py") { return r }
        let up = (Bundle.main.bundlePath as NSString).deletingLastPathComponent
        if fm.fileExists(atPath: up + "/dashboard.py") { return up }
        return fm.currentDirectoryPath
    }

    func randomToken(_ n: Int = 24) -> String {
        let cs = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        return String((0..<n).map { _ in cs[Int(arc4random_uniform(UInt32(cs.count)))] })
    }

    func applicationDidFinishLaunching(_ note: Notification) {
        let token = randomToken()
        let support = NSHomeDirectory() + "/Library/Application Support/prodscan"
        try? fm.createDirectory(atPath: support, withIntermediateDirectories: true)
        let epf = support + "/endpoint.json"
        try? fm.removeItem(atPath: epf)

        // Launch the dashboard server (OS-assigned port via --port 0).
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = [engineDir() + "/dashboard.py", "--port", "0"]
        p.currentDirectoryURL = URL(fileURLWithPath: engineDir())
        var env = ProcessInfo.processInfo.environment
        env["PRODSCAN_TOKEN"] = token
        env["PRODSCAN_ENDPOINT_FILE"] = epf
        p.environment = env
        do { try p.run() } catch { NSLog("server launch failed: \(error)") }
        server = p

        // Native window + embedded web view.
        let rect = NSRect(x: 0, y: 0, width: 1100, height: 760)
        window = NSWindow(contentRect: rect,
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Prodscan Dashboard"
        window.center()
        window.setFrameAutosaveName("ProdscanMain")
        let cfg = WKWebViewConfiguration()
        web = WKWebView(frame: rect, configuration: cfg)
        web.autoresizingMask = [.width, .height]
        web.navigationDelegate = self
        window.contentView = web
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        waitForEndpoint(epf, tries: 60)
    }

    func waitForEndpoint(_ path: String, tries: Int) {
        if tries <= 0 { showError(); return }
        if let data = fm.contents(atPath: path),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let urlStr = obj["url"] as? String, let url = URL(string: urlStr) {
            web.load(URLRequest(url: url))
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
            self.waitForEndpoint(path, tries: tries - 1)
        }
    }

    func showError() {
        web.loadHTMLString("<body style='font:16px -apple-system;padding:40px;color:#333'>"
            + "<h2>Couldn't start the dashboard server.</h2>"
            + "<p>Check that <code>/usr/bin/python3</code> exists and the engine "
            + "folder is present.</p></body>", baseURL: nil)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ s: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ note: Notification) { server?.terminate() }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
