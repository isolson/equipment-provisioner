import AppKit

// Menu-bar-only agent. LSUIElement in Info.plist keeps it out of the Dock; we
// also set .accessory here so it works when run directly from the build dir.
let app = NSApplication.shared
app.setActivationPolicy(.accessory)

let controller = AppController()
controller.start()

app.run()
