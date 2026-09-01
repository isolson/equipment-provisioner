import AppKit

/// Menu-bar controller: owns the status item, builds the menu, runs auto-apply.
final class AppController: NSObject, NSMenuDelegate {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private var watcher: InterfaceWatcher!
    private let autoApplyKey = "autoApplyEnabled"

    private var autoApplyEnabled: Bool {
        get {
            // Default ON for a fresh install.
            if UserDefaults.standard.object(forKey: autoApplyKey) == nil { return true }
            return UserDefaults.standard.bool(forKey: autoApplyKey)
        }
        set { UserDefaults.standard.set(newValue, forKey: autoApplyKey) }
    }

    func start() {
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "network", accessibilityDescription: "WISP-Reach")
            button.image?.isTemplate = true
        }
        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu

        watcher = InterfaceWatcher { [weak self] in self?.onNetworkChange() }
        watcher.start()

        // Apply once at launch for any dongle already plugged in.
        onNetworkChange()
    }

    // MARK: - Auto-apply

    private func onNetworkChange() {
        guard autoApplyEnabled, Privileged.helperInstalled() else { return }
        for iface in InterfaceInventory.targets() {
            let active = Privileged.activeAliases(ifname: iface.bsdName)
            // Re-apply only if some alias is missing (idempotent, avoids hammering sudo).
            if !Set(Presets.allIPs).isSubset(of: active) {
                let res = Privileged.apply(ifname: iface.bsdName)
                if !res.ok { NSLog("wisp-reach: apply \(iface.bsdName) failed: \(res.output)") }
            }
        }
    }

    // MARK: - Menu building

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()

        let header = NSMenuItem(title: "WISP-Reach", action: nil, keyEquivalent: "")
        header.isEnabled = false
        menu.addItem(header)
        menu.addItem(.separator())

        if !Privileged.helperInstalled() {
            let warn = NSMenuItem(title: "⚠︎ Helper not installed — run install.sh",
                                  action: nil, keyEquivalent: "")
            warn.isEnabled = false
            menu.addItem(warn)
            menu.addItem(.separator())
        }

        let targets = InterfaceInventory.targets()
        if targets.isEmpty {
            let none = NSMenuItem(title: "No USB Ethernet dongle detected",
                                  action: nil, keyEquivalent: "")
            none.isEnabled = false
            menu.addItem(none)
        } else {
            for iface in targets {
                addInterfaceSection(iface, to: menu)
                menu.addItem(.separator())
            }
        }

        let auto = NSMenuItem(title: "Auto-apply on plug-in",
                              action: #selector(toggleAutoApply), keyEquivalent: "")
        auto.target = self
        auto.state = autoApplyEnabled ? .on : .off
        menu.addItem(auto)

        let clearAll = NSMenuItem(title: "Clear all interfaces",
                                  action: #selector(clearAll), keyEquivalent: "")
        clearAll.target = self
        clearAll.isEnabled = !targets.isEmpty
        menu.addItem(clearAll)

        menu.addItem(.separator())
        let quit = NSMenuItem(title: "Quit WISP-Reach", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
    }

    private func addInterfaceSection(_ iface: EthInterface, to menu: NSMenu) {
        let title = NSMenuItem(title: "\(iface.bsdName) — \(iface.displayName)",
                               action: nil, keyEquivalent: "")
        title.isEnabled = false
        menu.addItem(title)

        let active = Privileged.activeAliases(ifname: iface.bsdName)
        let statusText: String
        if active.isEmpty {
            statusText = "   no aliases"
        } else {
            statusText = "   active: " + Presets.allIPs.filter { active.contains($0) }
                .joined(separator: ", ")
        }
        let status = NSMenuItem(title: statusText, action: nil, keyEquivalent: "")
        status.isEnabled = false
        menu.addItem(status)

        let reach = NSMenuItem(title: "Reach Everything",
                               action: #selector(applyReachEverything(_:)), keyEquivalent: "")
        reach.target = self
        reach.representedObject = iface.bsdName
        menu.addItem(reach)

        // Per-vendor presets in a submenu to keep things tidy.
        let presetsItem = NSMenuItem(title: "Vendor preset", action: nil, keyEquivalent: "")
        let sub = NSMenu()
        for preset in Presets.vendors {
            let item = NSMenuItem(title: "\(preset.title)  (\(preset.reaches))",
                                  action: #selector(applyPreset(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = ["ifname": iface.bsdName, "preset": preset.key]
            sub.addItem(item)
        }
        presetsItem.submenu = sub
        menu.addItem(presetsItem)

        let clear = NSMenuItem(title: "Clear \(iface.bsdName)",
                               action: #selector(clearInterface(_:)), keyEquivalent: "")
        clear.target = self
        clear.representedObject = iface.bsdName
        clear.isEnabled = !active.isEmpty
        menu.addItem(clear)
    }

    // MARK: - Actions

    @objc private func applyReachEverything(_ sender: NSMenuItem) {
        guard let ifname = sender.representedObject as? String else { return }
        report(Privileged.apply(ifname: ifname), verb: "Reach Everything on \(ifname)")
    }

    @objc private func applyPreset(_ sender: NSMenuItem) {
        guard let d = sender.representedObject as? [String: String],
              let ifname = d["ifname"], let preset = d["preset"] else { return }
        report(Privileged.apply(ifname: ifname, preset: preset), verb: "\(preset) on \(ifname)")
    }

    @objc private func clearInterface(_ sender: NSMenuItem) {
        guard let ifname = sender.representedObject as? String else { return }
        report(Privileged.clear(ifname: ifname), verb: "Clear \(ifname)")
    }

    @objc private func clearAll() {
        for iface in InterfaceInventory.targets() {
            _ = Privileged.clear(ifname: iface.bsdName)
        }
    }

    @objc private func toggleAutoApply() {
        autoApplyEnabled.toggle()
        if autoApplyEnabled { onNetworkChange() }
    }

    @objc private func quit() { NSApp.terminate(nil) }

    private func report(_ res: Privileged.Result, verb: String) {
        guard !res.ok else { return }
        NSLog("wisp-reach: \(verb) failed: \(res.output)")
        let alert = NSAlert()
        alert.messageText = "\(verb) failed"
        alert.informativeText = res.output.isEmpty
            ? "The helper returned an error. Is it installed and in sudoers?"
            : res.output
        alert.alertStyle = .warning
        alert.runModal()
    }
}
