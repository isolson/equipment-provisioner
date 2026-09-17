import Foundation
import SystemConfiguration

/// Watches for network-interface / link changes and reports them on the main
/// queue. Runs entirely unprivileged — observing the dynamic store needs no root.
final class InterfaceWatcher {
    private var store: SCDynamicStore?
    private let onChange: () -> Void

    init(onChange: @escaping () -> Void) {
        self.onChange = onChange
    }

    func start() {
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                            retain: nil, release: nil, copyDescription: nil)
        let callback: SCDynamicStoreCallBack = { _, _, info in
            guard let info = info else { return }
            let me = Unmanaged<InterfaceWatcher>.fromOpaque(info).takeUnretainedValue()
            DispatchQueue.main.async { me.onChange() }
        }
        guard let store = SCDynamicStoreCreate(nil, "com.isolson.wispreach" as CFString,
                                               callback, &context) else { return }
        self.store = store

        // Notify on link state and interface add/remove for any enN.
        let patterns = [
            "State:/Network/Interface/en[0-9]+/Link" as CFString,
            "State:/Network/Interface" as CFString,
            "State:/Network/Global/IPv4" as CFString,
        ] as CFArray
        SCDynamicStoreSetNotificationKeys(store, nil, patterns)

        if let rl = SCDynamicStoreCreateRunLoopSource(nil, store, 0) {
            CFRunLoopAddSource(CFRunLoopGetCurrent(), rl, .commonModes)
        }
    }
}
