import Foundation
import IOKit
import IOKit.network
import SystemConfiguration

/// Describes one Ethernet-capable BSD interface.
struct EthInterface {
    let bsdName: String        // e.g. "en7"
    let displayName: String    // e.g. "USB 10/100/1000 LAN"
    let isUSB: Bool
    let isBuiltin: Bool

    /// The interfaces we're willing to touch: external USB Ethernet only.
    var isTarget: Bool { isUSB && !isBuiltin }
}

enum InterfaceInventory {

    /// All Ethernet-type interfaces, classified USB vs built-in.
    static func ethernetInterfaces() -> [EthInterface] {
        guard let all = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else { return [] }
        var out: [EthInterface] = []
        for iface in all {
            guard let type = SCNetworkInterfaceGetInterfaceType(iface),
                  (type as String) == (kSCNetworkInterfaceTypeEthernet as String),
                  let bsd = SCNetworkInterfaceGetBSDName(iface) as String? else { continue }
            let display = (SCNetworkInterfaceGetLocalizedDisplayName(iface) as String?) ?? bsd
            let (usb, builtin) = classify(bsdName: bsd)
            out.append(EthInterface(bsdName: bsd, displayName: display,
                                    isUSB: usb, isBuiltin: builtin))
        }
        return out.sorted { $0.bsdName < $1.bsdName }
    }

    /// Only the interfaces we auto-apply to.
    static func targets() -> [EthInterface] {
        ethernetInterfaces().filter { $0.isTarget }
    }

    /// Walk the IORegistry provider chain for the given BSD name. An interface is
    /// "USB" if any ancestor is a USB device/host; "built-in" comes from the NIC's
    /// IOBuiltin property. SystemConfiguration alone can't tell USB from built-in,
    /// so we go to IOKit.
    static func classify(bsdName: String) -> (usb: Bool, builtin: Bool) {
        let matching = IOServiceMatching("IOEthernetInterface") as NSMutableDictionary
        matching["BSD Name"] = bsdName

        var iterator: io_iterator_t = 0
        guard IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) == KERN_SUCCESS else {
            return (false, false)
        }
        defer { IOObjectRelease(iterator) }

        let service = IOIteratorNext(iterator)
        guard service != 0 else { return (false, false) }
        defer { IOObjectRelease(service) }

        // Built-in flag lives on the IONetworkController parent of the interface.
        var builtin = boolProperty(service, "IOBuiltin")

        // Walk up the provider chain looking for a USB ancestor.
        var usb = false
        var current = service
        IOObjectRetain(current)
        for _ in 0..<24 {  // provider chains are short; cap to avoid runaway
            if !builtin { builtin = boolProperty(current, "IOBuiltin") }
            if let cls = className(current), cls.hasPrefix("IOUSB") {
                usb = true
            }
            var parent: io_registry_entry_t = 0
            let kr = IORegistryEntryGetParentEntry(current, kIOServicePlane, &parent)
            IOObjectRelease(current)
            if kr != KERN_SUCCESS || parent == 0 { current = 0; break }
            current = parent
            if usb { /* keep walking to also catch IOBuiltin, but usb is set */ }
        }
        if current != 0 { IOObjectRelease(current) }

        return (usb, builtin)
    }

    private static func boolProperty(_ entry: io_registry_entry_t, _ key: String) -> Bool {
        guard let cf = IORegistryEntryCreateCFProperty(entry, key as CFString,
                                                       kCFAllocatorDefault, 0)?
            .takeRetainedValue() else { return false }
        if let n = cf as? NSNumber { return n.boolValue }
        return false
    }

    private static func className(_ entry: io_registry_entry_t) -> String? {
        var name = [CChar](repeating: 0, count: 128)
        guard IOObjectGetClass(entry, &name) == KERN_SUCCESS else { return nil }
        return String(cString: name)
    }
}
