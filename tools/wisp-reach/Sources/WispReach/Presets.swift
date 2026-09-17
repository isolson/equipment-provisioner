import Foundation

/// A single IP alias to place on an interface.
struct AliasEntry {
    let ip: String
    let netmask: String   // dotted-quad, always 255.255.255.0 here
}

/// A named group of aliases (a vendor preset, or the union "Reach Everything").
struct Preset {
    let key: String       // stable id, must match the helper script's preset keys
    let title: String     // menu label
    let reaches: String    // human note of what it reaches
    let aliases: [AliasEntry]
}

/// The authoritative list is ALSO baked into the root helper (`helper/wisp-net`).
/// This copy is for the menu UI only — the helper never trusts IPs from the app.
/// Keep the two in sync; the core-4 subnets come from the network-provisioner
/// `DeviceLinkLocalIP` registry.
enum Presets {
    static let mask = "255.255.255.0"

    static let vendors: [Preset] = [
        Preset(key: "cambium-tachyon", title: "Cambium ePMP / Tachyon",
               reaches: "169.254.1.1",
               aliases: [AliasEntry(ip: "169.254.1.2", netmask: mask)]),
        Preset(key: "tarana", title: "Tarana",
               reaches: "169.254.100.1",
               aliases: [AliasEntry(ip: "169.254.100.2", netmask: mask)]),
        Preset(key: "ubiquiti", title: "Ubiquiti airMAX / Wave",
               reaches: "192.168.1.20 / .1",
               aliases: [AliasEntry(ip: "192.168.1.2", netmask: mask)]),
        Preset(key: "mikrotik", title: "MikroTik",
               reaches: "192.168.88.1",
               aliases: [AliasEntry(ip: "192.168.88.10", netmask: mask)]),
    ]

    /// The union of every vendor alias — the "Reach Everything" set.
    static let reachEverything: [AliasEntry] = vendors.flatMap { $0.aliases }

    /// Every alias IP, for status parsing / clear.
    static let allIPs: [String] = reachEverything.map { $0.ip }
}
