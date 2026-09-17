import Foundation

/// Thin wrapper around the root helper and `ifconfig` status parsing.
/// Never handles secrets and never passes IPs as arguments — the helper owns the
/// authoritative IP list; the app only names an interface.
enum Privileged {
    static let helperPath = "/usr/local/libexec/wisp-net"

    struct Result {
        let ok: Bool
        let output: String
    }

    /// `sudo -n /usr/local/libexec/wisp-net <action> <ifname> [preset]`
    /// `-n` = non-interactive: if the sudoers rule is missing it fails fast
    /// instead of hanging on a password prompt.
    @discardableResult
    static func run(action: String, ifname: String, preset: String? = nil) -> Result {
        guard ifnameIsValid(ifname) else {
            return Result(ok: false, output: "refused invalid ifname \(ifname)")
        }
        var args = ["-n", helperPath, action, ifname]
        if let preset = preset { args.append(preset) }
        return exec("/usr/bin/sudo", args)
    }

    static func apply(ifname: String, preset: String? = nil) -> Result {
        run(action: "apply", ifname: ifname, preset: preset)
    }

    static func clear(ifname: String) -> Result {
        run(action: "clear", ifname: ifname)
    }

    /// Which of our alias IPs are currently live on the interface.
    static func activeAliases(ifname: String) -> Set<String> {
        guard ifnameIsValid(ifname) else { return [] }
        let res = exec("/sbin/ifconfig", [ifname])
        guard res.ok else { return [] }
        var live = Set<String>()
        for ip in Presets.allIPs where res.output.contains("inet \(ip) ") {
            live.insert(ip)
        }
        return live
    }

    static func helperInstalled() -> Bool {
        FileManager.default.isExecutableFile(atPath: helperPath)
    }

    // MARK: - helpers

    static func ifnameIsValid(_ s: String) -> Bool {
        // en<digits>, defensively bounded.
        guard s.count >= 3, s.count <= 8, s.hasPrefix("en") else { return false }
        return s.dropFirst(2).allSatisfy { $0.isNumber }
    }

    private static func exec(_ path: String, _ args: [String]) -> Result {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        do {
            try proc.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            proc.waitUntilExit()
            let out = String(data: data, encoding: .utf8) ?? ""
            return Result(ok: proc.terminationStatus == 0, output: out)
        } catch {
            return Result(ok: false, output: "\(error)")
        }
    }
}
