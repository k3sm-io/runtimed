// B267 spike (see hack/spikes/containerhost/README.md). Subcommands:
//   mkext4 <tree-dir> <out.img> <size-bytes>      build an ext4 root from a materialized tree
//   boot   <kernel-Image> <store-dir> <rootfs.img> [--memory MiB] [--hold SECONDS] [--cmd CMD]
//          boot the VM, run CMD (default: uname -sm), then exec `cat /proc/1/comm`, print JSON
//          timings; with --hold, keep the container up (SIGTERM → stop → exit 0) for the
//          lifetime and memory probes.
import Containerization
import ContainerizationArchive
import ContainerizationEXT4
import ContainerizationError
import ContainerizationOCI
import ContainerizationOS
import Foundation
import Logging
import SystemPackage

final class Collect: Writer, @unchecked Sendable {
    private let lock = NSLock()
    private var buf = Data()
    func write(_ data: Data) throws { lock.lock(); buf.append(data); lock.unlock() }
    func close() throws {}
    var text: String { lock.lock(); defer { lock.unlock() }; return String(decoding: buf, as: UTF8.self) }
}

func now() -> Double { Date().timeIntervalSince1970 * 1000 }

func mkext4(tree: URL, out: URL, size: UInt64) throws -> (Int, Int, Int) {
    try? FileManager.default.removeItem(at: out)
    let fmt = try EXT4.Formatter(FilePath(out.path), minDiskSize: size)
    let fm = FileManager.default
    let base = tree.standardizedFileURL.path
    guard let en = fm.enumerator(at: tree, includingPropertiesForKeys: nil, options: []) else {
        throw ContainerizationError(.invalidArgument, message: "cannot enumerate \(base)")
    }
    var dirs = 0, files = 0, links = 0
    for case let url as URL in en {
        let full = url.standardizedFileURL.path
        var rel = String(full.dropFirst(base.count))
        if rel.isEmpty { continue }
        if !rel.hasPrefix("/") { rel = "/" + rel }
        let attrs = try fm.attributesOfItem(atPath: full)  // lstat semantics
        let type = attrs[.type] as? FileAttributeType
        let perm = UInt16((attrs[.posixPermissions] as? Int) ?? 0o644)
        switch type {
        case .typeDirectory:
            try fmt.create(path: FilePath(rel), mode: EXT4.Inode.Mode(.S_IFDIR, perm), uid: 0, gid: 0)
            dirs += 1
        case .typeSymbolicLink:
            let dest = try fm.destinationOfSymbolicLink(atPath: full)
            try fmt.create(path: FilePath(rel), link: FilePath(dest), mode: EXT4.Inode.Mode(.S_IFLNK, 0o777), uid: 0, gid: 0)
            links += 1
        case .typeRegular:
            guard let s = InputStream(url: url) else { continue }
            s.open()  // an unopened InputStream reads zero bytes: every file would land empty
            defer { s.close() }
            try fmt.create(path: FilePath(rel), mode: EXT4.Inode.Mode(.S_IFREG, perm), buf: s, uid: 0, gid: 0)
            files += 1
        default:
            continue  // devices, sockets, fifos: not materialized in an OCI tree
        }
    }
    try fmt.close()
    return (dirs, files, links)
}

func boot(kernelPath: String, storePath: String, rootfsPath: String, memoryMiB: UInt64, hold: Int, cmd: String) async throws {
    let store = try ImageStore(path: URL(fileURLWithPath: storePath))
    let t0 = now()
    let initfsURL = URL(fileURLWithPath: storePath).appendingPathComponent("initfs.ext4")
    let initfs: Containerization.Mount
    if FileManager.default.fileExists(atPath: initfsURL.path) {
        // Reuse the initfs a previous run unpacked (the framework's initBlock refuses an
        // existing path); read-only exactly as initBlock returns it.
        initfs = Containerization.Mount.block(format: "ext4", source: initfsURL.path, destination: "/", options: ["ro"])
    } else {
        let initImage = try await store.getInitImage(reference: "ghcr.io/apple/containerization/vminit:0.45.0")
        initfs = try await initImage.initBlock(at: initfsURL, for: .linuxArm)
    }
    let t1 = now()
    let kernel = Kernel(path: URL(fileURLWithPath: kernelPath), platform: .linuxArm)
    var log = Logger(label: "cvmspike"); log.logLevel = ProcessInfo.processInfo.environment["CVMSPIKE_DEBUG"] != nil ? .debug : .error
    let vmm = VZVirtualMachineManager(kernel: kernel, initialFilesystem: initfs, logger: log)
    var cfg = LinuxContainer.Configuration()
    cfg.cpus = 2
    cfg.memoryInBytes = memoryMiB * 1024 * 1024
    // The bare Configuration() carries no mounts; the framework's own run tool attaches
    // proc/sys/dev/devpts/shm/cgroup2 by default, and a shell dies at exec without /dev.
    cfg.mounts = LinuxContainer.defaultMounts()
    if let bl = ProcessInfo.processInfo.environment["CVMSPIKE_BOOTLOG"] {
        cfg.bootLog = .file(path: URL(fileURLWithPath: bl), append: false)  // the guest serial console
    }
    cfg.process.environmentVariables = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
    let out = Collect()
    // The main process must outlive the exec below (an exec into an exited container is ESRCH),
    // so without --hold it lingers 3 s after the command; the JSON's cmd_exit is the command's.
    cfg.process.arguments = ["/bin/sh", "-c", "\(cmd); rc=$?; sleep \(hold > 0 ? hold : 3); exit $rc"]
    cfg.process.stdout = out
    cfg.process.stderr = out
    let c = try LinuxContainer("spike", rootfs: .block(format: "ext4", source: rootfsPath, destination: "/"), vmm: vmm, configuration: cfg, logger: log)
    let t2 = now()
    try await c.create()
    let t3 = now()
    try await c.start()
    let t4 = now()
    if hold > 0 { print("{\"event\":\"up\",\"start_ms\":\(Int(t4 - t3))}"); fflush(stdout) }

    // SIGTERM → graceful stop → exit 0 (criterion e).
    signal(SIGTERM, SIG_IGN)
    let src = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
    src.setEventHandler {
        let ts = now()
        Task {
            try? await c.stop()
            let dt = now() - ts
            print("{\"event\":\"sigterm\",\"stop_ms\":\(Int(dt))}")
            exit(0)
        }
    }
    src.resume()

    // criterion c/(PID 1): exec inside the running container.
    let comm = Collect()
    let p = try await c.exec("comm") { pc in
        pc.arguments = ["/bin/cat", "/proc/1/comm"]
        pc.stdout = comm
    }
    try await p.start()
    let ps = try await p.wait()
    let t5 = now()
    let st: ExitStatus
    if hold > 0 {
        st = try await c.wait()
    } else {
        st = try await c.wait()
    }
    try await c.stop()
    let t6 = now()
    let js: [String: Any] = [
        "initfs_ms": Int(t1 - t0), "create_ms": Int(t3 - t2), "start_ms": Int(t4 - t3),
        "exec_ms": Int(t5 - t4), "stop_ms": Int(t6 - t5),
        "cmd_output": out.text.trimmingCharacters(in: .whitespacesAndNewlines),
        "pid1_comm": comm.text.trimmingCharacters(in: .whitespacesAndNewlines),
        "exec_exit": Int(ps.exitCode), "cmd_exit": Int(st.exitCode),
    ]
    let data = try JSONSerialization.data(withJSONObject: js, options: [.sortedKeys])
    print(String(decoding: data, as: UTF8.self))
}

@main
struct Main {
    static func main() async throws {
        let a = CommandLine.arguments
        guard a.count >= 2 else { print("usage: cvmspike mkext4|boot ..."); exit(64) }
        switch a[1] {
        case "mkext4":
            guard a.count == 5, let size = UInt64(a[4]) else { print("usage: cvmspike mkext4 <tree> <out.img> <bytes>"); exit(64) }
            let t = now()
            let (d, f, l) = try mkext4(tree: URL(fileURLWithPath: a[2]), out: URL(fileURLWithPath: a[3]), size: size)
            print("{\"dirs\":\(d),\"files\":\(f),\"symlinks\":\(l),\"mkext4_ms\":\(Int(now() - t))}")
        case "boot":
            guard a.count >= 5 else { print("usage: cvmspike boot <kernel> <store> <rootfs.img> [--memory MiB] [--hold S] [--cmd CMD]"); exit(64) }
            var mem: UInt64 = 512, hold = 0, cmd = "uname -sm"
            var i = 5
            while i < a.count {
                switch a[i] {
                case "--memory": mem = UInt64(a[i + 1]) ?? 512; i += 2
                case "--hold": hold = Int(a[i + 1]) ?? 0; i += 2
                case "--cmd": cmd = a[i + 1]; i += 2
                default: i += 1
                }
            }
            try await boot(kernelPath: a[2], storePath: a[3], rootfsPath: a[4], memoryMiB: mem, hold: hold, cmd: cmd)
        default:
            print("unknown subcommand \(a[1])"); exit(64)
        }
    }
}
