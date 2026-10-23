# containerhost spike

A throwaway spike that boots one Linux container VM on the open-source Containerization Swift
package. It is kept for reference and for the gate that still exercises it. It is not shipped and
nothing in `runtimed` imports it.

- `Package.swift` pins `apple/containerization` at an exact tag; `Package.resolved` is committed.
- `Sources/cvmspike/main.swift` — `mkext4` builds an ext4 root from a materialized OCI tree with the
  package's public `EXT4.Formatter`; `boot` boots the guest from a kernel path, an image-store dir
  (for the `vminit` image), and that ext4 root, runs a command, execs `cat /proc/1/comm`, prints
  JSON timings; `--hold` keeps the guest up and makes SIGTERM a graceful stop.
- `cvmspike.entitlements` — exactly `com.apple.security.virtualization`, ad-hoc signed.
- `kernel/` — a recipe derived from `guest-kernel/build.sh`
  (`build-framework-config.sh`) that takes the package's published `config-arm64` to its
  `olddefconfig` fixed point for k3sm's pinned kernel source. `kernel.config` is that fixed point;
  `config-arm64.upstream` is the package's file as published. No kernel binary is downloaded.

Run the gate: the acceptance script for this spike under `hack/acceptance/`. Build the toolchain-only way: `DEVELOPER_DIR=/Library/Developer/CommandLineTools swift build -c release`.
