# runtimed — k3sm native macOS runtime

@.claude/rules/native-builds.md

Use the `yurei build` queue via the runtime's executable absolute `YUREI_BIN`; verify native pod placement.
Preserve BypassGuard and every real human gate; this policy never widens credential, money, release or irreversible authority.

All build and test examples below run through the approved native Darwin pod route; older host exceptions are superseded.

Module **`k3sm.io/runtimed`** (≈ containerd). The native-Darwin runtime daemon: turns Pods into
isolated **native processes** — `pkg/sandbox` (Seatbelt/SBPL backends), a supervisor
(posix_spawn/kqueue, userspace memory/CPU limits), image (OCI → APFS `clonefile`), exposing a gRPC
runtime API defined in `k3sm.io/apis`.

> Roadmap & current phase: `docs/PHASES.md`.

## Build / test (**cgo** — darwin syscall shims, `CGO_ENABLED=1`)
```sh
gofmt -l .
go vet ./...
CGO_ENABLED=1 go build ./...
CGO_ENABLED=1 go test ./...
go mod tidy
```

## Notes
- cgo / private SPI (`libsandbox` Seatbelt, `memorystatus`, `clonefile`) is isolated behind
  `*_darwin.go` + a clean Go interface; prefer `golang.org/x/sys/unix` where a binding exists.
- Shared types/protos go in `../apis` (not here).
- Validated prototype: `prototypes/seatbelt-hostpath/` (default-deny Seatbelt at host paths, no chroot).

## Containers only, and no CI on GitHub

- **Containers only.** Nothing is installed on the host Mac, for supply-chain safety: no `brew`, no global
  `go install`/`cargo install`/`pip install`/`npm -g` of a tool, no `curl | sh`, no `sudo` installs. Toolchains
  and services run in k3sm pods; a tool the gate needs runs in a pod image pinned to an exact version and
  checksum. When a gate names a missing tool, it gives the pinned command to run in the pod, not on the host.
- **No CI on GitHub: no GitHub Actions workflows, ever, in any project, and Actions stays disabled; all gates
  run locally in k3sm pods**, through Yureisha CI (the `yureisha/ci` commit status) or this repo's own gate
  script, `hack/ci.sh`. No file may exist under `.github/workflows/`, commented out or not. `hack/ci.sh`
  checks the DCO sign-off on every commit a branch adds.

## Standards
@docs/GO-STANDARDS.md
