# runtimed — k3sm native macOS runtime

Module **`k3sm.io/runtimed`** (≈ containerd). The native-Darwin runtime daemon: turns Pods into
isolated **native processes** — `pkg/sandbox` (Seatbelt/SBPL backends), a supervisor
(posix_spawn/kqueue, userspace memory/CPU limits), image (OCI → APFS `clonefile`), exposing a gRPC
runtime API defined in `k3sm.io/apis`.

> Roadmap & current phase: `docs/PHASES.md` (workspace matrix: `../ROADMAP.md`).

## Build / test (**cgo** — darwin syscall shims)
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

## Standards
@docs/GO-STANDARDS.md
