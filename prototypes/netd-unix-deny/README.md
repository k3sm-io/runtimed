# Prototype: Seatbelt AF_UNIX helper-socket deny

Integration-tier proof of the runtimed **AF_UNIX barrier** (the `k3sm-netd-helper`
change, deliverable #1): a pod confined by a generated SBPL profile **cannot
`connect()`** to a denied AF_UNIX socket path — the explicit
`(deny network-outbound (remote unix-socket (literal "…")))` that
`sandbox.Generate` emits for each `SandboxProfile.denied_unix_socket_paths`.

## Why it exists

k3sm is going user-space: `runtimed` runs as the unprivileged `_k3sm` daemon and
**pods run at the same `_k3sm` uid** (no per-pod uid isolation — the documented
residual limitation; untrusted tenancy → the `vm` RuntimeClass). The only root
component is a separate `k3sm-netd` networking helper reached over a unix socket.

Because a pod shares the `_k3sm` uid with the legitimate runtime client,
`LOCAL_PEERCRED` on the helper socket **cannot tell them apart** — so it is not a
barrier. The Seatbelt **default-deny already blocks** the `connect()`, and the
generator adds an **explicit** per-path deny on top of it as the load-bearing,
future-proof barrier (it survives even if a later profile broadens egress). The
matching **unit** test (`pkg/sandbox: TestGenerateDeniedUnixSockets`) asserts the
SBPL text; this prototype is the **live** proof, kept out of unit tests because
the standards forbid real sandboxing/privilege there.

## Run it (macOS 26, arm64)

```sh
cd runtimed
go run prototypes/netd-unix-deny/main.go
```

It (1) opens a live AF_UNIX listener, (2) builds a tiny C connecter with `clang`,
(3) generates the SBPL with the socket denied, (4) runs the connecter **without**
a sandbox (control → `CONNECT-OK`, proving the socket is connectable) and then
**under** `sandbox-exec -f` the generated profile (→ `CONNECT-DENIED errno=1
Operation not permitted`). Note the pod is granted read/write to the socket
file's *directory* yet still cannot `connect()` — the **network** deny, not a file
deny, is what stops it.

> `sandbox-exec` is deprecated (still functional on 26.x); production applies the
> same SBPL in-process via the `libsandbox` `sandbox_compile/apply` exec-shim. See
> the sibling `seatbelt-hostpath/` prototype and DESIGN §5a.

The file carries `//go:build ignore`, so it is excluded from `go build ./...` /
`go test ./...` and only runs via `go run`.
