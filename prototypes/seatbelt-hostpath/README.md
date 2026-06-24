# Prototype: Seatbelt host-path confinement (no chroot)

Validates the core k3sm runtime assumption ([DESIGN.md §5a](https://github.com/k3sm-io/k3sm/blob/main/docs/DESIGN.md)):
a native Mach-O process runs **at its real host path** under a **default-deny Seatbelt
profile** — so it sees `/System` and links frameworks + the dyld shared cache — while being
confined out of the rest of the filesystem. This replaces the v1 chroot design, which SIP
makes impossible.

## Result — macOS 26.5.1, arm64 (2026-06-24)
| test | expectation | result |
|---|---|---|
| `plutil -p SystemVersion.plist` (Foundation) under profile | runs, prints dict | ✅ rc=0 |
| `sw_vers` under profile | runs | ✅ rc=0 |
| read `/Users/operator` | denied | ✅ `Operation not permitted` |
| write inside pod dir | allowed | ✅ |
| write into `/Users` | denied | ✅ `Operation not permitted` |

Both a permissive base (`allow default` + deny `/Users`) and the tight default-deny
profile here pass identically.

## Key lesson
The profile **must** `(import "system.sb")`. A hand-rolled allow-list without it makes every
binary abort with **SIGABRT** during dyld init — the shared-cache mapping + mach bootstrap
need the baseline that `system.sb` (in `/System/Library/Sandbox/Profiles/`) grants.

## Run it
```sh
POD=$(mktemp -d)
sed "s#@@POD_ROOT@@#$POD#g" pod.sb > "$POD.sb"
sandbox-exec -f "$POD.sb" /usr/bin/sw_vers     # runs
sandbox-exec -f "$POD.sb" /bin/ls /Users       # Operation not permitted
sandbox-exec -f "$POD.sb" /usr/bin/touch "$POD/ok"   # allowed
```

> `sandbox-exec` is deprecated (still functional on 26.5.1). Production uses the same SBPL
> via the private `libsandbox` `sandbox_compile/apply` in-process — see DESIGN.md §5a (the
> swappable, OS-version-gated sandbox backend + CI symbol-canary).
