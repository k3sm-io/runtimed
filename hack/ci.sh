#!/usr/bin/env bash
# runtimed local CI — the docs/GO-STANDARDS.md commit gate in one command.
# The standard CI / pre-commit gate for this repo. Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

CGO=1   # runtimed needs cgo (darwin syscall shims: libsandbox, memorystatus, clonefile)
STATICCHECK_VERSION=2026.2.1   # keep equal to the install pin in docs/GO-STANDARDS.md §Commit gates
GOVULNCHECK_VERSION=v1.8.0   # the govulncheck the gate requires; keep equal across the k3sm repos and k3sm/hack/etcd-wrapper.sh

echo "==> [runtimed] gofmt"
fmt=$(gofmt -l .) || true
[ -z "$fmt" ] || { echo "gofmt -w needed:"; echo "$fmt"; exit 1; }

echo "==> [runtimed] license headers"
hack/verify-boilerplate.sh

# Enumerate the Go packages BEFORE deciding to skip anything. Exit 0 with empty
# output means "no Go packages yet" — the legitimate skip this guard was written
# for. A NON-ZERO exit (broken go.mod, unresolvable dependency, bad GOWORK, absent
# toolchain) is a HARD ERROR: the old `[ -n "$(go list ./... 2>/dev/null)" ]` could
# not tell the two apart, so it silently skipped vet/build/test and still reported
# green — a gate that cannot even enumerate its packages must go RED.
golist_err="$(mktemp)"
trap 'rm -f "$golist_err"' EXIT
if ! go_pkgs="$(CGO_ENABLED=$CGO go list ./... 2>"$golist_err")"; then
	echo "FAIL: [runtimed] go list ./... failed — cannot enumerate packages; refusing to skip vet/build/test:" >&2
	cat "$golist_err" >&2
	exit 1
fi

if [ -n "$go_pkgs" ]; then
	echo "==> [runtimed] go vet";   CGO_ENABLED=$CGO go vet ./...
	echo "==> [runtimed] go build"; CGO_ENABLED=$CGO go build ./...
	echo "==> [runtimed] go test";  CGO_ENABLED=$CGO go test ./...

	# The deny-set completeness verifier parses the packages above; it sits
	# inside the package guard so a tree with no packages skips it like the rest.
	echo "==> [runtimed] work-dir deny-set completeness"
	hack/verify-workdir-subdirs.sh
	hack/verify-workdir-subdirs.sh --self-test

	# The guest init (cmd/k3sm-guest-init) is PID 1 of a vm-pod's micro-VM and
	# is GOOS=linux only, so the darwin build above never compiles it. This
	# cross-lane is the only thing standing between an unrelated change and a
	# guest that no longer builds (the guest-init cross-build contract). CGO stays OFF: the
	# binary ships inside the pinned initramfs, which has no libc.
	if [ -d cmd/k3sm-guest-init ]; then
		echo "==> [runtimed] guest-init cross-build (linux/arm64 + linux/amd64, CGO off)"
		guestout="$(mktemp -d)"
		for arch in arm64 amd64; do
			GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -o "$guestout/k3sm-guest-init.$arch" ./cmd/k3sm-guest-init
		done
		GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go vet ./cmd/k3sm-guest-init
		rm -rf "$guestout"
	fi

	echo "==> [runtimed] execshim linux cross-build (off-platform stub)"; GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go vet ./cmd/k3sm-execshim

	# staticcheck, pinned to an exact version: a different release reports
	# different findings, so an unpinned tool would make the verdict depend on
	# the host. Bump it together with the Go toolchain and with
	# docs/GO-STANDARDS.md (keep in step with the other k3sm repos).
	# -tests=false: test code is out of scope until a separate sweep; the gate
	# covers non-test code only. Suppress a finding with a
	# `//lint:ignore <Check> <reason>` comment on the preceding line
	# (`//nolint` is golangci-lint's spelling and is inert here).
	# Runs after vet/build/test so a mismatched host tool never stops those.
	sc=""; sc_seen=""
	for c in "$(command -v staticcheck 2>/dev/null || true)" "$(go env GOPATH)/bin/staticcheck"; do
		[ -n "$c" ] && [ -x "$c" ] || continue
		v="$("$c" -version 2>/dev/null | awk '{print $2}')" || v=""
		sc_seen="$sc_seen
  $c reports '${v:-unknown}'"
		if [ "$v" = "$STATICCHECK_VERSION" ]; then sc="$c"; break; fi
	done
	if [ -z "$sc" ]; then
		if [ -z "$sc_seen" ]; then
			echo "==> [runtimed] staticcheck: not installed; the gate needs ${STATICCHECK_VERSION} (go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION})" >&2
		else
			echo "==> [runtimed] staticcheck: the gate needs ${STATICCHECK_VERSION}, found:${sc_seen}" >&2
			echo "    install it with: go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}" >&2
		fi
		exit 1
	fi
	echo "==> [runtimed] staticcheck ${STATICCHECK_VERSION} (non-test)"; CGO_ENABLED=$CGO "$sc" -tests=false ./...
else
	echo "==> [runtimed] (no Go packages yet — skipping vet/build/test)"
fi

echo "==> [runtimed] go mod tidy (no-diff)"
go mod tidy
if [ -n "$(git status --porcelain -- go.mod go.sum 2>/dev/null)" ]; then
	echo "go.mod/go.sum not tidy after 'go mod tidy':"; git --no-pager diff -- go.mod go.sum; exit 1
fi

# The dependency supply-chain check (hack/verify-deps.sh): the go environment
# cannot weaken verification, go mod verify, the hack/deps.lock module graph,
# the 14-day cooldown on new versions, the OSV malicious-package query, go.mod
# replace discipline, and exact pins on every remote go install / go run. It
# needs proxy.golang.org and api.osv.dev; there is no offline skip, because a
# network failure there is RED by design. It runs only in the real module: the
# k3sm repo's hack/acceptance/ci_guard_test.go runs this script in a throwaway
# module whose graph the lock could never describe.
if grep -qx "module k3sm.io/runtimed" go.mod 2>/dev/null; then
	echo "==> [runtimed] verify-deps (self-test)"
	hack/verify-deps.sh --self-test
	echo "==> [runtimed] verify-deps"
	hack/verify-deps.sh

	# govulncheck, pinned to an exact version like staticcheck: a different release
	# can report different findings. Each candidate (PATH first, then
	# $(go env GOPATH)/bin) is probed and the first reporting exactly the pin is
	# used. A missing or mismatched tool is RED, never a skip, and so is a finding
	# or a failure to reach the vulnerability database.
	gv=""; gv_seen=""
	for c in "$(command -v govulncheck 2>/dev/null || true)" "$(go env GOPATH)/bin/govulncheck"; do
		[ -n "$c" ] && [ -x "$c" ] || continue
		gv_ver="$("$c" -version 2>/dev/null | sed -n 's/^Scanner: govulncheck@//p' | head -1)" || gv_ver=""
		gv_seen="${gv_seen}    $c reports ${gv_ver:-no version}"$'\n'
		if [ "$gv_ver" = "$GOVULNCHECK_VERSION" ]; then gv="$c"; break; fi
	done
	if [ -z "$gv" ]; then
		if [ -z "$gv_seen" ]; then
			echo "==> [runtimed] govulncheck: not installed; the gate needs ${GOVULNCHECK_VERSION} (go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION})" >&2
		else
			echo "==> [runtimed] govulncheck: wrong version; the gate needs ${GOVULNCHECK_VERSION} (go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}). Found:" >&2
			printf '%s' "$gv_seen" >&2
		fi
		exit 1
	fi
	echo "==> [runtimed] govulncheck ${GOVULNCHECK_VERSION} ./..."
	GOWORK=off CGO_ENABLED=$CGO "$gv" ./...
fi

echo "OK: runtimed ci green"
