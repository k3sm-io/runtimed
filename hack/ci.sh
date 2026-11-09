#!/usr/bin/env bash
# runtimed local CI — the docs/GO-STANDARDS.md commit gate in one command.
# The standard CI / pre-commit gate for this repo. Run from anywhere.
#
#   hack/ci.sh [--tier fast|full] [--edited <file>]
#              [--packages <file> [--base <sha>]] [--dry-run]
#
# --tier picks how the test stage applies hack/quarantine.txt: full (the default)
# reds on every failing test; fast excuses a listed flake outside the packages the
# change edits. --edited names a file with one edited import path per line.
#
# With no mode flag the gate is the full gate, unchanged. One explicit mode narrows
# only the go vet and go test package sets; every other stage still runs:
#   --packages <file>  read a k3sm-affected/v1 package list (the format the affected-set
#                      selector writes; its grammar is restated in hack/lib/affected-mode.sh).
#                      A missing, unreadable, malformed or unknown-version file, or an
#                      @full line for runtimed, runs the full gate. A list holding no runtimed
#                      package is red when the diff against --base (default: the merge
#                      base with origin/main) holds a .go file, runs the full gate when it
#                      holds any other non-doc file (the gate cannot map it to a package)
#                      or the base does not resolve, and skips vet and test when only doc
#                      files (*.md, docs/, LICENSE, NOTICE, DCO) changed.
# --dry-run resolves the mode, prints the plan (mode, reason, vet and test sets) and
# exits before any stage runs: 0 for a plan, 1 for a red verdict.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

usage() {
	echo "usage: hack/ci.sh [--tier fast|full] [--edited <file>] [--packages <file> [--base <sha>]] [--dry-run]" >&2
	exit 2
}
test_tier=full
edited_file=""
pkg_file="" pkg_file_set=0 diff_base="" dry_run=0
while [ $# -gt 0 ]; do
	case "$1" in
		--tier) [ $# -ge 2 ] || usage; test_tier="$2"; shift 2 ;;
		--edited) [ $# -ge 2 ] || usage; edited_file="$2"; shift 2 ;;
		--packages) [ $# -ge 2 ] || usage; pkg_file="$2"; pkg_file_set=1; shift 2 ;;
		--base) [ $# -ge 2 ] && [ -n "$2" ] || usage; diff_base="$2"; shift 2 ;;
		--dry-run) dry_run=1; shift ;;
		*) usage ;;
	esac
done
case "$test_tier" in fast|full) ;; *) echo "hack/ci.sh: --tier must be fast or full" >&2; exit 2 ;; esac
if [ -n "$diff_base" ] && [ "$pkg_file_set" = 0 ]; then
	echo "hack/ci.sh: --base goes with --packages" >&2; exit 2
fi
edited_pkgs=()
if [ -n "$edited_file" ]; then
	[ -r "$edited_file" ] || { echo "hack/ci.sh: --edited $edited_file is not readable" >&2; exit 2; }
	while IFS= read -r p; do
		case "$p" in ''|'#'*) continue ;; esac
		edited_pkgs+=("$p")
	done < "$edited_file"
fi

CGO=1   # runtimed needs cgo (darwin syscall shims: libsandbox, memorystatus, clonefile)
STATICCHECK_VERSION=2026.2.2   # keep equal to the install pin in docs/GO-STANDARDS.md §Commit gates
GOVULNCHECK_VERSION=v1.9.0   # the govulncheck the gate requires; keep equal across the k3sm repos and k3sm/hack/etcd-wrapper.sh

ci_tmp="$(mktemp -d)"
# Record this run in the gitignored .ci/last.json (read by the workspace hack/ci-last.sh), best effort,
# never changing the exit status. A stage is the text of the last `echo "==> ..."` printed;
# on a red run that stage is the one that failed. ci_cleanup is the cleanup the EXIT
# handler runs first; a stage that owns a temp dir sets it instead of calling trap.
ci_root=$PWD
ci_cleanup=""
ci_last_stage=""
ci_note_stage() {
	case ${1:-} in
	"==> "*)
		ci_last_stage=${1#"==> "}
		ci_last_stage=${ci_last_stage#\[*\] } ;;
	esac
}
# echo is wrapped (not a DEBUG trap) so PIPESTATUS survives for the stages that read it.
echo() { ci_note_stage "${1:-}"; builtin echo "$@"; }
ci_json_str() {
	local s
	s=$(printf '%s' "$1" | tr -d '[:cntrl:]')
	s=${s//\\/\\\\}
	printf '%s' "${s//\"/\\\"}"
}
ci_record_last() {
	local rc=$1 result=green failed="" sha at tmpf
	# Record only where .ci/ is gitignored: a fixture tree that runs this script (hack/verify-affected-modes.sh) must stay clean.
	git -C "$ci_root" check-ignore -q .ci/last.json 2>/dev/null || return 0
	if [ "$rc" != 0 ]; then
		result=red
		[ -z "$ci_last_stage" ] || failed="\"$(ci_json_str "$ci_last_stage")\""
	elif [ "${dry_run:-0}" = 1 ]; then
		result=skipped
	fi
	sha=$(git -C "$ci_root" rev-parse HEAD 2>/dev/null) || sha=""
	at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	mkdir -p "$ci_root/.ci" && tmpf=$(mktemp "$ci_root/.ci/last.XXXXXX") || return 0
	printf '{"repo":"%s","sha":"%s","result":"%s","at":"%s","failed":[%s]}\n' \
		"$(ci_json_str "$(basename "$ci_root")")" "$sha" "$result" "$at" "$failed" >"$tmpf"
	mv -f "$tmpf" "$ci_root/.ci/last.json" || rm -f "$tmpf"
}
ci_done=0
ci_on_exit() {
	local rc=$1
	if [ "$rc" = 0 ] && [ "$ci_done" != 1 ]; then
		rc=1
		echo "ci: stopped before the end of the script with status 0 (a set -u abort under bash 3.2?); treating it as red" >&2
		[ -n "$ci_last_stage" ] || ci_last_stage=unknown
	fi
	if [ -n "$ci_cleanup" ]; then eval "$ci_cleanup" || true; fi
	ci_record_last "$rc" || true
	exit "$rc"
}
trap 'ci_on_exit $?' EXIT
# shellcheck disable=SC2016 # the EXIT handler evals this string
ci_cleanup='rm -rf "$ci_tmp"'

# The --packages mode lives in hack/lib/affected-mode.sh, which defines read_packages
# and resolve_gate_mode and carries the k3sm-affected/v1 grammar; these two are the
# variables that make it this repository's.
gate_repo=runtimed
gate_module=k3sm.io/runtimed
. hack/lib/affected-mode.sh
resolve_gate_mode

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
golist_err="$ci_tmp/golist.err"
if ! go_pkgs="$(CGO_ENABLED=$CGO go list ./... 2>"$golist_err")"; then
	echo "FAIL: [runtimed] go list ./... failed — cannot enumerate packages; refusing to skip vet/build/test:" >&2
	cat "$golist_err" >&2
	exit 1
fi

if [ -n "$go_pkgs" ]; then
	if [ ${#vet_set[@]} -gt 0 ]; then
		echo "==> [runtimed] go vet";   CGO_ENABLED=$CGO go vet "${vet_set[@]}"
	else
		echo "==> [runtimed] go vet: skipped (no affected package)"
	fi
	echo "==> [runtimed] go build"; CGO_ENABLED=$CGO go build ./...
	# Every test runs under the race detector, as a go test -json stream piped
	# through hack/lib/testresults.go, which validates hack/quarantine.txt and applies
	# it for the tier. It echoes the output a plain go test prints and ends with the
	# failing tests. Its exit status says whether go test itself should have failed
	# (0: no failure, 3: only registry-excused failures), so the two statuses are
	# checked against each other: neither can turn the other green.
	if [ ${#test_set[@]} -gt 0 ]; then
		echo "==> [runtimed] go test -race (quarantine tier: $test_tier)"
		CGO_ENABLED=$CGO go build -o "$ci_tmp/testresults" hack/lib/testresults.go
		set +e
		CGO_ENABLED=$CGO go test -race -count=1 -json "${test_set[@]}" 2>"$ci_tmp/gotest.err" \
			| "$ci_tmp/testresults" -registry hack/quarantine.txt -tier "$test_tier" ${edited_pkgs[@]+"${edited_pkgs[@]}"}
		st=("${PIPESTATUS[@]}")
		set -e
		go_rc="${st[0]}" tr_rc="${st[1]}"
		if [ -s "$ci_tmp/gotest.err" ]; then
			echo "==> [runtimed] go test stderr:" >&2
			cat "$ci_tmp/gotest.err" >&2
		fi
		case "$go_rc:$tr_rc" in
			0:0) ;;
			1:3) echo "==> [runtimed] go test failed only on quarantined tests (see QUARANTINED above)" ;;
			*:1) echo "==> [runtimed] test stage RED (go test exit $go_rc); the RED lines above say why" >&2; exit 1 ;;
			*:0) echo "FAIL: [runtimed] go test exited $go_rc but its stream holds no failure; read the stderr above" >&2; exit 1 ;;
			*) echo "FAIL: [runtimed] go test exit $go_rc and testresults exit $tr_rc disagree" >&2; exit 1 ;;
		esac
	else
		echo "==> [runtimed] go test: skipped (no affected package)"
	fi

	# The race witness: a planted race that go test -race must catch. If the
	# toolchain's race detector is not live, this goes red instead of the gate
	# passing races silently.
	echo "==> [runtimed] race witness"
	if CGO_ENABLED=$CGO go test -race -count=1 ./hack/testdata/racewitness > "$ci_tmp/witness.log" 2>&1; then
		echo "FAIL: [runtimed] the planted race in hack/testdata/racewitness passed; go test -race does not detect races" >&2
		exit 1
	fi
	if ! grep -q 'WARNING: DATA RACE' "$ci_tmp/witness.log"; then
		echo "FAIL: [runtimed] the race witness failed without a race report:" >&2
		cat "$ci_tmp/witness.log" >&2
		exit 1
	fi

	# The path shim build tests skip without an x86_64-capable clang, and a skip
	# is invisible in the run above; on a host that can run them, they must pass.
	echo "==> [runtimed] path shim build tests ran"
	hack/verify-pathshim-not-skipped.sh

	# Wall-clock waits and fixed ports in tests, outside hack/test-sleeps.allow.
	echo "==> [runtimed] test-sleep lint"
	hack/verify-test-sleeps.sh --self-test
	hack/verify-test-sleeps.sh

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
	# The candidate lookup lives in hack/staticcheck-pick.sh so a test can pin its order.
	sc=""
	# shellcheck source=hack/staticcheck-pick.sh
	. hack/staticcheck-pick.sh
	staticcheck_pick || exit 1
	echo "==> [runtimed] staticcheck ${STATICCHECK_VERSION} (non-test)"; CGO_ENABLED=$CGO "$sc" -tests=false ./...
	# The guest init is linux-only, so the darwin run above never analyses its
	# linux files: a helper only the linux spawn calls reads as unused there and
	# nowhere else. Check the package under GOOS=linux with the same pinned binary.
	# Only this package: the rest of the tree is darwin code, unused on linux.
	if [ -d cmd/k3sm-guest-init ]; then
		echo "==> [runtimed] staticcheck ${STATICCHECK_VERSION} (guest-init, GOOS=linux, non-test)"; GOOS=linux GOARCH=arm64 CGO_ENABLED=0 "$sc" -tests=false ./cmd/k3sm-guest-init
	fi
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
ci_done=1
