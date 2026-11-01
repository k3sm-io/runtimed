#!/usr/bin/env bash
# The path shim temp-dir test must run, not skip, on a host that can run it.
#
# TestPathShimBuildLeavesNoTempDirs (pkg/runtime/pathshim_tmpdir_test.go) skips
# when the toolchain cannot emit an x86_64 slice, so the unit tier stays green on
# a host without one. go test without -v prints no SKIP line, so a toolchain that
# loses its x86_64 slice would turn the test into a silent pass. This stage runs
# the test alone with -v and goes RED unless it reports PASS.
#
# It applies only where the test can run: Apple silicon hardware (hw.optional.arm64,
# which stays 1 under a Rosetta-translated shell, unlike uname -m) with an Xcode or
# Command Line Tools clang that xcrun can find. Anywhere else it says so and exits 0.
#
# RED when: the test reports SKIP; it fails; it does not run at all (renamed or
# removed, so -run matches nothing).
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

test_name=TestPathShimBuildLeavesNoTempDirs
pkg=./pkg/runtime/

if [ "$(uname -s)" != Darwin ] || [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" != 1 ]; then
	echo "    $test_name: not an Apple silicon Mac, not required to run here"
	exit 0
fi
if ! xcrun --find clang >/dev/null 2>&1; then
	echo "    $test_name: xcrun finds no clang, not required to run here"
	exit 0
fi

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
rc=0
CGO_ENABLED=1 go test -race -count=1 -v -run "^${test_name}\$" "$pkg" > "$log" 2>&1 || rc=$?
if grep -q -- "--- SKIP: ${test_name}" "$log"; then
	cat "$log" >&2
	echo "FAIL: [runtimed] $test_name skipped on an Apple silicon Mac where xcrun finds clang;" \
		"the toolchain clang on PATH cannot build the universal path shim (see the SKIP reason above)" >&2
	exit 1
fi
if [ "$rc" -ne 0 ] || ! grep -q -- "--- PASS: ${test_name}" "$log"; then
	cat "$log" >&2
	echo "FAIL: [runtimed] $test_name did not pass (exit $rc)" >&2
	exit 1
fi
echo "    $test_name: PASS"
