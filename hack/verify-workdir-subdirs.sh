#!/usr/bin/env bash
# k3sm work-dir deny-set completeness gate. Wraps hack/verify-workdir-subdirs
# (a go/parser-based scan): every exported *Subdir const declared in
# pkg/image, pkg/guestartifacts and pkg/sandbox must be referenced by
# pkg/runtime/workdirdeny_test.go, which is the test that actually pins those
# names into the daemon's deny-set. Run from a repo root:
#   hack/verify-workdir-subdirs.sh              # check the real tree
#   hack/verify-workdir-subdirs.sh --self-test   # prove the check against its own fixtures
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

case "${1:-}" in
--self-test)
	exec go run ./hack/verify-workdir-subdirs --self-test
	;;
*)
	exec go run ./hack/verify-workdir-subdirs "$@"
	;;
esac
