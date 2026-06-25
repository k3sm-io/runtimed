#!/usr/bin/env bash
# runtimed local CI — the docs/GO-STANDARDS.md commit gate in one command.
# Exactly what a /orchestrate builder agent runs before checkpointing, and what the
# workspace hack/ci.sh invokes for this repo. Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

CGO=1   # runtimed needs cgo (darwin syscall shims: libsandbox, memorystatus, clonefile)

echo "==> [runtimed] gofmt"
fmt=$(gofmt -l .) || true
[ -z "$fmt" ] || { echo "gofmt -w needed:"; echo "$fmt"; exit 1; }

if [ -n "$(CGO_ENABLED=$CGO go list ./... 2>/dev/null)" ]; then
	echo "==> [runtimed] go vet";   CGO_ENABLED=$CGO go vet ./...
	echo "==> [runtimed] go build"; CGO_ENABLED=$CGO go build ./...
	echo "==> [runtimed] go test";  CGO_ENABLED=$CGO go test ./...
else
	echo "==> [runtimed] (no Go packages yet — skipping vet/build/test)"
fi

echo "==> [runtimed] go mod tidy (no-diff)"
go mod tidy
if [ -n "$(git status --porcelain -- go.mod go.sum 2>/dev/null)" ]; then
	echo "go.mod/go.sum not tidy after 'go mod tidy':"; git --no-pager diff -- go.mod go.sum; exit 1
fi

echo "OK: runtimed ci green"
