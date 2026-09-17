//go:build darwin

package sandbox

// VMReapSubdir stands in for a real pkg/sandbox *Subdir const declared
// behind a //go:build constraint — the shape a raw, non-build-tag-aware
// parse must still find.
const VMReapSubdir = "vmreap"
