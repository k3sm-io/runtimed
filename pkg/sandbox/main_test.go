package sandbox

import "flag"

// update regenerates golden files when set (go test ./pkg/sandbox -update).
var update = flag.Bool("update", false, "update golden files")
