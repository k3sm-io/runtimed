package runtime

import (
	"fake.example/pkg/guestartifacts"
	"fake.example/pkg/image"
	"fake.example/pkg/sandbox"
)

// everyDaemonPrivateSubdir stands in for the real test's maintained list —
// this fixture asserts that every *Subdir const declared under this
// tree's pkg/image, pkg/guestartifacts and pkg/sandbox is referenced
// somewhere below.
var everyDaemonPrivateSubdir = []string{
	image.IndexSubdir,
	image.OperatorSubdir,
	guestartifacts.GuestArtifactsSubdir,
	sandbox.ServerSubdir,
	sandbox.VMReapSubdir,
}
