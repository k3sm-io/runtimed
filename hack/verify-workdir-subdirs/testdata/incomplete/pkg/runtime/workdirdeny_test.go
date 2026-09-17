package runtime

import (
	"fake.example/pkg/guestartifacts"
	"fake.example/pkg/image"
	"fake.example/pkg/sandbox"
)

// everyDaemonPrivateSubdir stands in for the real test's maintained list.
//
// StraySubdir is deliberately left out of this list — it is mentioned only
// in this comment, never as code — so this fixture must come back RED naming
// it.
var everyDaemonPrivateSubdir = []string{
	image.IndexSubdir,
	image.OperatorSubdir,
	guestartifacts.GuestArtifactsSubdir,
	sandbox.ServerSubdir,
	sandbox.VMReapSubdir,
}
