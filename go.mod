module k3sm.io/runtimed

go 1.25.8

require (
	github.com/google/go-containerregistry v0.21.6
	github.com/klauspost/compress v1.18.6
	golang.org/x/sys v0.44.0
	golang.org/x/text v0.34.0
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260618152121-87f3d3e198d3
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
	k3sm.io/apis v0.0.0-00010101000000-000000000000
)

require (
	github.com/docker/cli v29.4.3+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.3 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	gotest.tools/v3 v3.5.2 // indirect
)

// k3sm.io/apis is a sibling workspace module (go.work); pin a replace to the
// local checkout so this module also builds and `go mod tidy`s standalone in CI.
replace k3sm.io/apis => ../apis
