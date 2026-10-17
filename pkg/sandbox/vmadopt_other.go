//go:build !darwin

/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sandbox

import (
	"context"
	"errors"
)

// errAdoptUnsupported reports that this build lane cannot adopt a vm host
// helper: the helper and its guest are darwin-only, so there is never one to
// adopt, and every adoption probe refuses.
var errAdoptUnsupported = errors.New("vm host helper adoption is darwin-only")

func watchAdoptedHelperExit(context.Context, int, func() bool) (<-chan struct{}, error) {
	return nil, errAdoptUnsupported
}

func bootSessionID() (string, error) { return "", errAdoptUnsupported }

func dialVMHostVersion(context.Context, string) (vmHostAnswer, error) {
	return vmHostAnswer{}, errAdoptUnsupported
}
