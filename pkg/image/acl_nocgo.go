//go:build darwin && !cgo

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

package image

import (
	"errors"
	"fmt"
	"os"
)

// hasACL without cgo cannot read an ACL (see acl_darwin.go), so it reports
// unsupported and the local blob path is not used.
func hasACL(f *os.File) (bool, error) {
	return false, fmt.Errorf("read ACL of %s: %w", f.Name(), errors.ErrUnsupported)
}
