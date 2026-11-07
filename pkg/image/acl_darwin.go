//go:build darwin && cgo

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

/*
#include <errno.h>
#include <sys/acl.h>

// k3sm_fd_has_acl returns 1 when fd carries an extended ACL, 0 when it has
// none, and -1 with errno set on any other failure.
static int k3sm_fd_has_acl(int fd) {
	acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		return errno == ENOENT ? 0 : -1;
	}
	acl_free(acl);
	return 1;
}
*/
import "C"

import (
	"os"
)

// hasACL reports whether the open file f carries an ACL.
//
// It uses cgo for the public libSystem ACL API (acl_get_fd_np(3)): darwin
// keeps the ACL in the com.apple.system.Security xattr, but listxattr hides
// it and getxattr on it is refused (EPERM) to callers, so there is no x/sys
// path that can answer. acl_get_fd_np fails with ENOENT when there is no ACL.
func hasACL(f *os.File) (bool, error) {
	conn, err := f.SyscallConn()
	if err != nil {
		return false, err
	}
	var rc C.int
	var cerr error
	if err := conn.Control(func(fd uintptr) {
		rc, cerr = C.k3sm_fd_has_acl(C.int(fd))
	}); err != nil {
		return false, err
	}
	switch rc {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, &os.PathError{Op: "acl_get_fd_np", Path: f.Name(), Err: cerr}
	}
}
