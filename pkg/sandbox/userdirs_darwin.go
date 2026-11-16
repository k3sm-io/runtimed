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

package sandbox

/*
#include <unistd.h>
#include <stdlib.h>

static size_t k3sm_confstr(int name, char *buf, size_t len) { return confstr(name, buf, len); }
static int k3sm_cs_temp(void) { return _CS_DARWIN_USER_TEMP_DIR; }
static int k3sm_cs_cache(void) { return _CS_DARWIN_USER_CACHE_DIR; }
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

// DarwinUserDirs returns this process's own Darwin user temp and cache
// directories (confstr _CS_DARWIN_USER_TEMP_DIR and _CS_DARWIN_USER_CACHE_DIR),
// cleaned of their trailing slash. Pods run at the daemon's uid, so these are
// the trees a pod's confstr would name.
//
// It refuses to answer while DIRHELPER_USER_DIR_SUFFIX is set in this process:
// the answer would then be a suffixed subdirectory, and links made beside it
// would sit one level too deep for any pod to find. It also refuses an answer
// that is not an absolute directory.
func DarwinUserDirs() (temp, cache string, err error) {
	if v, ok := os.LookupEnv(UserDirSuffixEnv); ok {
		return "", "", fmt.Errorf("%s=%q is set in this process; refusing to derive the per-pod user dirs from a suffixed answer", UserDirSuffixEnv, v)
	}
	temp, err = confstrDir(C.k3sm_cs_temp())
	if err != nil {
		return "", "", fmt.Errorf("darwin user temp dir: %w", err)
	}
	cache, err = confstrDir(C.k3sm_cs_cache())
	if err != nil {
		return "", "", fmt.Errorf("darwin user cache dir: %w", err)
	}
	return temp, cache, nil
}

func confstrDir(name C.int) (string, error) {
	const size = 1024
	buf := (*C.char)(C.malloc(size))
	defer C.free(unsafe.Pointer(buf))
	n := C.k3sm_confstr(name, buf, size)
	if n == 0 || n > size {
		return "", fmt.Errorf("confstr answered no path (len %d)", n)
	}
	dir := filepath.Clean(C.GoString(buf))
	if !filepath.IsAbs(dir) || dir == "/" {
		return "", fmt.Errorf("confstr answered %q, not an absolute directory", dir)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	}
	return dir, nil
}
