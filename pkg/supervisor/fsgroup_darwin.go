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

package supervisor

import "golang.org/x/sys/unix"

// fsGroupCanOpenLinks reports whether a symlink can be opened as itself, so
// that the walk can set a link's group through a descriptor.
const fsGroupCanOpenLinks = true

// fsGroupLinkFlags opens a symlink itself (O_SYMLINK), not what it names. If
// the name has become something else, that is what is opened, and the walk
// sees it is no longer a link and stops.
const fsGroupLinkFlags = unix.O_RDONLY | unix.O_SYMLINK | unix.O_NONBLOCK | unix.O_CLOEXEC
