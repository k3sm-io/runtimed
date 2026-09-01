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

// Package guestartifacts composes the boot artifacts a k3sm vm-backend pod's
// micro-VM is started from.
//
// # Byte-determinism is the requirement
//
// Both guest artifacts — the kernel Image and the initramfs — are published by
// digest and pinned by a human. A pin is only worth the ability to re-derive
// it, so composing the initramfs must be a pure function of its input: the
// same init binary must always produce the same archive bytes, on any host, at
// any time, under any umask.
//
// That rules out shelling out to cpio(1). `find . | cpio -o -H newc` embeds the
// build host's clock in every mtime, the builder's uid/gid in every entry,
// inode numbers from the host filesystem, and an entry order that is whatever
// readdir returned — four independent sources of drift, each of which alone
// makes two archives of identical content differ. ComposeInitramfs writes the
// newc stream directly with every one of those pinned: mtime 0, uid/gid 0,
// sequential inodes, sorted names, and no block padding at the end.
//
// # Why newc, and why uncompressed
//
// newc (SVR4, magic "070701", no CRC) is the format the Linux initramfs
// unpacker reads. The archive is handed to the VM uncompressed: the guest
// kernel is built without any of the initrd decompressors it does not need,
// and the artifact is small enough that compressing it would trade a boot-time
// decompression for a saving nobody measures.
//
// # What is in the archive
//
// Exactly /init plus the directories the guest PID 1 mounts over. The init in
// cmd/k3sm-guest-init creates its own mount points with MkdirAll, so these
// entries are not strictly required for it to boot — they are here so that a
// failure to create one surfaces as an unpack-time fault with a name attached,
// rather than as a mount failing at a path that does not exist. The guest
// scratch root is taken from k3sm.io/runtimed/pkg/guestinit rather than
// respelled, so a change there cannot leave this package composing an
// initramfs the init does not fit.
package guestartifacts
