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

package guestinit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MaxPodFQDNBytes is the longest GuestSpec.pod_fqdn a guest accepts: the
// DNS-1123 subdomain limit.
const MaxPodFQDNBytes = 253

// maxDNSLabelBytes is the DNS-1123 label limit.
const maxDNSLabelBytes = 63

// checkPodFQDN validates GuestSpec.pod_fqdn against its contract: empty, or a
// DNS-1123 subdomain of at most MaxPodFQDNBytes bytes whose first label equals
// the hostname's first label. The guest derives no name, so a value outside
// the contract is a host bug, refused with ErrInvalidSpec rather than dropped.
func checkPodFQDN(hostname, fqdn string) error {
	if fqdn == "" {
		return nil
	}
	if len(fqdn) > MaxPodFQDNBytes {
		return fmt.Errorf("%w: pod_fqdn is %d bytes, the limit is %d",
			ErrInvalidSpec, len(fqdn), MaxPodFQDNBytes)
	}
	for i := 0; i < len(fqdn); i++ {
		c := fqdn[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' {
			continue
		}
		return fmt.Errorf("%w: pod_fqdn %q has byte 0x%02x at offset %d, want [a-z0-9.-]",
			ErrInvalidSpec, fqdn, c, i)
	}
	for _, label := range strings.Split(fqdn, ".") {
		switch {
		case label == "":
			return fmt.Errorf("%w: pod_fqdn %q has an empty label", ErrInvalidSpec, fqdn)
		case len(label) > maxDNSLabelBytes:
			return fmt.Errorf("%w: pod_fqdn %q has a %d-byte label, the limit is %d",
				ErrInvalidSpec, fqdn, len(label), maxDNSLabelBytes)
		case label[0] == '-' || label[len(label)-1] == '-':
			return fmt.Errorf("%w: pod_fqdn %q has a label starting or ending with '-'", ErrInvalidSpec, fqdn)
		}
	}
	short, _, _ := strings.Cut(fqdn, ".")
	host, _, _ := strings.Cut(hostname, ".")
	if short != host {
		return fmt.Errorf("%w: pod_fqdn %q does not start with the hostname's first label %q",
			ErrInvalidSpec, fqdn, host)
	}
	return nil
}

// ReplaceEtcFile replaces dir/name with content by writing a temp file in dir,
// syncing it and renaming it over name.
//
// It is the one write mode for re-rendering a pod-level /etc file once the
// lease is held. A rename swaps the inode, so it must run before any container
// binds the file (a bind pins the inode it was made from, and a later rename is
// invisible through it); a truncate-then-write would instead be visible
// mid-write. The temp file never outlives the call.
func ReplaceEtcFile(dir, name, content string) error {
	dst := filepath.Join(dir, name)
	tmp := filepath.Join(dir, "."+name+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp) // best effort: the write error is the one reported
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp) // best effort: the sync error is the one reported
		return fmt.Errorf("sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp) // best effort: the close error is the one reported
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp) // best effort: the rename error is the one reported
		return fmt.Errorf("rename %s over %s: %w", tmp, dst, err)
	}
	return nil
}
