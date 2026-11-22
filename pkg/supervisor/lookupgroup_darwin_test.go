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

import (
	"errors"
	"os/user"
	"strconv"
	"testing"
)

// hostAccessGroups are the com.apple.access_ groups macOS makes for its
// sharing services. Which of them a host has depends on what it enabled.
var hostAccessGroups = []string{
	"com.apple.access_ssh",
	"com.apple.access_screensharing",
	"com.apple.access_remote_ae",
	"com.apple.access_ftp",
	"com.apple.access_sessionkey",
	"com.apple.access_disabled",
}

// TestCheckPodGroupsProductionLookup runs CheckPodGroups through the nil
// seam, so the verdicts come from LookupGroupID asking this Mac. everyone
// (12) is a host-assigned system group and only the lookup can refuse it;
// daemon (1) is refused by the never-list whatever the lookup answers. A
// com.apple.access_ group the host has, found by name, must be refused too:
// those groups are the ones a lookup that misses the system's group database
// would wave through.
func TestCheckPodGroupsProductionLookup(t *testing.T) {
	for _, tc := range []struct {
		name string
		gid  int
	}{
		{"everyone", 12},
		{"daemon", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred := Credential{UID: 300, GID: tc.gid, Groups: []int{tc.gid}, Drop: true}
			if err := cred.CheckPodGroups(ServiceIdentity{}, nil, nil); !errors.Is(err, ErrPodGroupRefused) {
				t.Errorf("primary gid %d (%s): err = %v, want ErrPodGroupRefused", tc.gid, tc.name, err)
			}
		})
	}
	t.Run("a com.apple.access_ group", func(t *testing.T) {
		for _, name := range hostAccessGroups {
			g, err := user.LookupGroup(name)
			if err != nil {
				continue
			}
			gid, err := strconv.Atoi(g.Gid)
			if err != nil {
				t.Fatalf("group %s: gid %q: %v", name, g.Gid, err)
			}
			cred := Credential{UID: 300, GID: gid, Groups: []int{gid}, Drop: true}
			if err := cred.CheckPodGroups(ServiceIdentity{}, nil, nil); !errors.Is(err, ErrPodGroupRefused) {
				t.Errorf("primary gid %d (%s): err = %v, want ErrPodGroupRefused", gid, name, err)
			}
			return
		}
		t.Skipf("this host has none of the com.apple.access_ groups %v", hostAccessGroups)
	})
}
