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

package runtime

import (
	"context"
	"io"
	"sort"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestImagesServiceServesOnlyCacheVerbs pins the node store's surface: it is an
// internal pull cache, so it serves the cache verbs (list, fs info, prune, the
// warm pull, inspect) and the read-only SaveImage export the one-time move into
// the cluster registry reads, and it answers every verb that would write a user
// name into the store with UNIMPLEMENTED naming the cluster-registry
// replacement.
//
// The table is checked against the service descriptor, so a verb added to the
// wire without a row here fails this test rather than defaulting to served.
func TestImagesServiceServesOnlyCacheVerbs(t *testing.T) {
	ctx := context.Background()
	client, _ := imagesTestClientDeps(t, Deps{Puller: &fakePuller{}})

	// call issues one minimal request and returns the RPC's error. A served verb
	// may well refuse the minimal request (INVALID_ARGUMENT, NOT_FOUND); what
	// matters here is only whether the daemon implements it.
	rows := []struct {
		verb    string
		served  bool
		replace string // the cluster-registry replacement an UNIMPLEMENTED names
		call    func() error
	}{
		{"ListImages", true, "", func() error {
			_, err := client.ListImages(ctx, &runtimev1.ListImagesRequest{})
			return err
		}},
		{"ImageFsInfo", true, "", func() error {
			_, err := client.ImageFsInfo(ctx, &runtimev1.ImageFsInfoRequest{})
			return err
		}},
		{"PruneImages", true, "", func() error {
			_, err := client.PruneImages(ctx, &runtimev1.PruneImagesRequest{DryRun: true})
			return err
		}},
		{"PullImage", true, "", func() error {
			_, err := client.PullImage(ctx, &runtimev1.PullImageRequest{Reference: "NOT A REF"})
			return err
		}},
		{"InspectImage", true, "", func() error {
			_, err := client.InspectImage(ctx, &runtimev1.InspectImageRequest{})
			return err
		}},
		{"SaveImage", true, "", func() error {
			stream, err := client.SaveImage(ctx, &runtimev1.SaveImageRequest{Reference: "example.com/absent:v1"})
			if err != nil {
				return err
			}
			for {
				if _, err := stream.Recv(); err != nil {
					if err == io.EOF {
						return nil
					}
					return err
				}
			}
		}},
		{"RemoveImage", false, "k3sm image untag", func() error {
			_, err := client.RemoveImage(ctx, &runtimev1.RemoveImageRequest{})
			return err
		}},
		{"LoadImage", false, "k3sm image load", func() error {
			stream, err := client.LoadImage(ctx)
			if err != nil {
				return err
			}
			_, err = stream.CloseAndRecv()
			return err
		}},
		{"TagImage", false, "k3sm image tag", func() error {
			_, err := client.TagImage(ctx, &runtimev1.TagImageRequest{Reference: "example.com/app:v1", Digest: "sha256:" + hexOf("x")})
			return err
		}},
		{"UntagImage", false, "k3sm image untag", func() error {
			_, err := client.UntagImage(ctx, &runtimev1.UntagImageRequest{Reference: "example.com/app:v1"})
			return err
		}},
	}

	var wire []string
	for _, m := range runtimev1.Images_ServiceDesc.Methods {
		wire = append(wire, m.MethodName)
	}
	for _, s := range runtimev1.Images_ServiceDesc.Streams {
		wire = append(wire, s.StreamName)
	}
	var covered []string
	for _, r := range rows {
		covered = append(covered, r.verb)
	}
	sort.Strings(wire)
	sort.Strings(covered)
	if strings.Join(wire, ",") != strings.Join(covered, ",") {
		t.Fatalf("table covers %v, the Images service has %v", covered, wire)
	}

	for _, r := range rows {
		t.Run(r.verb, func(t *testing.T) {
			err := r.call()
			got := status.Code(err)
			if r.served {
				if got == codes.Unimplemented {
					t.Fatalf("%s answered UNIMPLEMENTED (%v); it is a cache verb the node store serves", r.verb, err)
				}
				return
			}
			if got != codes.Unimplemented {
				t.Fatalf("%s answered %v (%v); want UNIMPLEMENTED, the node store is a pull cache", r.verb, got, err)
			}
			msg := status.Convert(err).Message()
			if !strings.Contains(msg, "cluster registry") || !strings.Contains(msg, r.replace) {
				t.Errorf("%s refusal %q does not name the cluster registry and %q", r.verb, msg, r.replace)
			}
		})
	}
}
