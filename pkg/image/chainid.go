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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// ChainID computes the OCI chain id of a layer chain from its diffIDs, in apply
// order, exactly as the OCI image-spec defines it:
//
//	ChainID(L0)      = DiffID(L0)
//	ChainID(L0..Ln)  = SHA256(ChainID(L0..Ln-1) + " " + DiffID(Ln))
//
// It is the key the LINUX dialect's snapshot store is filed under, and choosing
// it over TreeKey is a decision about what the tree IS rather than about how it
// was requested. A chain id names the content of an applied rootfs: two images
// built from one base — a different tag, a different registry, a different
// manifest entirely — that end in the same diffID sequence have the same rootfs,
// so they must share one snapshot. TreeKey, which folds in the config digest,
// would file them separately and unpack the same bytes twice.
//
// It is also self-AUTHENTICATING in a way a manifest-derived key is not: every
// diffID in the chain is re-verified against the layer's decompressed bytes
// before the snapshot is committed (Unpacker.applyLayer), so a committed
// snapshot's path is a claim the unpacker proved rather than one the registry
// asserted.
//
// # Why the single-layer case returns the diffID verbatim
//
// That is the spec's base case, not a shortcut: a one-layer chain IS its layer,
// so re-hashing it would produce a key that no other implementation agrees with
// and that could not be compared against a containerd or podman snapshot id.
//
// Every diffID is validated through parseBlobDigest before it enters the
// computation, so no registry-supplied string can inject the " " separator the
// construction depends on. An empty chain is an error: an image with no layers
// has no rootfs, and returning the digest of the empty string would give every
// such image one shared, permanently-empty snapshot.
func ChainID(diffIDs []string) (string, error) {
	if len(diffIDs) == 0 {
		return "", errors.New("chain id: an image with no layers has no rootfs chain")
	}
	for i, d := range diffIDs {
		if _, err := parseBlobDigest(d); err != nil {
			return "", fmt.Errorf("chain id: diffID %d: %w", i, err)
		}
	}
	chain := diffIDs[0]
	for _, d := range diffIDs[1:] {
		sum := sha256.Sum256([]byte(chain + " " + d))
		chain = "sha256:" + hex.EncodeToString(sum[:])
	}
	return chain, nil
}
