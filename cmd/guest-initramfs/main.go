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

// Command guest-initramfs composes the micro-VM guest's initramfs from a
// cross-compiled k3sm-guest-init binary.
//
//	guest-initramfs -init <path-to-init> -o <out.cpio>
//
// It is a thin front end for k3sm.io/runtimed/pkg/guestartifacts: every
// decision about the archive's contents and its byte-determinism lives there,
// where it is unit-tested. This file reads a file, writes a file, and reports
// the digest the artifact will be pinned by.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"k3sm.io/runtimed/pkg/guestartifacts"
)

func main() {
	initPath := flag.String("init", "", "path to the cross-compiled guest init binary (required)")
	outPath := flag.String("o", "", "path to write the newc cpio initramfs to (required)")
	flag.Parse()

	if err := run(*initPath, *outPath); err != nil {
		fmt.Fprintf(os.Stderr, "guest-initramfs: %v\n", err)
		os.Exit(1)
	}
}

func run(initPath, outPath string) error {
	if initPath == "" || outPath == "" {
		flag.Usage()
		return fmt.Errorf("both -init and -o are required")
	}

	initBinary, err := os.ReadFile(initPath)
	if err != nil {
		return fmt.Errorf("read init %s: %w", initPath, err)
	}

	// Composed into memory first so a failed compose leaves no partial archive
	// on disk for a later step to mistake for a finished one. The artifact is
	// a few megabytes; buffering it costs nothing worth a truncated output.
	var buf bytes.Buffer
	if err := guestartifacts.ComposeInitramfs(&buf, initBinary); err != nil {
		return fmt.Errorf("compose initramfs: %w", err)
	}
	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}

	sum := sha256.Sum256(buf.Bytes())
	fmt.Printf("%s: %d bytes, sha256 %s\n", outPath, buf.Len(), hex.EncodeToString(sum[:]))
	return nil
}
