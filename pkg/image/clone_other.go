//go:build !darwin

package image

// APFSCloner off darwin has no APFS CoW; it byte-copies. It exists so the
// package builds and unit-tests run on non-darwin CI; production is darwin-only.
type APFSCloner struct{}

// Clone byte-copies src to dst (cow is always false off darwin).
func (APFSCloner) Clone(src, dst string) (bool, error) {
	if err := byteCopyFile(src, dst); err != nil {
		return false, err
	}
	return false, nil
}

// assertNoQuarantine is a no-op off darwin (no com.apple.quarantine concept).
func assertNoQuarantine(string) error { return nil }
