package volume

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
	storagev1 "k3sm.io/apis/storage/v1"
)

// testClass returns a local-path class rooted at <root>/storage (the runtime-root
// sibling layout New uses, with a temp root so tests need no privilege).
func testClass(root string) storagev1.LocalPathClass {
	c := storagev1.DefaultLocalPathClass()
	c.BasePath = filepath.Join(root, "storage")
	return c
}

// pvcBox builds a one-container PodBox mounting PVC claimName as volume volName at
// mountPath, in namespace ns.
func pvcBox(ns, volName, claimName, mountPath string, readOnly bool) *runtimev1.PodBox {
	return &runtimev1.PodBox{
		PodId:     "pod-" + claimName,
		Namespace: ns,
		Name:      "demo",
		Volumes: []*runtimev1.Volume{{
			Name: volName,
			PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{
				ClaimName: claimName,
				ReadOnly:  readOnly,
			},
		}},
		Containers: []*runtimev1.Container{{
			Name:         "main",
			VolumeMounts: []*runtimev1.VolumeMount{{Name: volName, MountPath: mountPath}},
		}},
	}
}

// fakeTemplate is a TemplateResolver returning a fixed source dir for any claim
// when present is true; ok=false models a class with no seed template.
type fakeTemplate struct {
	dir     string
	present bool
	err     error
}

func (f fakeTemplate) Template(_ context.Context, _, _ string) (string, bool, error) {
	return f.dir, f.present, f.err
}

// TestPVCMaterializeStableDir is acceptance runtimed:M3.1-a1 (root-free): a PodBox
// with a PVC source materializes the dir at storagev1 DataDir, and the SAME
// (namespace, claim) resolves to the SAME path across calls (stable), with a
// symlink linking it into each pod's rootfs.
func TestPVCMaterializeStableDir(t *testing.T) {
	root := t.TempDir()
	class := testClass(root)
	b := NewBinder(class, image.ByteCopier{}, nil, nil)

	wantDir, err := class.DataDir("prod", "pgdata")
	if err != nil {
		t.Fatal(err)
	}

	// First pod binds the claim.
	rootfs1 := filepath.Join(root, "pods", "pod-a", "rootfs")
	if err := os.MkdirAll(rootfs1, 0o755); err != nil {
		t.Fatal(err)
	}
	box1 := pvcBox("prod", "data", "pgdata", "/var/lib/pg", false)
	bindings, err := b.Bind(context.Background(), box1, rootfs1)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("got %d bindings, want 1", len(bindings))
	}
	bd := bindings[0]
	if bd.DataDir != wantDir {
		t.Errorf("DataDir = %q, want %q (storagev1 DataDir)", bd.DataDir, wantDir)
	}
	if bd.Seeded {
		t.Error("empty-create must not report Seeded")
	}
	if fi, err := os.Stat(bd.DataDir); err != nil || !fi.IsDir() {
		t.Fatalf("PV dir not created at %s: %v", bd.DataDir, err)
	}
	// The mount root is linked into the pod rootfs and resolves to the PV dir.
	wantLink := filepath.Join(rootfs1, "var/lib/pg")
	if len(bd.Links) != 1 || bd.Links[0] != wantLink {
		t.Fatalf("Links = %v, want [%s]", bd.Links, wantLink)
	}
	if dst, err := os.Readlink(wantLink); err != nil || dst != bd.DataDir {
		t.Errorf("link %s -> %q (err %v), want -> %q", wantLink, dst, err, bd.DataDir)
	}

	// A SECOND pod for the SAME (namespace, claim) resolves to the SAME dir
	// (stable) and reuses it (not re-created, not seeded).
	rootfs2 := filepath.Join(root, "pods", "pod-b", "rootfs")
	if err := os.MkdirAll(rootfs2, 0o755); err != nil {
		t.Fatal(err)
	}
	box2 := pvcBox("prod", "data", "pgdata", "/var/lib/pg", false)
	bindings2, err := b.Bind(context.Background(), box2, rootfs2)
	if err != nil {
		t.Fatalf("Bind (reuse): %v", err)
	}
	if bindings2[0].DataDir != wantDir {
		t.Errorf("reuse DataDir = %q, want stable %q", bindings2[0].DataDir, wantDir)
	}
	if bindings2[0].Seeded {
		t.Error("reuse must not re-seed")
	}

	// A DIFFERENT claim resolves to a DIFFERENT dir.
	other, _ := class.DataDir("prod", "redisdata")
	if other == wantDir {
		t.Fatal("distinct claims must map to distinct dirs")
	}
}

// TestPVCSeedOnce proves clonefile seeding happens ONLY on first create (M3.1-d2):
// a fresh claim with a configured template is seeded; a reuse is not re-seeded
// (even after the seeded content is removed), and a claim whose class has no
// template is empty-created with no clone.
func TestPVCSeedOnce(t *testing.T) {
	root := t.TempDir()
	class := testClass(root)

	// A template source dir with one seed file.
	src := filepath.Join(root, "template")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "schema.sql"), []byte("CREATE TABLE t;"), 0o644); err != nil {
		t.Fatal(err)
	}

	b := NewBinder(class, image.ByteCopier{}, fakeTemplate{dir: src, present: true}, nil)

	rootfs1 := filepath.Join(root, "pods", "pod-a", "rootfs")
	if err := os.MkdirAll(rootfs1, 0o755); err != nil {
		t.Fatal(err)
	}
	box := pvcBox("prod", "data", "seeded", "/seed", false)
	bindings, err := b.Bind(context.Background(), box, rootfs1)
	if err != nil {
		t.Fatalf("Bind (seed): %v", err)
	}
	if !bindings[0].Seeded {
		t.Fatal("first create with a template must report Seeded")
	}
	seedFile := filepath.Join(bindings[0].DataDir, "schema.sql")
	if got, err := os.ReadFile(seedFile); err != nil || string(got) != "CREATE TABLE t;" {
		t.Fatalf("seed content = %q (err %v), want the template file", got, err)
	}

	// Simulate the pod consuming/removing the seeded file, then a SECOND bind for
	// the same claim. Seeding must NOT recur: the file stays absent (seed-once).
	if err := os.Remove(seedFile); err != nil {
		t.Fatal(err)
	}
	rootfs2 := filepath.Join(root, "pods", "pod-b", "rootfs")
	if err := os.MkdirAll(rootfs2, 0o755); err != nil {
		t.Fatal(err)
	}
	bindings2, err := b.Bind(context.Background(), box, rootfs2)
	if err != nil {
		t.Fatalf("Bind (reuse): %v", err)
	}
	if bindings2[0].Seeded {
		t.Error("reuse must NOT re-seed (seed-once)")
	}
	if _, err := os.Stat(seedFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("seed file was re-created on reuse (err=%v); seeding must be once-only", err)
	}

	// A class with no template (ok=false) empty-creates: no seed file appears.
	bEmpty := NewBinder(class, image.ByteCopier{}, fakeTemplate{present: false}, nil)
	rootfs3 := filepath.Join(root, "pods", "pod-c", "rootfs")
	if err := os.MkdirAll(rootfs3, 0o755); err != nil {
		t.Fatal(err)
	}
	emptyBox := pvcBox("prod", "data", "fresh", "/fresh", false)
	eb, err := bEmpty.Bind(context.Background(), emptyBox, rootfs3)
	if err != nil {
		t.Fatalf("Bind (empty): %v", err)
	}
	if eb[0].Seeded {
		t.Error("empty-create (no template) must not report Seeded")
	}
	if entries, _ := os.ReadDir(eb[0].DataDir); len(entries) != 0 {
		t.Errorf("empty-create dir is not empty: %v", entries)
	}
}

// TestBindReadOnlyAndNoPVC covers the read-only flag pass-through and the no-PVC
// short-circuit (a box with only ephemeral volumes returns no bindings).
func TestBindReadOnlyAndNoPVC(t *testing.T) {
	root := t.TempDir()
	b := NewBinder(testClass(root), image.ByteCopier{}, nil, nil)
	rootfs := filepath.Join(root, "pods", "pod-ro", "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}

	ro := pvcBox("prod", "data", "shared", "/ro", true)
	bindings, err := b.Bind(context.Background(), ro, rootfs)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if len(bindings) != 1 || !bindings[0].ReadOnly {
		t.Fatalf("read-only intent not propagated: %+v", bindings)
	}

	noPVC := &runtimev1.PodBox{
		PodId:     "pod-e",
		Namespace: "prod",
		Volumes:   []*runtimev1.Volume{{Name: "scratch", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}},
		Containers: []*runtimev1.Container{{
			Name:         "main",
			VolumeMounts: []*runtimev1.VolumeMount{{Name: "scratch", MountPath: "/scratch"}},
		}},
	}
	if got, err := b.Bind(context.Background(), noPVC, rootfs); err != nil || got != nil {
		t.Errorf("no-PVC box: got (%v, %v), want (nil, nil)", got, err)
	}
}

// TestBindRejectsMountEscape fails closed when a PVC mount path would escape the
// pod rootfs.
func TestBindRejectsMountEscape(t *testing.T) {
	root := t.TempDir()
	b := NewBinder(testClass(root), image.ByteCopier{}, nil, nil)
	rootfs := filepath.Join(root, "pods", "pod-esc", "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	box := pvcBox("prod", "data", "evil", "../../escape", false)
	if _, err := b.Bind(context.Background(), box, rootfs); !errors.Is(err, ErrInvalid) {
		t.Fatalf("escaping mount path: err = %v, want ErrInvalid", err)
	}
}
