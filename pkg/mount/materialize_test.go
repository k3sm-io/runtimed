package mount

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fakeResolver serves canned ConfigMap/Secret data and a canned SA token — the
// provider's apiserver-backed Resolver stands in here so materialization is
// unit-testable without an apiserver or root.
type fakeResolver struct {
	cms      map[string]map[string][]byte
	secrets  map[string]map[string][]byte
	token    string
	tokenErr error
}

func (f fakeResolver) ConfigMap(_ context.Context, _, name string) (map[string][]byte, error) {
	if d, ok := f.cms[name]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("configMap %q: %w", name, os.ErrNotExist)
}

func (f fakeResolver) Secret(_ context.Context, _, name string) (map[string][]byte, error) {
	if d, ok := f.secrets[name]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("secret %q: %w", name, os.ErrNotExist)
}

func (f fakeResolver) ServiceAccountToken(_ context.Context, _, _ string, _ int64) (string, error) {
	return f.token, f.tokenErr
}

// mount builds a one-container PodBox mounting each named volume at /etc/<name>
// (or /scratch for the emptyDir), so Materialize has a mount to act on.
func boxWith(volumes ...*runtimev1.Volume) *runtimev1.PodBox {
	mounts := make([]*runtimev1.VolumeMount, 0, len(volumes))
	for _, v := range volumes {
		mounts = append(mounts, &runtimev1.VolumeMount{Name: v.GetName(), MountPath: "/etc/" + v.GetName()})
	}
	return &runtimev1.PodBox{
		PodId:      "pod-1",
		Namespace:  "default",
		Name:       "demo",
		PodIp:      "10.1.2.3",
		Volumes:    volumes,
		Containers: []*runtimev1.Container{{Name: "main", VolumeMounts: mounts}},
	}
}

// TestMaterializeAllSources is acceptance M2.2-a1 (materialization half, root-
// free): each of the five volume sources materializes at its mount path inside
// the pod data volume with the resolved content; secrets + the projected SA-token
// are reported as credentials for the SBPL read-only sub-scope.
func TestMaterializeAllSources(t *testing.T) {
	dataVol := t.TempDir()
	r := fakeResolver{
		cms: map[string]map[string][]byte{
			"nats-config": {"nats.conf": []byte("listen: 4222")},
			"ca":          {"ca.crt": []byte("CERT")},
		},
		secrets: map[string]map[string][]byte{
			"git-ssh-key": {"id_rsa": []byte("PRIVATE")},
		},
		token: "BOUND-TOKEN",
	}

	box := boxWith(
		&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "nats-config"}},
		&runtimev1.Volume{Name: "sec", Secret: &runtimev1.SecretVolumeSource{SecretName: "git-ssh-key"}},
		&runtimev1.Volume{Name: "scratch", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
		&runtimev1.Volume{Name: "down", DownwardApi: &runtimev1.DownwardAPIVolumeSource{Items: []*runtimev1.DownwardAPIVolumeFile{
			{Path: "name", FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "metadata.name"}},
			{Path: "ip", FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "status.podIP"}},
		}}},
		&runtimev1.Volume{Name: "proj", Projected: &runtimev1.ProjectedVolumeSource{Sources: []*runtimev1.VolumeProjection{
			{ServiceAccountToken: &runtimev1.ServiceAccountTokenProjection{Audience: "api", ExpirationSeconds: 3600, Path: "token"}},
			{ConfigMap: &runtimev1.ConfigMapProjection{Name: "ca"}},
		}}},
	)

	layout, err := Materialize(context.Background(), box, dataVol, "10.1.2.3", r)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}

	wantFiles := map[string]string{
		"etc/cm/nats.conf": "listen: 4222",
		"etc/sec/id_rsa":   "PRIVATE",
		"etc/down/name":    "demo",
		"etc/down/ip":      "10.1.2.3",
		"etc/proj/token":   "BOUND-TOKEN",
		"etc/proj/ca.crt":  "CERT",
	}
	for rel, want := range wantFiles {
		got, rerr := os.ReadFile(filepath.Join(dataVol, rel))
		if rerr != nil {
			t.Errorf("read %s: %v", rel, rerr)
			continue
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}
	// emptyDir is a real empty directory.
	if fi, err := os.Stat(filepath.Join(dataVol, "etc/scratch")); err != nil || !fi.IsDir() {
		t.Errorf("emptyDir scratch missing or not a dir: %v", err)
	}

	// Credentials: the secret and the projected (SA-token) mounts, sorted.
	wantCreds := []string{filepath.Join(dataVol, "etc/proj"), filepath.Join(dataVol, "etc/sec")}
	if got := layout.CredentialPaths(); !reflect.DeepEqual(got, wantCreds) {
		t.Errorf("CredentialPaths() = %v, want %v", got, wantCreds)
	}
}

// TestMaterializeSelectedKeysAndMode covers KeyToPath item selection and explicit
// file modes (a ConfigMap projecting only one key to a custom path/mode).
func TestMaterializeSelectedKeysAndMode(t *testing.T) {
	dataVol := t.TempDir()
	r := fakeResolver{cms: map[string]map[string][]byte{
		"cfg": {"a": []byte("AA"), "b": []byte("BB")},
	}}
	box := boxWith(&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{
		Name:        "cfg",
		Items:       []*runtimev1.KeyToPath{{Key: "a", Path: "only-a", Mode: 0o600}},
		DefaultMode: 0o644,
	}})
	if _, err := Materialize(context.Background(), box, dataVol, "", r); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dataVol, "etc/cm/b")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unselected key b should not be written")
	}
	fi, err := os.Stat(filepath.Join(dataVol, "etc/cm/only-a"))
	if err != nil {
		t.Fatalf("selected key not written: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("item mode = %o, want 600", fi.Mode().Perm())
	}
}

// TestMaterializeRejectsTraversal is the security guard: a mount path that would
// escape the pod data volume via ".." is rejected.
func TestMaterializeRejectsTraversal(t *testing.T) {
	dataVol := t.TempDir()
	box := &runtimev1.PodBox{
		Namespace:  "default",
		Volumes:    []*runtimev1.Volume{{Name: "ed", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}},
		Containers: []*runtimev1.Container{{Name: "c", VolumeMounts: []*runtimev1.VolumeMount{{Name: "ed", MountPath: "../../escape"}}}},
	}
	if _, err := Materialize(context.Background(), box, dataVol, "", nil); err == nil {
		t.Fatal("traversal mount path must be rejected")
	}
}

// TestMaterializeErrors covers undefined-volume refs, a missing Resolver for a
// data-backed source, and a required (non-optional) source that is absent.
func TestMaterializeErrors(t *testing.T) {
	dataVol := t.TempDir()

	t.Run("undefined-volume", func(t *testing.T) {
		box := &runtimev1.PodBox{
			Namespace:  "default",
			Containers: []*runtimev1.Container{{Name: "c", VolumeMounts: []*runtimev1.VolumeMount{{Name: "nope", MountPath: "/x"}}}},
		}
		if _, err := Materialize(context.Background(), box, dataVol, "", nil); err == nil {
			t.Fatal("undefined volume ref must error")
		}
	})

	t.Run("secret-without-resolver", func(t *testing.T) {
		box := boxWith(&runtimev1.Volume{Name: "sec", Secret: &runtimev1.SecretVolumeSource{SecretName: "s"}})
		if _, err := Materialize(context.Background(), box, dataVol, "", nil); err == nil {
			t.Fatal("data-backed volume with no Resolver must fail closed")
		}
	})

	t.Run("required-configmap-missing", func(t *testing.T) {
		box := boxWith(&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "absent"}})
		if _, err := Materialize(context.Background(), box, dataVol, "", fakeResolver{}); err == nil {
			t.Fatal("missing required ConfigMap must error")
		}
	})
}

// TestMaterializeOptionalMissing tolerates a missing optional source (empty mount
// dir, no error).
func TestMaterializeOptionalMissing(t *testing.T) {
	dataVol := t.TempDir()
	box := boxWith(&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "absent", Optional: true}})
	if _, err := Materialize(context.Background(), box, dataVol, "", fakeResolver{}); err != nil {
		t.Fatalf("optional missing ConfigMap should not error: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dataVol, "etc/cm")); err != nil || !fi.IsDir() {
		t.Errorf("optional mount dir should still exist: %v", err)
	}
}
