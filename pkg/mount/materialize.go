package mount

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// defaultFileMode is the file permission applied to a materialized volume file
// when neither the item mode nor the source default_mode is set (mirrors the
// corev1 default 0644). Credential read-only-ness is enforced by the SBPL
// sub-scope, not these bits.
const defaultFileMode os.FileMode = 0o644

// Layout describes the volumes materialized for one pod: the per-mount roots, and
// which of them are credentials (secrets / SA-token) that must get the SBPL
// read-only sub-scope.
type Layout struct {
	// Mounts is one entry per unique materialized mount path.
	Mounts []Mount
}

// Mount is one materialized volume mount root.
type Mount struct {
	// Name is the Volume/VolumeMount name.
	Name string
	// Path is the absolute host path the volume was materialized at (always under
	// the pod data volume — see the package doc).
	Path string
	// ReadOnly is the effective read-only intent (true for secrets, SA-token, and
	// projected volumes, or when the VolumeMount sets read_only).
	ReadOnly bool
	// Credential marks a secret / SA-token (or a projected volume containing one):
	// it gets the SBPL read-only sub-scope so the pod cannot overwrite it.
	Credential bool
}

// CredentialPaths returns the materialized paths that are credentials, sorted —
// the input to sandbox.GenerateOptions.ReadOnlyPaths (the read-only sub-scope).
func (l *Layout) CredentialPaths() []string {
	var out []string
	for _, m := range l.Mounts {
		if m.Credential {
			out = append(out, m.Path)
		}
	}
	sort.Strings(out)
	return out
}

// Materialize renders every volume referenced by a container VolumeMount in box
// into the pod's data volume, returning the resulting Layout. dataVol is the pod
// data volume (its rootfs); podIP is the resolved pod IP (for status.podIP
// downward-API projections); r supplies ConfigMap/Secret data and SA tokens.
//
// A mount that needs data (configMap / secret / projected-with-data) requires a
// non-nil Resolver; emptyDir and pure-downwardAPI volumes do not. A volume_mount
// that names no PodBox.volume, or whose mount path would escape the data volume,
// is rejected (fail closed). A persistentVolumeClaim mount is SKIPPED here — it is
// durable and lifecycle-decoupled, bound by pkg/volume to a stable dir outside the
// pod tree (M3.1), not materialized into the pod data volume.
func Materialize(ctx context.Context, box *runtimev1.PodBox, dataVol, podIP string, r Resolver) (*Layout, error) {
	dataVol = filepath.Clean(dataVol)
	volumes := make(map[string]*runtimev1.Volume, len(box.GetVolumes()))
	for _, v := range box.GetVolumes() {
		volumes[v.GetName()] = v
	}

	layout := &Layout{}
	seen := make(map[string]string) // target path -> volume name (conflict guard)

	containers := make([]*runtimev1.Container, 0, len(box.GetInitContainers())+len(box.GetContainers()))
	containers = append(containers, box.GetInitContainers()...)
	containers = append(containers, box.GetContainers()...)

	for _, c := range containers {
		for _, vm := range c.GetVolumeMounts() {
			vol, ok := volumes[vm.GetName()]
			if !ok {
				return nil, fmt.Errorf("container %s: volume_mount %q references undefined volume", c.GetName(), vm.GetName())
			}
			// PVC sources are durable and lifecycle-decoupled: pkg/volume binds them
			// to a stable dir OUTSIDE the pod tree and symlinks them into the rootfs.
			// They are not materialized (rebased) here. (M3.1)
			if vol.GetPersistentVolumeClaim() != nil {
				continue
			}
			target, err := resolveTarget(dataVol, vm.GetMountPath(), vm.GetSubPath())
			if err != nil {
				return nil, fmt.Errorf("volume %s: %w", vm.GetName(), err)
			}
			if prev, dup := seen[target]; dup {
				if prev == vm.GetName() {
					continue // same volume mounted into multiple containers at the same path
				}
				return nil, fmt.Errorf("volumes %q and %q both target %q", prev, vm.GetName(), target)
			}
			seen[target] = vm.GetName()

			credential, err := materializeVolume(ctx, box.GetNamespace(), podIP, vol, target, box, r)
			if err != nil {
				return nil, fmt.Errorf("materialize volume %s: %w", vm.GetName(), err)
			}
			layout.Mounts = append(layout.Mounts, Mount{
				Name:       vm.GetName(),
				Path:       target,
				ReadOnly:   vm.GetReadOnly() || credential || vol.GetProjected() != nil,
				Credential: credential,
			})
		}
	}
	return layout, nil
}

// resolveTarget rebases mountPath (and optional subPath) under dataVol. Because
// k3sm has no mount namespace, an absolute mountPath like "/etc/config" is
// interpreted relative to the pod data volume, not the host root. A path that
// would escape dataVol (via "..") is rejected.
func resolveTarget(dataVol, mountPath, subPath string) (string, error) {
	if mountPath == "" {
		return "", errors.New("mount_path is empty")
	}
	target := filepath.Join(dataVol, mountPath, subPath)
	if !isUnder(target, dataVol) {
		return "", fmt.Errorf("mount_path %q escapes the pod data volume", filepath.Join(mountPath, subPath))
	}
	return target, nil
}

// materializeVolume writes vol's single source into target, returning whether the
// volume is a credential (secret / projected-with-secret-or-token).
func materializeVolume(ctx context.Context, ns, podIP string, vol *runtimev1.Volume, target string, box *runtimev1.PodBox, r Resolver) (credential bool, err error) {
	if err := os.MkdirAll(target, 0o755); err != nil {
		return false, fmt.Errorf("create mount dir %s: %w", target, err)
	}
	switch {
	case vol.GetConfigMap() != nil:
		return false, renderConfigMap(ctx, ns, vol.GetConfigMap(), target, r)
	case vol.GetSecret() != nil:
		return true, renderSecret(ctx, ns, vol.GetSecret(), target, r)
	case vol.GetEmptyDir() != nil:
		return false, nil // an empty writable dir is the whole job
	case vol.GetDownwardApi() != nil:
		return false, renderDownwardAPI(vol.GetDownwardApi(), target, box, podIP)
	case vol.GetProjected() != nil:
		return renderProjected(ctx, ns, vol.GetProjected(), target, box, podIP, r)
	default:
		return false, fmt.Errorf("volume %s has no recognized source", vol.GetName())
	}
}

// renderConfigMap writes a ConfigMap's keys as files under target.
func renderConfigMap(ctx context.Context, ns string, src *runtimev1.ConfigMapVolumeSource, target string, r Resolver) error {
	data, err := resolveData(ctx, r, "configMap", ns, src.GetName(), src.GetOptional(), func() (map[string][]byte, error) {
		if r == nil {
			return nil, errNoResolver
		}
		return r.ConfigMap(ctx, ns, src.GetName())
	})
	if err != nil {
		return err
	}
	return writeKeyed(target, data, src.GetItems(), modeOr(src.GetDefaultMode()), src.GetOptional())
}

// renderSecret writes a Secret's keys as files under target (read-only sub-scope
// applied SBPL-side by the caller).
func renderSecret(ctx context.Context, ns string, src *runtimev1.SecretVolumeSource, target string, r Resolver) error {
	data, err := resolveData(ctx, r, "secret", ns, src.GetSecretName(), src.GetOptional(), func() (map[string][]byte, error) {
		if r == nil {
			return nil, errNoResolver
		}
		return r.Secret(ctx, ns, src.GetSecretName())
	})
	if err != nil {
		return err
	}
	return writeKeyed(target, data, src.GetItems(), modeOr(src.GetDefaultMode()), src.GetOptional())
}

// renderEmptyDir is a no-op beyond the MkdirAll the caller already did.

// renderDownwardAPI writes each downward-API field projection as a file.
func renderDownwardAPI(src *runtimev1.DownwardAPIVolumeSource, target string, box *runtimev1.PodBox, podIP string) error {
	dflt := modeOr(src.GetDefaultMode())
	for _, item := range src.GetItems() {
		val, err := resolveDownwardField(box, podIP, item.GetFieldRef().GetFieldPath())
		if err != nil {
			return err
		}
		mode := dflt
		if m := item.GetMode(); m != 0 {
			mode = os.FileMode(m)
		}
		if err := writeFile(target, item.GetPath(), []byte(val), mode); err != nil {
			return err
		}
	}
	return nil
}

// renderProjected layers each projection source into the same target dir,
// returning whether any source is a credential (secret / SA-token).
func renderProjected(ctx context.Context, ns string, src *runtimev1.ProjectedVolumeSource, target string, box *runtimev1.PodBox, podIP string, r Resolver) (bool, error) {
	dflt := modeOr(src.GetDefaultMode())
	credential := false
	for _, p := range src.GetSources() {
		switch {
		case p.GetConfigMap() != nil:
			cm := p.GetConfigMap()
			data, err := resolveData(ctx, r, "configMap", ns, cm.GetName(), cm.GetOptional(), func() (map[string][]byte, error) {
				if r == nil {
					return nil, errNoResolver
				}
				return r.ConfigMap(ctx, ns, cm.GetName())
			})
			if err != nil {
				return credential, err
			}
			if err := writeKeyed(target, data, cm.GetItems(), dflt, cm.GetOptional()); err != nil {
				return credential, err
			}
		case p.GetSecret() != nil:
			credential = true
			sec := p.GetSecret()
			data, err := resolveData(ctx, r, "secret", ns, sec.GetName(), sec.GetOptional(), func() (map[string][]byte, error) {
				if r == nil {
					return nil, errNoResolver
				}
				return r.Secret(ctx, ns, sec.GetName())
			})
			if err != nil {
				return credential, err
			}
			if err := writeKeyed(target, data, sec.GetItems(), dflt, sec.GetOptional()); err != nil {
				return credential, err
			}
		case p.GetDownwardApi() != nil:
			for _, item := range p.GetDownwardApi().GetItems() {
				val, err := resolveDownwardField(box, podIP, item.GetFieldRef().GetFieldPath())
				if err != nil {
					return credential, err
				}
				mode := dflt
				if m := item.GetMode(); m != 0 {
					mode = os.FileMode(m)
				}
				if err := writeFile(target, item.GetPath(), []byte(val), mode); err != nil {
					return credential, err
				}
			}
		case p.GetServiceAccountToken() != nil:
			credential = true
			sat := p.GetServiceAccountToken()
			if r == nil {
				return credential, errNoResolver
			}
			token, err := r.ServiceAccountToken(ctx, ns, sat.GetAudience(), sat.GetExpirationSeconds())
			if err != nil {
				return credential, fmt.Errorf("mint SA token (audience %q): %w", sat.GetAudience(), err)
			}
			if err := writeFile(target, sat.GetPath(), []byte(token), dflt); err != nil {
				return credential, err
			}
		}
	}
	return credential, nil
}

// errNoResolver reports a data-backed volume source with no Resolver wired.
var errNoResolver = errors.New("no volume Resolver configured (configMap/secret/SA-token require one)")

// resolveData fetches a ConfigMap/Secret's data, honoring optional: a source that
// reports os.ErrNotExist while optional yields empty data (skip), otherwise the
// error propagates.
func resolveData(ctx context.Context, r Resolver, kind, ns, name string, optional bool, fetch func() (map[string][]byte, error)) (map[string][]byte, error) {
	data, err := fetch()
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			return map[string][]byte{}, nil
		}
		return nil, fmt.Errorf("%s %s/%s: %w", kind, ns, name, err)
	}
	return data, nil
}

// writeKeyed writes data into target. With items set, only the named keys are
// projected (to their item paths/modes); otherwise every key is written to a file
// of the same name. A selected key absent from data is an error unless optional.
func writeKeyed(target string, data map[string][]byte, items []*runtimev1.KeyToPath, dflt os.FileMode, optional bool) error {
	if len(items) > 0 {
		for _, item := range items {
			val, ok := data[item.GetKey()]
			if !ok {
				if optional {
					continue
				}
				return fmt.Errorf("key %q not found", item.GetKey())
			}
			mode := dflt
			if m := item.GetMode(); m != 0 {
				mode = os.FileMode(m)
			}
			if err := writeFile(target, item.GetPath(), val, mode); err != nil {
				return err
			}
		}
		return nil
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := writeFile(target, k, data[k], dflt); err != nil {
			return err
		}
	}
	return nil
}

// writeFile writes content to rel under base, creating parent dirs, then chmods
// to mode exactly (independent of umask). rel may not escape base.
func writeFile(base, rel string, content []byte, mode os.FileMode) error {
	if rel == "" {
		return errors.New("empty file path in volume projection")
	}
	p := filepath.Join(base, rel)
	if !isUnder(p, base) {
		return fmt.Errorf("projection path %q escapes the volume", rel)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("create dir for %s: %w", p, err)
	}
	if err := os.WriteFile(p, content, mode); err != nil {
		return fmt.Errorf("write %s: %w", p, err)
	}
	if err := os.Chmod(p, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", p, err)
	}
	return nil
}

// resolveDownwardField resolves a downward-API field path against the PodBox.
// Supported: metadata.name/namespace/uid, status.podIP(s), and
// metadata.labels['k'] / metadata.annotations['k']. Fields the PodBox cannot
// carry (spec.nodeName, status.hostIP, spec.serviceAccountName) resolve to ""
// rather than failing the pod; a genuinely unknown path is an error.
func resolveDownwardField(box *runtimev1.PodBox, podIP, fieldPath string) (string, error) {
	if key, ok := subscript(fieldPath, "metadata.labels"); ok {
		return box.GetLabels()[key], nil
	}
	if key, ok := subscript(fieldPath, "metadata.annotations"); ok {
		return box.GetAnnotations()[key], nil
	}
	switch fieldPath {
	case "metadata.name":
		return box.GetName(), nil
	case "metadata.namespace":
		return box.GetNamespace(), nil
	case "metadata.uid":
		return box.GetPodId(), nil
	case "status.podIP", "status.podIPs":
		return podIP, nil
	case "status.hostIP", "spec.nodeName", "spec.serviceAccountName":
		return "", nil // not carried by PodBox; the provider supplies these via env
	default:
		return "", fmt.Errorf("unsupported downward-API field path %q", fieldPath)
	}
}

// subscript parses a "prefix['key']" downward-API field path, returning the key
// and true when fieldPath has that prefix-with-subscript shape.
func subscript(fieldPath, prefix string) (string, bool) {
	if !strings.HasPrefix(fieldPath, prefix+"[") || !strings.HasSuffix(fieldPath, "]") {
		return "", false
	}
	inner := fieldPath[len(prefix)+1 : len(fieldPath)-1]
	inner = strings.Trim(inner, `'"`)
	return inner, true
}

// modeOr converts a proto mode (0 = unset) to an os.FileMode, defaulting to
// defaultFileMode when unset.
func modeOr(m int32) os.FileMode {
	if m == 0 {
		return defaultFileMode
	}
	return os.FileMode(m)
}

// isUnder reports whether path is base itself or a descendant (both cleaned).
func isUnder(path, base string) bool {
	path = filepath.Clean(path)
	base = filepath.Clean(base)
	return path == base || strings.HasPrefix(path, base+string(filepath.Separator))
}
