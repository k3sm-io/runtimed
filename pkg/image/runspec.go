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
	"errors"
	"fmt"
	"strconv"
	"strings"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ErrRunSpecInvalid reports a container that cannot be run as specified: the
// merge of its pod spec with its image config yields no command, or the
// resolved identity contradicts an explicit runAsNonRoot.
//
// It is a POD-SPEC verdict, not an image verdict, which is why it is one
// sentinel and not two: in every case the operator's remedy is to change the
// container (give it a command, set runAsUser, drop runAsNonRoot), even when the
// missing half came from the image.
var ErrRunSpecInvalid = errors.New("image: container run spec is not runnable")

// ImageRunConfig is the PROCESS half of an OCI image config: what the image says
// it runs when a pod spec says nothing.
//
// It is a plain struct rather than the ggcr config type so that MergeRunSpec is
// a pure function over data this package controls, testable without building an
// image — and so the merge cannot silently start depending on a config field
// nobody decided to honour.
type ImageRunConfig struct {
	// Entrypoint and Cmd are the image's argv halves. Their interaction with
	// the pod's command/args is the four-quadrant table in MergeRunSpec.
	Entrypoint []string
	Cmd        []string
	// Env are the image's environment entries in "K=V" form.
	Env []string
	// WorkingDir is the image's declared working directory.
	WorkingDir string
	// User is the image's USER directive, verbatim and unparsed: "1000",
	// "1000:1000", "nobody", "nobody:nogroup", or empty. It is not resolved
	// here — resolving a NAME requires the image's own /etc/passwd, which is a
	// file inside the unpacked tree, so resolution belongs to whoever has that
	// tree mounted as a root. See RunSpec.User.
	User string
}

// RunSpec is the resolved process spec for one container: what to execute, with
// what environment, where, and as whom.
type RunSpec struct {
	// Argv is the merged argument vector. Argv[0] is the program as the merge
	// produced it — a bare name, a relative path, or an absolute one — and is
	// not resolved against any rootfs here: which root it is resolved against is
	// the spine's decision (a native pod has no root; a guest chroots), and this
	// package must not pick one.
	Argv []string
	// Env is the merged environment in "K=V" form: the image's entries first,
	// in image order, with the pod's entries overriding by NAME and any new
	// pod entries appended in pod order.
	Env []string
	// WorkingDir is the pod's working_dir when set, else the image's, else
	// empty (meaning "the spine's default").
	WorkingDir string
	// User is the image's USER directive verbatim (see ImageRunConfig.User),
	// carried so a guest that can resolve a name has the string to resolve. It
	// is empty when the image declares none.
	User string
	// UID is the numeric uid to run as, and HasUID reports whether one was
	// determined at all. It is the pod's resolved runAsUser when that is set,
	// else the image's USER when that is numeric, else undetermined — a
	// non-numeric image USER never becomes a uid here.
	UID    int64
	HasUID bool
}

// RunSpecRequest is the pod-side half of the merge.
//
// The security-context fields arrive as RESOLVED SCALARS rather than as the
// proto messages, because the kube precedence chain (container securityContext >
// pod securityContext > PodBox) is the runtime layer's contract and already has
// exactly one implementation there. Duplicating it here would make this package
// a second authority on it; passing the answer keeps it the caller's.
type RunSpecRequest struct {
	// Container is the pod's container spec. Its Command, Args, Env and
	// WorkingDir are the pod half of the merge.
	Container *runtimev1.Container
	// RunAsUID is the uid the caller resolved from the securityContext chain.
	// zero MEANS UNSPECIFIED: the proto's run_as_user is a plain int64 with no
	// presence, so "unset" and "explicitly root" are the same wire value — the
	// same reading pkg/runtime.resolveCredential already applies, and the two
	// readings must agree or a pod would drop to a uid this merge did not
	// validate.
	RunAsUID int64
	// RunAsNonRoot is the effective runAsNonRoot for this container.
	RunAsNonRoot bool
}

// MergeRunSpec merges an image's run config with a container's pod spec, per
// Kubernetes' four-quadrant command/args rule, and validates the result.
//
// # The four quadrants (upstream's table, verbatim)
//
//	pod command | pod args | argv
//	------------+----------+------------------------------------
//	empty       | empty    | image Entrypoint + image Cmd
//	empty       | set      | image Entrypoint + pod args
//	set         | empty    | pod command
//	set         | set      | pod command + pod args
//
// The asymmetry in row 3 is the one people get wrong and it is deliberate
// upstream: a pod command replaces the entrypoint and discards the image's Cmd,
// because the image's Cmd is arguments to the entrypoint the pod just replaced.
// Carrying it over would silently pass one program's arguments to another.
//
// # $(VAR) expansion
//
// Every element of the merged argv is expanded against the merged environment
// using upstream's syntax: "$(NAME)" is replaced, "$$" is a literal "$", and a
// reference to a name the environment does not define is left exactly AS
// WRITTEN. The last rule is what makes it safe to run a shell command
// containing "$(date)" as an argument: an undefined reference is data, never an
// error and never an empty string.
//
// # runAsNonRoot
//
// Upstream's verifyRunAsNonRoot, reproduced branch for branch:
//
//   - runAsNonRoot unset/false — no check.
//   - runAsUser set (non-zero, see RunSpecRequest.RunAsUID) — allowed; a
//     non-zero uid is by definition not root.
//   - runAsUser unset, image USER numeric 0 — refused ("the image will run as
//     root").
//   - runAsUser unset, image USER non-numeric — refused ("cannot verify the
//     user is non-root"). This is the numeric-USER rule: the host will not
//     resolve a name out of the image's /etc/passwd to decide a privilege
//     question, because that file is registry-supplied content inside the very
//     tree being run.
//   - runAsUser unset, image USER empty — ALLOWED, which is upstream's behaviour
//     and is a fail-OPEN branch this deliberately does not close. An image with
//     no USER runs as root by the OCI spec, so a stricter reading would be
//     defensible; but the CRI reports "no user" and "user 0" identically, so
//     upstream admits this case, and refusing it here would reject the large
//     majority of real images under a runAsNonRoot pod security context that
//     every other Kubernetes admits. The effective uid is applied by the spine
//     that actually has a uid to apply, and that is where the gap closes.
func MergeRunSpec(cfg ImageRunConfig, req RunSpecRequest) (RunSpec, error) {
	c := req.Container
	cmd, args := c.GetCommand(), c.GetArgs()

	var argv []string
	switch {
	case len(cmd) > 0:
		argv = append(argv, cmd...)
		argv = append(argv, args...)
	case len(args) > 0:
		argv = append(argv, cfg.Entrypoint...)
		argv = append(argv, args...)
	default:
		argv = append(argv, cfg.Entrypoint...)
		argv = append(argv, cfg.Cmd...)
	}
	if len(argv) == 0 {
		return RunSpec{}, fmt.Errorf("%w: container %s has no command and image %s declares neither Entrypoint nor Cmd",
			ErrRunSpecInvalid, quoteBounded(c.GetName(), maxTokenLen), quoteBounded(c.GetImage(), maxDigestLen))
	}

	env := mergeEnv(cfg.Env, c.GetEnv())
	lookup := envLookup(env)
	expanded := make([]string, len(argv))
	for i, a := range argv {
		expanded[i] = expandVars(a, lookup)
	}

	workdir := c.GetWorkingDir()
	if workdir == "" {
		workdir = cfg.WorkingDir
	}

	spec := RunSpec{Argv: expanded, Env: env, WorkingDir: workdir, User: cfg.User}
	if req.RunAsUID != 0 {
		spec.UID, spec.HasUID = req.RunAsUID, true
	} else if uid, ok := numericImageUser(cfg.User); ok {
		spec.UID, spec.HasUID = uid, true
	}
	if err := verifyRunAsNonRoot(cfg.User, req); err != nil {
		return RunSpec{}, err
	}
	return spec, nil
}

// verifyRunAsNonRoot is upstream's check, in the branch order MergeRunSpec's doc
// comment enumerates. It takes the image USER string rather than the resolved
// uid because the two REFUSING branches are distinguished by whether the string
// parsed at all, which the resolved uid can no longer tell you.
func verifyRunAsNonRoot(imageUser string, req RunSpecRequest) error {
	if !req.RunAsNonRoot || req.RunAsUID != 0 {
		return nil
	}
	name := c0(imageUser)
	if name == "" {
		return nil
	}
	if uid, ok := numericImageUser(imageUser); ok {
		if uid == 0 {
			return fmt.Errorf("%w: container %s sets runAsNonRoot and the image runs as uid 0",
				ErrRunSpecInvalid, quoteBounded(req.Container.GetName(), maxTokenLen))
		}
		return nil
	}
	return fmt.Errorf("%w: container %s sets runAsNonRoot and the image user %s is not numeric, so it cannot be verified non-root",
		ErrRunSpecInvalid, quoteBounded(req.Container.GetName(), maxTokenLen), quoteBounded(name, maxTokenLen))
}

// numericImageUser parses the UID half of an image USER directive
// ("1000", "1000:1000"), reporting false for a name, an empty value, or a
// negative or overflowing number.
func numericImageUser(user string) (int64, bool) {
	name := c0(user)
	if name == "" {
		return 0, false
	}
	uid, err := strconv.ParseInt(name, 10, 64)
	if err != nil || uid < 0 {
		return 0, false
	}
	return uid, true
}

// c0 returns the USER half of a "user[:group]" directive.
func c0(user string) string {
	name, _, _ := strings.Cut(user, ":")
	return name
}

// mergeEnv merges the image's environment with the pod's: image entries first in
// image order, pod entries overriding by NAME in place, and new pod entries
// appended in pod order.
//
// Overriding IN place rather than appending matters for a consumer that reads
// the last occurrence of a duplicate name (execve leaves duplicates to libc, and
// implementations differ on which wins), and preserving image order matters
// because an image's own $PATH must keep whatever position it had.
//
// An image entry with no "=" is DROPPED. The OCI spec requires "K=V", and a
// bare name would otherwise reach execve as an entry no libc can parse.
func mergeEnv(imageEnv []string, podEnv []*runtimev1.EnvVar) []string {
	out := make([]string, 0, len(imageEnv)+len(podEnv))
	at := make(map[string]int, len(imageEnv)+len(podEnv))
	for _, e := range imageEnv {
		name, _, ok := strings.Cut(e, "=")
		if !ok || name == "" {
			continue
		}
		if i, dup := at[name]; dup {
			out[i] = e
			continue
		}
		at[name] = len(out)
		out = append(out, e)
	}
	for _, e := range podEnv {
		name := e.GetName()
		if name == "" {
			continue
		}
		entry := name + "=" + e.GetValue()
		if i, ok := at[name]; ok {
			out[i] = entry
			continue
		}
		at[name] = len(out)
		out = append(out, entry)
	}
	return out
}

// envLookup indexes a merged "K=V" environment by name.
func envLookup(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, e := range env {
		if name, value, ok := strings.Cut(e, "="); ok {
			m[name] = value
		}
	}
	return m
}

// expandVars performs upstream's $(VAR) expansion over one string.
//
// The grammar is small and its edge cases are the whole point, so they are
// enumerated rather than inferred: "$$" is a literal "$"; "$(NAME)" is replaced
// when NAME is defined and left verbatim (including its parentheses) when it is
// not; a "$" that begins neither is itself, and an unterminated "$(" is itself
// through to the end of the string.
//
// Leaving an undefined reference verbatim rather than substituting an empty
// string is upstream's choice and it is the safe one: a container whose argv
// carries a shell snippet must not have that snippet silently emptied by a
// runtime that does not know what it means.
func expandVars(s string, lookup map[string]string) string {
	if !strings.Contains(s, "$") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '$' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if i+1 < len(s) && s[i+1] == '$' {
			b.WriteByte('$')
			i += 2
			continue
		}
		if i+1 < len(s) && s[i+1] == '(' {
			end := strings.IndexByte(s[i+2:], ')')
			if end >= 0 {
				name := s[i+2 : i+2+end]
				if v, ok := lookup[name]; ok {
					b.WriteString(v)
				} else {
					b.WriteString(s[i : i+3+end])
				}
				i += 3 + end
				continue
			}
		}
		b.WriteByte('$')
		i++
	}
	return b.String()
}

// IsHostPathReference reports whether an image reference is the absolute-HOST-PATH
// convention rather than an OCI reference — the discriminator that decides
// whether a container is a host binary run in place or an image to pull, unpack
// and merge (apis runtime/v1 Container.command).
//
// The two cases are disjoint BY construction and that is why the discriminator
// is a property of the value rather than a mode a caller must remember to set:
// an OCI reference cannot begin with '/'. A registry host is a DNS name, a
// repository path never leads with a separator, and both grammars reject an
// empty first component — so no reference a registry will serve is ever
// mistaken for a path, and no absolute path is ever mistaken for a reference.
//
// It tests the SLASH, not filepath.IsAbs, deliberately: the convention is about
// the shape of a string the provider stamped, and it must classify identically
// on every GOOS this package is compiled for, including the linux cross-build
// lane. On darwin the two agree.
func IsHostPathReference(ref string) bool { return strings.HasPrefix(ref, "/") }
