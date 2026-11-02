#!/usr/bin/env bash
# Sourced by hack/ci.sh (and exercised by hack/acceptance/staticcheck_pick_test.go).
# Defines staticcheck_pick, the lookup of the pinned staticcheck binary.
#
# Inputs: STATICCHECK_VERSION (the pin). Sets: sc (the chosen binary).
# Candidates, in order: $(go env GOPATH)/bin/staticcheck-<pin> (the versioned
# name, so two pins can be installed side by side while the repos switch),
# then staticcheck on PATH, then $(go env GOPATH)/bin/staticcheck; the first
# reporting exactly the pin wins. Returns 1 with a named message otherwise.

staticcheck_pick() {
	local c v sc_seen="" sc_gopath sc_hint
	sc=""
	sc_gopath="$(go env GOPATH)"
	sc_hint="go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}; or, beside another pin: GOBIN=<tmp> go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION} && mv <tmp>/staticcheck ${sc_gopath}/bin/staticcheck-${STATICCHECK_VERSION}"
	for c in "${sc_gopath}/bin/staticcheck-${STATICCHECK_VERSION}" "$(command -v staticcheck 2>/dev/null || true)" "${sc_gopath}/bin/staticcheck"; do
		[ -n "$c" ] && [ -x "$c" ] || continue
		v="$("$c" -version 2>/dev/null | awk '{print $2}')" || v=""
		sc_seen="$sc_seen
  $c reports '${v:-unknown}'"
		if [ "$v" = "$STATICCHECK_VERSION" ]; then sc="$c"; break; fi
	done
	if [ -z "$sc" ]; then
		if [ -z "$sc_seen" ]; then
			echo "==> [runtimed] staticcheck: not installed; the gate needs ${STATICCHECK_VERSION} (${sc_hint})" >&2
		else
			echo "==> [runtimed] staticcheck: the gate needs ${STATICCHECK_VERSION}, found:${sc_seen}" >&2
			echo "    install it with: ${sc_hint}" >&2
		fi
		return 1
	fi
}
