#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Gate for the artifact fetch path: a platform-less OCI artifact is fetched
# from the cluster registry into the node cache, every blob digest-verified,
# fail-closed on every rule, then viewed read-only as clones of its blobs, which
# stay GC roots while its record exists. Network-free: every test runs over a fake fetcher
# seam (and the image-path pin over an in-process loopback registry).
#
# --check runs the fetch-path, view and lifetime tests and requires each named
# test to have run and passed. A named test not built yet is listed as PENDING,
# and while any is pending --check exits 3, which is not a pass, even when every
# built test is green.
#
# Exit 0 pass, 1 fail, 2 usage, 3 PENDING: not a pass.
#
# Usage: hack/acceptance/B1368.sh --check
set -euo pipefail

GATE_NAME=B1368
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# package:test pairs that must run and pass.
BUILT=(
	"./pkg/artifact/:TestPullArtifactVerifiesEveryLayer"
	"./pkg/artifact/:TestPullArtifactRefusesTypeOutsideAllowSet"
	"./pkg/artifact/:TestPullArtifactRefusesLayerOutsideAllowSet"
	"./pkg/artifact/:TestPullArtifactRefusesImageConfig"
	"./pkg/artifact/:TestPullArtifactRefusesTarLayers"
	"./pkg/artifact/:TestPullArtifactRefusesBareIndex"
	"./pkg/artifact/:TestPullArtifactRefusesUnspecifiedPolicy"
	"./pkg/artifact/:TestPullArtifactArtifactTypeFallsBackToConfigMediaType"
	"./pkg/artifact/:TestPullArtifactRefusesForeignHostBeforeAnyRequest"
	"./pkg/artifact/:TestPullArtifactLayerCap"
	"./pkg/artifact/:TestPullArtifactManifestCap"
	"./pkg/artifact/:TestArtifactPathValidation"
	"./pkg/artifact/:TestPullArtifactSubsetPaths"
	"./pkg/artifact/:TestPullArtifactCommitsAndRecords"
	"./pkg/artifact/:TestPullArtifactRecordsOnlyAfterEveryLayer"
	"./pkg/artifact/:TestPullArtifactResumesWithRange"
	"./pkg/artifact/:TestPullArtifactResumesAcrossRestart"
	"./pkg/artifact/:TestPullArtifactRestartsWhenRangeIgnored"
	"./pkg/artifact/:TestPullArtifactAtMostTwoLayersAtOnce"
	"./pkg/artifact/:TestPullArtifactChecksSpaceBeforeFirstByte"
	"./pkg/artifact/:TestPullArtifactReservationCountsConcurrentPullsAndTemps"
	"./pkg/artifact/:TestPullArtifactRefusesHostileLayerSizes"
	"./pkg/artifact/:TestSpaceArithmeticRefusesOverflow"
	"./pkg/artifact/:TestPullArtifactBoundsErrorText"
	"./pkg/artifact/:TestRegistryFetcherManifestReadIsBounded"
	"./pkg/artifact/:TestRecordConcurrentSubsetsKeepEveryLayer"
	"./pkg/runtime/:TestImagePathStillRefusesArtifact"
	"./pkg/runtime/:TestImagesServiceServesOnlyCacheVerbs"
	"./pkg/runtime/:TestPullArtifactRPCServesThroughThePuller"
	"./pkg/runtime/:TestPullArtifactRPCRefusesSwappedByte"
	"./pkg/runtime/:TestPullArtifactRPCRefusals"
	"./pkg/runtime/:TestPullArtifactRefusedWithoutClusterRegistry"
	"./pkg/runtime/:TestPullArtifactRPCChecksHostBeforeCredentials"
	"./pkg/runtime/:TestPullArtifactRPCBoundsConcurrency"
	"./pkg/runtime/:TestPullArtifactRPCBoundsErrorText"
	"./pkg/artifact/:TestArtifactViewIsCloneNotLink"
	"./pkg/artifact/:TestArtifactViewRefusesCrossVolume"
	"./pkg/artifact/:TestArtifactViewKeyedByPathSet"
	"./pkg/artifact/:TestStaleViewStagingReapedAtStart"
	"./pkg/artifact/:TestArtifactPartialDirMustBeTheCacheChild"
	"./pkg/image/:TestPruneKeepsLiveArtifactReclaimsDeadOne"
	"./pkg/artifact/:TestArtifactViewCloneRefusesBeforeAnyCopy"
	"./pkg/artifact/:TestViewsRefuseOtherDeviceAtStart"
	"./pkg/artifact/:TestViewsDirsOwnedExactMode"
	"./pkg/artifact/:TestPruneSweepsViewsOfReplacedManifest"
	"./pkg/artifact/:TestForgetKeepsRecordRePutConcurrently"
	"./pkg/artifact/:TestStartupRemovesTamperedViews"
	"./pkg/image/:TestCloneOnlyClonesOrRefuses"
	"./pkg/image/:TestArtifactRecordsRefuseNonRegularJSON"
	"./pkg/image/:TestArtifactRootsNameCorruptRecord"
	"./pkg/runtime/:TestPruneImagesSweepsOrphanedArtifactViews"
)

# Named tests not built yet. Empty: every named test is in BUILT.
PENDING=()

check() {
	cd "$ROOT"
	local pkgs=() pkg name regex out fail=0
	for pair in "${BUILT[@]}"; do
		pkg="${pair%%:*}"
		case " ${pkgs[*]-} " in *" $pkg "*) ;; *) pkgs+=("$pkg") ;; esac
	done
	for pkg in "${pkgs[@]}"; do
		regex=""
		for pair in "${BUILT[@]}"; do
			[ "${pair%%:*}" = "$pkg" ] || continue
			name="${pair#*:}"
			regex="${regex:+$regex|}$name"
		done
		echo "$GATE_NAME: go test $pkg -run ^($regex)\$"
		if ! out="$(CGO_ENABLED=1 go test -count=1 -v -run "^($regex)\$" "$pkg" 2>&1)"; then
			printf '%s\n' "$out" | grep -E -- '^(--- FAIL|FAIL|panic)|_test.go' >&2 || true
			echo "$GATE_NAME: FAIL: $pkg" >&2
			fail=1
		fi
		for pair in "${BUILT[@]}"; do
			[ "${pair%%:*}" = "$pkg" ] || continue
			name="${pair#*:}"
			if ! printf '%s\n' "$out" | grep -q -- "^--- PASS: $name "; then
				echo "$GATE_NAME: FAIL: $name did not run and pass" >&2
				fail=1
			fi
		done
	done
	[ "$fail" -eq 0 ] || return 1
	echo "$GATE_NAME: ${#BUILT[@]} built tests pass"
	if [ "${#PENDING[@]}" -gt 0 ]; then
		for name in "${PENDING[@]}"; do
			echo "$GATE_NAME: PENDING: $name (not built yet)"
		done
		echo "$GATE_NAME: PENDING: not a pass"
		return 3
	fi
	echo "$GATE_NAME: PASS"
}

case "${1-}" in
--check) check ;;
*) echo "usage: $0 --check" >&2; exit 2 ;;
esac
