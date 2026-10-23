#!/usr/bin/env bash
#
# runtimed B494 acceptance gate: the wasm spike's results table is complete,
# well formed, and every evidence digest it cites re-hashes to the committed
# evidence file.
#
# The spike answers twelve questions, rows (a) through (l), before the wasm
# RuntimeClass build starts. Its results are recorded as a markdown table, the
# results table, under a "## Spike questions" heading, one row per question:
#
#   | # | question (abbreviated) | answer | evidence sha256 | reason/notes |
#
# This gate reads that table and is RED when:
#   - the heading or the table is missing, or the table has no rows;
#   - the header is not exactly the five cells above, in that order, or a
#     data row does not have exactly five cells;
#   - any of the rows (a)..(l) is missing, or one appears twice, or an
#     unknown row is present;
#   - an answer is not exactly PASS, FAIL or N/A (so "pending" is red);
#   - an N/A row carries no reason;
#   - an evidence cell is not 64 lowercase hex digits, or is the sha256 of
#     the empty file;
#   - row (a) is FAIL on WASI_HTTP, or its evidence says WASI_HTTP: ABSENT
#     whatever the verdict: that is a HARD STOP for the wasi:http bindings
#     (a source-built engine is out of scope), never a fallback;
#   - row (a) is PASS but its evidence lacks a "WASI_HTTP: present" marker;
#   - row (a) is FAIL and neither its note nor its evidence mentions
#     WASI_HTTP: the hard stop cannot be decided (a WARN line, still red);
#   - with an evidence directory: a row has no evidence file named
#     "<row>-*" in it (exactly one per row), or the file's sha256 differs
#     from the table's cell.
#
# A FAIL or N/A answer is a valid result and keeps the gate green: the gate
# checks that the question was answered honestly and traceably, not that the
# answer was the hoped-for one.
#
# Usage:
#   hack/acceptance/B494.sh --check --plan <plan.md> [--evidence <dir>]
#   hack/acceptance/B494.sh --record <row> <PASS|FAIL|N/A> <file> [notes...]
#   hack/acceptance/B494.sh --self-test
#
# --check with no --evidence re-hashes against the committed
# hack/acceptance/testdata/B494/evidence/ when that directory exists.
# --plan names the markdown file holding the results table (optional input:
# the committed fixtures under testdata/B494 need none); it may also come from
# B494_PLAN. --record prints one filled table row
# with the digest computed from <file>, so no cell is typed by hand.
#
# Exit: 0 green, 1 red, 2 usage.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SELF="$HERE/B494.sh"
TESTDATA="$HERE/testdata/B494"
EMPTY_SHA="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ROWS="a b c d e f g h i j k l"

usage() {
	sed -n '/^# Usage:/,/^# Exit:/p' "$SELF" | sed 's/^# \{0,1\}//' >&2
	exit 2
}

question() {
	case "$1" in
	a) echo "libwasmtime.a features (WASI, WASI_HTTP) and its provenance digest" ;;
	b) echo "WASI p1 hello: exit code and stdout in the crilog file" ;;
	c) echo "wasi:http incoming-handler on a post-sandbox pod-IP listener" ;;
	d) echo "Cranelift under Seatbelt, ad-hoc and -o runtime signed" ;;
	e) echo "footprint (compile+load peak, steady), cold start, binary size" ;;
	f) echo "StoreLimits above the pod limit: the sampler OOMKills first" ;;
	g) echo "a wasi/wasm32 OCI image through the existing Puller" ;;
	h) echo "SIGTERM within the grace period; traps with Go handlers installed" ;;
	i) echo "WasiConfig p1 sock_accept listener preopen" ;;
	j) echo "the engine in-process under -race on darwin/arm64" ;;
	k) echo "raw cosign signature fetch per transport; payload digest; format" ;;
	l) echo "offline stdlib verification and its distinct error classes" ;;
	*) return 1 ;;
	esac
}

sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }

# extract_rows <plan> prints "<row>\t<answer>\t<sha>\t<notes>" per table row,
# or "!<reason>" lines for structural problems. The table is the first run of
# "|"-lines after the "## Spike questions" heading and before the next "## ".
extract_rows() {
	awk '
	function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
	/^## Spike questions/ { insec = 1; seen = 1; next }
	insec && /^## / { insec = 0 }
	insec && /^\|/ { intab = 1; lines[++n] = $0; next }
	insec && intab && !/^\|/ { insec = 0 }
	END {
		if (!seen) { print "!no \"## Spike questions\" heading"; exit }
		if (n < 2) { print "!no table under \"## Spike questions\""; exit }
		hdr = lines[1]; gsub(/\\\|/, "\001", hdr)
		nh = split(hdr, h, "|")
		want[1] = "#"; want[2] = "question (abbreviated)"; want[3] = "answer"
		want[4] = "evidence sha256"; want[5] = "reason/notes"
		if (nh != 7 || trim(h[1]) != "" || trim(h[7]) != "") {
			printf "!table header has %d cells, want exactly 5: | # | question (abbreviated) | answer | evidence sha256 | reason/notes |\n", nh - 2
			exit
		}
		for (i = 1; i <= 5; i++) {
			if (tolower(trim(h[i + 1])) != want[i]) {
				printf "!table header cell %d is \"%s\", want \"%s\"\n", i, trim(h[i + 1]), want[i]
				exit
			}
		}
		if (n < 3) { print "!table has no rows"; exit }
		for (r = 3; r <= n; r++) {
			line = lines[r]; gsub(/\\\|/, "\001", line)
			nc = split(line, c, "|")
			if (nc != 7 || trim(c[1]) != "" || trim(c[7]) != "") {
				printf "!table row %d has %d cells, want exactly 5: %s\n", r - 2, nc - 2, substr(lines[r], 1, 60)
				continue
			}
			id = trim(c[2]); ans = trim(c[4])
			sha = trim(c[5]); gsub(/`/, "", sha)
			note = trim(c[6]); gsub(/\001/, "|", note)
			if (id ~ /^\([a-z]\)$/) id = substr(id, 2, 1)
			printf "%s\t%s\t%s\t%s\n", id, ans, sha, note
		}
	}' "$1"
}

# check <plan> <evidence-dir|""> ; prints findings, returns 0 green / 1 red.
check() {
	local plan="$1" evdir="$2" red=0 hard=0 line id ans sha note seen=" "
	[ -f "$plan" ] || { echo "RED  plan not found: $plan"; return 1; }
	local out
	out="$(extract_rows "$plan")"
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		if [ "${line#!}" != "$line" ]; then
			echo "RED  ${line#!}"; red=1; continue
		fi
		IFS=$'\t' read -r id ans sha note <<<"$line"
		if ! question "$id" >/dev/null 2>&1; then
			echo "RED  unknown row '$id'"; red=1; continue
		fi
		case "$seen" in *" $id "*) echo "RED  row ($id) appears more than once"; red=1; continue ;; esac
		seen="$seen$id "
		case "$ans" in
		PASS | FAIL | N/A) ;;
		*) echo "RED  row ($id): answer '$ans' is not PASS, FAIL or N/A"; red=1 ;;
		esac
		if [ "$ans" = "N/A" ] && { [ -z "$note" ] || [ "$note" = "-" ]; }; then
			echo "RED  row ($id): N/A without a reason"; red=1
		fi
		if ! [[ "$sha" =~ ^[0-9a-f]{64}$ ]]; then
			echo "RED  row ($id): evidence sha256 '$sha' is not 64 lowercase hex digits"; red=1
		elif [ "$sha" = "$EMPTY_SHA" ]; then
			echo "RED  row ($id): evidence sha256 is the empty file's digest"; red=1
		fi
		if [ "$id" = a ]; then
			# The WASI_HTTP cross-check runs whatever the verdict says: the
			# evidence decides, so a PASS cannot hide an absent feature.
			local wh_absent=0 wh_present=0 wh_note=0 af
			case "$note" in *WASI_HTTP*) wh_note=1 ;; esac
			if [ -n "$evdir" ]; then
				for af in "$evdir"/a-*; do
					[ -f "$af" ] || continue
					grep -q 'WASI_HTTP: ABSENT' "$af" && wh_absent=1
					grep -q 'WASI_HTTP: present' "$af" && wh_present=1
				done
				if [ "$ans" = PASS ] && [ "$wh_absent" = 1 ]; then
					echo "RED  row (a): PASS, but its evidence says WASI_HTTP: ABSENT"; red=1
				elif [ "$ans" = PASS ] && [ "$wh_present" = 0 ]; then
					echo "RED  row (a): PASS, but its evidence carries no 'WASI_HTTP: present' marker"; red=1
				fi
			fi
			if [ "$ans" = FAIL ] || [ "$wh_absent" = 1 ]; then
				red=1
				if [ "$wh_note" = 1 ] || [ "$wh_absent" = 1 ]; then
					echo "RED  HARD STOP: row (a) fails on WASI_HTTP; the wasi:http bindings need a new design, never an in-gate source build"
					hard=1
				else
					echo "WARN row (a) is FAIL and neither its note nor its evidence ties the failure to WASI_HTTP: the hard stop could not be decided"
					echo "RED  row (a): FAIL with an undecidable WASI_HTTP hard stop"
				fi
			fi
		fi
		if [ -n "$evdir" ] && [[ "$sha" =~ ^[0-9a-f]{64}$ ]]; then
			local files=() f
			for f in "$evdir/$id"-*; do [ -f "$f" ] && files+=("$f"); done
			if [ "${#files[@]}" -ne 1 ]; then
				echo "RED  row ($id): want exactly one evidence file '$id-*' in $evdir, found ${#files[@]}"; red=1
			else
				local got
				got="$(sha256_of "${files[0]}")"
				if [ "$got" != "$sha" ]; then
					echo "RED  row ($id): $(basename "${files[0]}") hashes to $got, the table says $sha"; red=1
				fi
			fi
		fi
	done <<<"$out"
	local r
	for r in $ROWS; do
		case "$seen" in *" $r "*) ;; *) case "$out" in "!"*) ;; *) echo "RED  row ($r) is missing"; red=1 ;; esac ;; esac
	done
	if [ "$red" = 0 ]; then
		echo "GREEN  rows (a)..(l) answered, digests well formed${evdir:+, evidence re-hashed from $evdir}"
	elif [ "$hard" = 1 ]; then
		echo "HARD STOP"
	fi
	return "$red"
}

record() {
	[ $# -ge 3 ] || usage
	local row="$1" verdict="$2" file="$3" q sha notes
	shift 3
	q="$(question "$row")" || { echo "B494: unknown row '$row'" >&2; exit 2; }
	case "$verdict" in PASS | FAIL | N/A) ;; *) echo "B494: verdict must be PASS, FAIL or N/A" >&2; exit 2 ;; esac
	[ -s "$file" ] || { echo "B494: evidence file '$file' is missing or empty" >&2; exit 2; }
	sha="$(sha256_of "$file")"
	notes="$*"
	notes="${notes//|/\\|}"
	printf '| (%s) | %s | %s | %s | %s |\n' "$row" "$q" "$verdict" "$sha" "$notes"
}

self_test() {
	local fails=0 name want got
	expect() {
		want="$1"; name="$2"; shift 2
		set +e
		"$@" >"$TMP/out" 2>&1
		got=$?
		set -e
		if [ "$got" = "$want" ]; then
			echo "ok    $name (exit $got)"
		else
			echo "FAIL  $name: exit $got, want $want"; sed 's/^/      /' "$TMP/out"; fails=$((fails + 1))
		fi
	}
	TMP="$(mktemp -d)"
	trap 'rm -rf "$TMP"' RETURN
	local st="$TESTDATA/selftest" ev="$TESTDATA/selftest/evidence"
	expect 0 "green fixture, evidence re-hashed" "$SELF" --check --plan "$st/green.md" --evidence "$ev"
	expect 1 "empty table" "$SELF" --check --plan "$st/red-empty.md" --evidence "$ev"
	expect 1 "a pending row" "$SELF" --check --plan "$st/red-pending.md" --evidence "$ev"
	expect 1 "a missing row" "$SELF" --check --plan "$st/red-missing.md" --evidence "$ev"
	expect 1 "a duplicated row" "$SELF" --check --plan "$st/red-duplicate.md" --evidence "$ev"
	expect 1 "a malformed digest" "$SELF" --check --plan "$st/red-baddigest.md" --evidence "$ev"
	expect 1 "the empty-file digest" "$SELF" --check --plan "$st/red-emptydigest.md" --evidence "$ev"
	expect 1 "a verdict outside PASS|FAIL|N/A" "$SELF" --check --plan "$st/red-badverdict.md" --evidence "$ev"
	expect 1 "N/A without a reason" "$SELF" --check --plan "$st/red-na-noreason.md" --evidence "$ev"
	expect 1 "a digest that does not match its evidence" "$SELF" --check --plan "$st/red-mismatch.md" --evidence "$ev"
	expect 1 "row (a) FAIL on WASI_HTTP" "$SELF" --check --plan "$st/red-wasihttp.md" --evidence "$ev"
	if ! grep -q "HARD STOP" "$TMP/out"; then
		echo "FAIL  row (a) FAIL on WASI_HTTP did not print HARD STOP"; fails=$((fails + 1))
	fi
	expect 1 "row (a) PASS whose evidence says WASI_HTTP: ABSENT" "$SELF" --check --plan "$st/red-a-absent.md" --evidence "$st/evidence-a-absent"
	if ! grep -q "HARD STOP" "$TMP/out"; then
		echo "FAIL  row (a) PASS with WASI_HTTP: ABSENT did not print HARD STOP"; fails=$((fails + 1))
	fi
	expect 1 "row (a) PASS without a WASI_HTTP: present marker" "$SELF" --check --plan "$st/red-a-nomarker.md" --evidence "$st/evidence-a-nomarker"
	expect 1 "row (a) FAIL with no WASI_HTTP mention (undecidable)" "$SELF" --check --plan "$st/red-a-undecided.md" --evidence "$ev"
	if ! grep -q "^WARN row (a) is FAIL" "$TMP/out" || grep -q "HARD STOP" "$TMP/out"; then
		echo "FAIL  undecidable row (a) FAIL did not print the WARN line (or wrongly printed HARD STOP)"; fails=$((fails + 1))
	fi
	expect 1 "a header that is not the five documented cells" "$SELF" --check --plan "$st/red-header-columns.md" --evidence "$ev"
	expect 1 "a data row with six cells" "$SELF" --check --plan "$st/red-row-columns.md" --evidence "$ev"
	expect 1 "no Spike questions heading" "$SELF" --check --plan "$st/red-noheading.md"
	expect 2 "--check without --plan" env -u B494_PLAN "$SELF" --check
	expect 2 "unknown flag" "$SELF" --bogus
	# --record round trip: a row it prints for a fixture file carries that file's digest.
	expect 0 "--record prints a row" "$SELF" --record b PASS "$ev/b-selftest.txt" "a note | with a pipe"
	if ! grep -q "| (b) | .* | PASS | $(sha256_of "$ev/b-selftest.txt") | a note \\\\| with a pipe |" "$TMP/out"; then
		echo "FAIL  --record row shape"; sed 's/^/      /' "$TMP/out"; fails=$((fails + 1))
	fi
	expect 2 "--record with an empty file" "$SELF" --record b PASS /dev/null
	if [ "$fails" = 0 ]; then echo "self-test: GREEN"; else echo "self-test: $fails FAILED"; fi
	[ "$fails" = 0 ]
}

[ $# -ge 1 ] || usage
case "$1" in
--self-test)
	self_test
	;;
--record)
	shift
	record "$@"
	;;
--check)
	shift
	plan="${B494_PLAN:-}" evdir=""
	while [ $# -gt 0 ]; do
		case "$1" in
		--plan) [ $# -ge 2 ] || usage; plan="$2"; shift 2 ;;
		--evidence) [ $# -ge 2 ] || usage; evdir="$2"; shift 2 ;;
		*) usage ;;
		esac
	done
	[ -n "$plan" ] || usage
	if [ -z "$evdir" ] && [ -d "$TESTDATA/evidence" ] && compgen -G "$TESTDATA/evidence/?-*" >/dev/null; then
		evdir="$TESTDATA/evidence"
	fi
	[ -z "$evdir" ] || [ -d "$evdir" ] || { echo "B494: evidence dir not found: $evdir" >&2; exit 2; }
	echo "==> runtimed B494 spike results gate ($plan)"
	check "$plan" "$evdir"
	;;
*)
	usage
	;;
esac
