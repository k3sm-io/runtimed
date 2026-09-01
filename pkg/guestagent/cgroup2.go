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

package guestagent

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrCgroupFieldAbsent reports that a cgroup2 file did not carry the field the
// caller asked for.
//
// It is a distinct error rather than a zero value because ABSENCE and zero are
// different FACTS and the metering surface must not confuse them: a zero working
// set is indistinguishable from an idle container, so a container whose sample
// could not be read is omitted from the response (guest.proto says so of the
// response itself) rather than reported as zeros.
var ErrCgroupFieldAbsent = errors.New("guestagent: field absent from the cgroup2 file")

// ParseKeyedUint reads a `key value` line-oriented cgroup2 file (cpu.stat,
// memory.stat, io.stat's flat cousins) and returns the value for field.
//
// The format is fixed by the kernel: whitespace-separated key and decimal value,
// one pair per line. Parsing it here — rather than in the linux executor — is what
// makes it testable: these parsers are the only place a mis-read turns into a
// wrong number in `kubectl top`, and a parser that only exists in a linux-only
// file is a parser no darwin test can reach.
//
// Unknown lines are skipped, not rejected: the kernel adds counters over time, and
// an agent that refused to read cpu.stat because a newer kernel added a field
// would report nothing at all rather than the field it came for.
func ParseKeyedUint(content, field string) (uint64, error) {
	for _, line := range strings.Split(content, "\n") {
		key, rest, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || key != field {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(rest), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("cgroup2 field %q: %w", field, err)
		}
		return v, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrCgroupFieldAbsent, field)
}

// ParseSingleUint reads a cgroup2 file whose whole content is one decimal number
// (memory.current, pids.current).
//
// The literal "max" is reported as ErrCgroupFieldAbsent rather than as a number:
// it appears in the LIMIT files (memory.max), means "no limit", and mapping it to
// any integer — 0 or MaxUint64 — would be a lie in one direction or the other.
func ParseSingleUint(content string) (uint64, error) {
	s := strings.TrimSpace(content)
	if s == "" {
		return 0, fmt.Errorf("%w: the file is empty", ErrCgroupFieldAbsent)
	}
	if s == "max" {
		return 0, fmt.Errorf("%w: the value is \"max\" (no limit), which is not a number", ErrCgroupFieldAbsent)
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("cgroup2 single value: %w", err)
	}
	return v, nil
}

// CPUUsageUsec extracts the cumulative CPU time in MICROSECONDS from a cpu.stat
// file's content — the `usage_usec` counter guest/v1's
// GuestContainerStats.cpu_usage_usec carries verbatim.
func CPUUsageUsec(cpuStat string) (uint64, error) {
	return ParseKeyedUint(cpuStat, "usage_usec")
}

// WorkingSet computes the working set from memory.current and memory.stat, as
// `current - inactive_file`, saturating at zero.
//
// that SUBTRACTION IS the DEFINITION, not an approximation. It is what the kubelet
// reports as working-set bytes, and memory.current alone is not: page cache is
// charged to a cgroup, so a container that has merely READ a large file would
// otherwise appear to be holding all of it live — and would be the one an operator
// blames for the node's memory pressure, and the one a VPA would size up.
//
// Saturation matters because the two numbers are read from two files at two
// instants. A guest that faulted pages in between them can legitimately produce
// inactive_file > current, and an unsigned subtraction there wraps to an enormous
// working set: a metering surface that reports 16 exabytes for a container is worse
// than one that reports zero.
func WorkingSet(memoryCurrent, memoryStat string) (uint64, error) {
	current, err := ParseSingleUint(memoryCurrent)
	if err != nil {
		return 0, fmt.Errorf("memory.current: %w", err)
	}
	inactiveFile, err := ParseKeyedUint(memoryStat, "inactive_file")
	if err != nil {
		// A memory.stat with no inactive_file line is a kernel this code does not
		// know, not a container using no page cache. Reporting memory.current
		// would overstate the working set by exactly the amount that field exists
		// to remove, so the honest answer is that there is no sample.
		return 0, fmt.Errorf("memory.stat: %w", err)
	}
	if inactiveFile >= current {
		return 0, nil
	}
	return current - inactiveFile, nil
}
