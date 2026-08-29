# Recovering a leaked pod process group (keep-and-warn)

What to do when the daemon logs an "orphaned pod process group leaked" warning
at startup and keeps warning on every subsequent restart. This is the
**keep-and-warn** outcome of the startup pod reap (`pkg/runtime/podreap.go`) —
a deliberate, bounded-safety trade, not a bug, and not something the daemon
will resolve on its own.

## How you got here

Every pod's container process group is spawned `POSIX_SPAWN_SETSID` (a session
leader) and durably recorded under `<root>/podreap/<podID>/<pgid>.json`
**before** the spawn is acknowledged. If the daemon dies without teardown — a
crash, `launchctl kickstart -k` — a still-running group reparents to launchd
instead of exiting, and its record survives on disk. Before serving the next
`CreatePod`, the new daemon instance reaps every record it finds against the
live process table.

The reap identifies a recorded group **only** by an exact-instance match: it
re-probes the group by pgid, and requires the group's **leader** member
(`Pid == pgid`) to report a kernel start time identical to the one recorded at
spawn. Three outcomes follow from that:

- leader present, start time matches → the group is provably ours → killed;
- leader present, start time differs (the kernel recycled the pgid to an
  unrelated process) → dropped, never signalled;
- **leader absent, but the group is non-empty (a grandchild keeps it alive)**
  → **keep-and-warn**.

The third case is what you're looking at. With the leader gone there is no
start time left to compare, so the reap can no longer *prove* the surviving
group is the one it recorded. It refuses to guess in either direction: it will
not kill (a recycled pgid can belong to an unrelated leader's children — that
would be a wrong-target root `SIGKILL`), and it will not drop the record
either (the leak is real and dropping the record would make it untraceable).
It keeps the record and warns instead.

## What the daemon did — and did not do

- **Kept** the on-disk record file. It is not removed.
- **Logged one line** the moment the decision was made, and will log the same
  line again on every future daemon start for as long as the record and the
  live group both persist:

  ```
  orphaned pod process group leaked: leader gone but group still alive via a descendant (kept, not killed; will re-warn each start)
  ```

  with structured fields `pod`, `container`, `pgid` identifying the record.
- **Did not signal the group.** No `SIGTERM`, no `SIGKILL`, nothing. The
  processes keep running exactly as they were.
- **Did not remove anything.** Whatever the surviving descendant(s) hold —
  memory, open ports, `lo0` bindings — stays held until someone acts.

## Triage

**1. Get the pgid, pod, and container from the log line**, or read the record
directly:

```
cat /var/lib/k3sm/podreap/<podID>/<pgid>.json
```

The record is `{"podId": "...", "container": "...", "pgid": N,
"startUnixNano": N}`. `startUnixNano` is the leader's kernel start time
recorded at spawn — convert it to a readable timestamp for the next step:

```
date -r $(( startUnixNano / 1000000000 ))
```

**2. List the live group** by pgid:

```
sudo ps -g <pgid> -o pid,ppid,pgid,lstart,state,command
```

- **Empty output** — the group is already gone; there's nothing left to kill.
  Skip to recovery branch (b) below and just clear the record.
- **A member with `PID == PGID`** is present — the group now has a leader
  again. This is no longer the keep-and-warn case: either it's a genuinely new
  process that reused the pgid (its `lstart` will not match the record's
  converted timestamp), or the daemon simply hasn't reaped since the group
  changed. Either way, do not act by hand here — restart the daemon and let
  the reap's exact-identity check make the call (it will kill on a match, or
  silently drop the stale record on a mismatch).
- **No `PID == PGID` member** (the expected keep-and-warn shape) — every
  surviving process is a descendant of the original leader, which has exited.
  This is the group you're deciding about below.

**3. Distinguish a real leak from pgid reuse.** A pgid is a small, reused
kernel identifier — after the original leader exits, nothing stops some
unrelated later process from being assigned the same number as *its own*
session leader, at which point `ps -g <pgid>` would show a plausible-looking
but entirely unrelated process tree. This is exactly why the reap itself
refuses to guess. Cross-check by hand:

- Does the `command` column look like the container's actual entrypoint /
  image, or like something unrelated (a shell, an editor, a completely
  different tool)?
- Does the group's `lstart` (or, better, the record's own `startUnixNano`
  converted per step 1, compared against how long ago the pod was created)
  line up with when this pod would plausibly still be running, or does it
  look freshly started — i.e. after the daemon's last restart, which a real
  leaked leftover cannot be?
- Does `<root>/pods/<podID>/` still exist? Pod teardown (`DeletePod`) removes
  a pod's reap records **after** signalling its groups, so a record that
  outlived its pod directory strongly suggests the group was never cleanly
  torn down — a real leak, not a coincidence.

If any of these disagree with "this is the pod's own leftover work," treat it
as pgid reuse and use recovery branch (b).

## Recovery

### (a) It IS a leaked pod — kill the group, then clear the record

```
sudo kill -KILL -<pgid>
```

The leading `-` is required — it signals the **process group**, not a single
pid. Killing only the descendant's pid (see "What not to do" below) leaves
the rest of the group running.

Then remove the now-stale record so the daemon stops re-warning about a group
that no longer exists:

```
sudo rm /var/lib/k3sm/podreap/<podID>/<pgid>.json
```

If the record's parent directory (`<root>/podreap/<podID>/`) is now empty,
you may remove it too, but this is cosmetic — an empty directory does not
produce further warnings.

On the next daemon start, `ps -g <pgid>` will find nothing, the record is
already gone, and there is nothing left to reap for that pgid.

### (b) It is NOT a pod — pgid reuse, nothing to kill

Do not signal anything — the live process(es) at that pgid belong to
something else entirely, and a group signal would kill an unrelated
workload. Remove only the stale record:

```
sudo rm /var/lib/k3sm/podreap/<podID>/<pgid>.json
```

The daemon will stop warning about this pgid on its next start. If it should
be reaping something at that pgid, the reaper's own exact-identity check
already decided it is not the same instance — that is `drop`, not
keep-and-warn, and needs no manual help.

## What NOT to do

- **`kill -9 <pid>` on a single descendant pid, instead of `kill -KILL
  -<pgid>` on the whole group.** This kills one process and leaves the rest
  of the group (and anything it forked) running — you'll be back here on the
  next restart with the same warning, possibly against a different
  descendant.
- **Deleting a reap record for a group that is still genuinely live and still
  the daemon's own pod.** The record is the only durable trace of that group;
  removing it while the group is real just makes the leak untraceable instead
  of fixing it. Confirm with the triage steps above before removing anything.
- **Running the daemon as root, or otherwise trying to make the reap "just
  kill it," to force past keep-and-warn.** The refusal is not a privilege
  problem — the reap has the privilege to signal the group already. It
  refuses because it cannot *prove* the group is still the one it recorded,
  and a recycled pgid can belong to an unrelated process tree. Loosening the
  exact-identity check to make this case auto-resolve reopens the wrong-target
  kill this design exists to prevent.

## Beyond this runbook

Automatically reclaiming a genuinely leaked group on daemon restart —
re-adopting it into the running pod set instead of leaving it to either this
manual procedure or an eventual kill — is tracked follow-up work, not
something the current daemon does. Until it ships, keep-and-warn plus this
runbook is the complete recovery path.
