# Guest-kernel signing keys

The two ASCII-armored public keys `../build.sh` verifies the kernel source
with, one file per key, named by its full fingerprint:

| File | Key | Pinned as |
|---|---|---|
| `B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1.asc` | Kernel.org checksum autosigner (signs `sha256sums.asc`) | `KERNEL_KEY_FPR` |
| `647F28654894E3BD457199BE38DBBDC86092693E.asc` | Greg Kroah-Hartman, stable-release key (signs `linux-*.tar.sign`) | `KERNEL_DEV_KEY_FPR` |

## What these files are

- **The fingerprint constants in `build.sh` are the only trust anchors.** These
  files are caches of the bytes those fingerprints name. Every import, on the
  host and inside the toolchain pod, asserts that the keyring then holds exactly
  one primary key and that it is the pinned fingerprint, and the build dies
  otherwise. A file that fails the assertion fails the build; nothing falls back
  to a keyserver.
- **The files are machine-minted. Never edit them by hand.** They are written
  only by `hack/guest-kernel/build.sh --refresh-keys`, which fetches each key
  from a keyserver, asserts its fingerprint, and exports it with
  `--export-options export-clean`.
- `--refresh-keys` is the only code path in the recipe that talks to a keyserver.

## Refreshing a key (same fingerprint)

Do this when a key's self-signatures change, for example an extended expiry.

1. Run `hack/guest-kernel/build.sh --refresh-keys`.
2. Review the diff under `keys/`. The fingerprint is unchanged, so the change
   is new signature packets on the same key.
3. Commit the refreshed file.

## Rotating a key (new fingerprint)

Do this when kernel.org replaces a signing key.

1. Re-derive the new fingerprint independently of any keyserver, from
   kernel.org's signature page (<https://www.kernel.org/signature.html>). For
   the autosigner, confirm it against the issuer gpg reports for a current
   `sha256sums.asc`.
2. Change the constant in `build.sh`. **The reviewed act is that change**; the
   key file follows from it.
3. Run `hack/guest-kernel/build.sh --refresh-keys` to mint the new file, delete
   the file named by the old fingerprint, and commit all three changes
   together.
4. Run `hack/acceptance/B392.sh`.
