# Changelog

User-visible changes, newest first.

## Unreleased

### Fixed

- A layer symlink is now checked against the tree it is written into, not only against its target
  string. A relative target may climb with `..` only before any other component (`a/../b` is
  refused), and a target that climbs is refused when the link's own parent path runs through an
  existing symlink. Before this, two links that were each contained as strings could compose into
  one that resolved above the unpacked tree.
