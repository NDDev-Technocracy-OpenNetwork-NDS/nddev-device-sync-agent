---
status: accepted
date: '2026-10-22'
adaptation:
  standard:
    id: std-0001
  rules:
  - R-0018
  paths:
  - .config
  - module.yaml
  - standarts.lock
  reason: NDS system ADR 0013 (accepted owner direction) keeps NDS-owned material at fixed top-level locations
    in member repositories.
  result: '`.config`: Pinned nextest CI profile configuration owned by the repository. `module.yaml`:
    NDS module descriptor owned by the product standards corpus. `standarts.lock`: NDS contract lock pinning
    the standards source.'
  verification: Review against the NDS root ADR 0013; the root catalog check validates NDS descriptors
    and locks, and the repository's own checks exercise the remaining paths.
---
# NDS contract locations

The owner accepted NDS system [ADR 0013](https://github.com/NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync/blob/main/standarts/decisions/0013-estate-hygiene-and-standards-adoption.md). It keeps NDS-owned material at
deliberate top-level locations in member repositories. This record scopes
that decision to this repository under std-0001 R-0037 and replaces the
earlier manifest variations without changing them.

- `.config` (tool-config): Pinned nextest CI profile configuration owned by the repository.
- `module.yaml` (manifest): NDS module descriptor owned by the product standards corpus.
- `standarts.lock` (lock): NDS contract lock pinning the standards source.
