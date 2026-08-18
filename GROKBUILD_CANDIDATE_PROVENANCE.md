# GrokBuild candidate provenance

This fork retains the official xAI repository as the fetch-only `origin` and
publishes Jimmy-owned work only through `personal`. The local repository must
set `origin`'s push URL to the unsupported `no_push://xai-org/grok-build`
sentinel. That policy is intentionally local Git configuration, not source.

`tools/grokbuild-candidate/build_candidate.sh` builds the pinned Rust 1.94.0
`xai-grok-pager-bin` package with the hardened `release-dist` profile **and**
the separate `release-dist` feature. Before building, it performs a package-
and-profile-scoped clean so a new Git commit cannot reuse an older pager build
whose embedded `VERSION_WITH_COMMIT` came from a stale Cargo build-script
result. It refuses a dirty source tree and the common ambient variables that
can silently replace the compiled build string or compiler flags. System Git
and Python are absolute macOS paths; Rust 1.94.0 and DotSlash 0.5.7 are resolved
from approved installation roots rooted at the current account record rather
than ambient `PATH`, `HOME`, `CARGO_HOME`, or `RUSTUP_HOME`. The build executes
under a minimal allowlisted environment with system tools ahead of the exact
DotSlash directory; user Cargo config is refused instead of silently changing
the build. Cargo incremental compilation is hard-disabled even though the
upstream `release-dist` profile inherits `incremental = true`; the canonical
environment receipt records that invariant. DotSlash remains
part of the recorded toolchain because the pinned `bin/protoc` shim invokes it
during code generation. Cargo reaches the
repository's ignored `target` directory
through an owner-private no-space cache symlink, because jemalloc's configure
script refuses a prefix containing spaces. This avoids both the bad prefix and
a second multi-gigabyte build cache. The artifact is staged outside the
repository; it is never installed and never shadows the official CLI.

The candidate `--version` probe runs with a disposable owner-private `HOME` and
`GROK_HOME`; it never consults Jimmy's live Grok state. Output components are
physical, owner-private directories, the candidate leaf may not be a symlink,
and the manifest is published atomically without replacing an existing file.

The generated schema-v1 manifest is deterministic and credential-free. It
binds the official 1.0.5 base, upstream replay base, full fork source, lockfile,
toolchain versions and executable digests, exact pre-build clean and build
commands, the canonical placeholder-based build environment, binary
digest/size/architecture,
`VERSION_WITH_COMMIT`, ACP `cliBuild`, and the observed code-signing state. It
contains no timestamp or absolute artifact path, so two independent inspections
of the same candidate are byte-identical. `SOURCE_REV` is opened without
following links, bounded to 128 bytes, and required to contain exactly one full
Git SHA before it can enter the receipt.

Run the noninstalling candidate build from a clean committed head:

```sh
tools/grokbuild-candidate/build_candidate.sh \
  "$HOME/Documents/Codex/GrokBuild-Slice4B0/candidates"
```

The 4B.0 artifact is expected to report `unsigned` or `adHoc`; neither is a
trusted signing identity. A later slice must require
strict signing, Team Identifier `DD2GCQJVB4`, and the exact designated
requirement before the app may select a candidate. An unsigned or ad-hoc
staging artifact is not an armable runtime. Byte reproducibility is accepted
only when two package/profile-clean builds from the same committed worktree,
target root, and macOS host produce identical binary and manifest digests.
This receipt does not claim cross-host reproducibility: schema v1 does not bind
the Xcode SDK/linker, and the unstripped line-table debug data is path-sensitive.
This candidate also advertises hard-budget capability v3 and ledger v4 after
the conservative provider-usage settlement repair. The currently merged app
accepts capability v2 only, so it intentionally rejects this candidate until
the paired 4B.1 runtime-selection contract is versioned and merged.
