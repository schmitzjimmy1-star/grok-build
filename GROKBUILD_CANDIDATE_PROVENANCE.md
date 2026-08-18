# GrokBuild candidate provenance

This fork retains the official xAI repository as the fetch-only `origin` and
publishes Jimmy-owned work only through `personal`. The local repository must
set `origin`'s push URL to the unsupported `no_push://xai-org/grok-build`
sentinel. That policy is intentionally local Git configuration, not source.

`tools/grokbuild-candidate/build_candidate.sh` builds the pinned Rust 1.94.0
`xai-grok-pager-bin` package with the hardened `release-dist` profile **and**
the separate `release-dist` feature. It refuses a dirty source tree and the
common ambient variables that can silently replace the compiled build string
or compiler flags. Cargo reaches the repository's ignored `target` directory
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
toolchain, exact build command, binary digest/size/architecture,
`VERSION_WITH_COMMIT`, ACP `cliBuild`, and the observed code-signing state. It
contains no timestamp or absolute artifact path, so two independent inspections
of the same candidate are byte-identical.

Run the noninstalling candidate build from a clean committed head:

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
tools/grokbuild-candidate/build_candidate.sh \
  "$HOME/Documents/Codex/GrokBuild-Slice4B0/candidates"
```

The 4B.0 artifact is expected to report `unsigned` or `adHoc`; neither is a
trusted signing identity. A later slice must require
strict signing, Team Identifier `DD2GCQJVB4`, and the exact designated
requirement before the app may select a candidate. An unsigned or ad-hoc
staging artifact is evidence of reproducible bytes, not an armable runtime.
