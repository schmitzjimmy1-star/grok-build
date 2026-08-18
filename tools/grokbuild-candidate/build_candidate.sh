#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  print -u2 "usage: $0 <owner-private-output-directory>"
  exit 64
fi

git_bin="/usr/bin/git"
python_bin="/usr/bin/python3"
account_home="$("$python_bin" -c 'import os, pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')"
export HOME="$account_home"
unset CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN
repo_root="$("$git_bin" rev-parse --show-toplevel)"
output_root="$1"
official_base="9fabadea800fa6e2ed8ec91c4f45f02b7e2504f4"
replay_base="d71f6e0c1f5acc5469e503e192fe14824e6f8c90"
tool="$repo_root/tools/grokbuild-candidate/candidate_provenance.py"

cargo_bin="$("$python_bin" "$tool" resolve-tool --name cargo)"
rustc_bin="$("$python_bin" "$tool" resolve-tool --name rustc)"
dotslash_bin="$("$python_bin" "$tool" resolve-tool --name dotslash)"
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:${dotslash_bin:h}"
export RUSTC="$rustc_bin"

[[ -z "$("$git_bin" -C "$repo_root" status --porcelain=v1)" ]] || {
  print -u2 "candidate build refused: source worktree is dirty"
  exit 2
}

for name in GROK_VERSION RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER; do
  if (( ${+parameters[$name]} )) && [[ -n "${(P)name}" ]]; then
    print -u2 "candidate build refused: build-affecting environment variable is set: $name"
    exit 2
  fi
done

for cargo_config in "$HOME/.cargo/config" "$HOME/.cargo/config.toml"; do
  [[ ! -e "$cargo_config" && ! -L "$cargo_config" ]] || {
    print -u2 "candidate build refused: user Cargo configuration is not allowed: $cargo_config"
    exit 2
  }
done

"$python_bin" "$tool" prepare-directory --directory "$output_root"

if [[ -n "${GROKBUILD_CARGO_TARGET_DIR:-}" ]]; then
  cargo_target_root="$GROKBUILD_CARGO_TARGET_DIR"
  [[ "$cargo_target_root" != *" "* ]] || {
    print -u2 "candidate build refused: Cargo target path contains spaces"
    exit 2
  }
  "$python_bin" "$tool" prepare-directory --directory "$cargo_target_root"
else
  cache_parent="$HOME/Library/Caches/GrokBuild"
  cargo_target_root="$cache_parent/cli-candidate-target"
  repo_target="$repo_root/target"
  "$python_bin" "$tool" prepare-directory --directory "$cache_parent"
  "$python_bin" "$tool" prepare-directory --directory "$repo_target"
  if [[ ! -e "$cargo_target_root" && ! -L "$cargo_target_root" ]]; then
    /bin/ln -s "$repo_target" "$cargo_target_root"
  fi
  [[ -L "$cargo_target_root" && "${cargo_target_root:A}" == "${repo_target:A}" ]] || {
    print -u2 "candidate build refused: default Cargo cache is not the expected no-space symlink"
    exit 2
  }
fi

cd "$repo_root"
cargo_environment=(
  /usr/bin/env -i
  "HOME=$HOME"
  "PATH=$PATH"
  "LANG=C"
  "LC_ALL=C"
  "TMPDIR=/private/tmp"
  "CARGO_HOME=$HOME/.cargo"
  "RUSTUP_HOME=$HOME/.rustup"
  "RUSTC=$rustc_bin"
  "CARGO_TARGET_DIR=$cargo_target_root"
  "CARGO_INCREMENTAL=0"
)
"${cargo_environment[@]}" "$cargo_bin" clean --target-dir "$cargo_target_root" --profile release-dist -p xai-grok-pager-bin
"${cargo_environment[@]}" "$cargo_bin" build --locked --profile release-dist -p xai-grok-pager-bin --features release-dist

source_binary="$cargo_target_root/release-dist/xai-grok-pager"
source_sha="$("$git_bin" rev-parse HEAD)"
candidate_dir="$output_root/$source_sha"
"$python_bin" "$tool" prepare-directory --directory "$candidate_dir" --must-not-exist
candidate_binary="$candidate_dir/xai-grok-pager"
/bin/cp "$source_binary" "$candidate_binary"
/bin/chmod 700 "$candidate_binary"

manifest="$candidate_dir/candidate-provenance-v1.json"
second_manifest="$candidate_dir/.candidate-provenance-v1.second.json"
"$python_bin" "$tool" inspect \
  --repo "$repo_root" \
  --binary "$candidate_binary" \
  --official-base "$official_base" \
  --replay-base "$replay_base" \
  --output "$manifest"
"$python_bin" "$tool" inspect \
  --repo "$repo_root" \
  --binary "$candidate_binary" \
  --official-base "$official_base" \
  --replay-base "$replay_base" \
  --output "$second_manifest"
/usr/bin/cmp "$manifest" "$second_manifest"
/bin/unlink "$second_manifest"
"$python_bin" "$tool" verify \
  --repo "$repo_root" \
  --binary "$candidate_binary" \
  --official-base "$official_base" \
  --replay-base "$replay_base" \
  --manifest "$manifest"

print "candidate=$candidate_binary"
print "manifest=$manifest"
/usr/bin/shasum -a 256 "$candidate_binary" "$manifest"
