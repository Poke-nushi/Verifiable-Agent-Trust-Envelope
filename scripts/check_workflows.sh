#!/usr/bin/env bash
# Run the same pinned workflow checker locally and in CI.
set -euo pipefail

version=1.7.12
# https://github.com/rhysd/actionlint/releases/tag/v1.7.12
# Update the version and all archive checksums together.
case "$(uname -s)/$(uname -m)" in
  Darwin/arm64)
    platform=darwin_arm64
    checksum=aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f
    ;;
  Darwin/x86_64)
    platform=darwin_amd64
    checksum=5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644
    ;;
  Linux/x86_64)
    platform=linux_amd64
    checksum=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
    ;;
  Linux/aarch64|Linux/arm64)
    platform=linux_arm64
    checksum=325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6
    ;;
  *)
    echo "actionlint: supported platforms are macOS/Linux on arm64/x86_64" >&2
    exit 1
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/vate/actionlint/$version"
mkdir -p "$cache_dir"
work_dir="$(mktemp -d "$cache_dir/.run.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

archive="actionlint_${version}_${platform}.tar.gz"
if [ -f "$cache_dir/$archive" ]; then
  cp "$cache_dir/$archive" "$work_dir/$archive"
else
  echo "Downloading actionlint $version ($platform)" >&2
  curl -q --fail --location --silent --show-error \
    --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 120 --retry 2 \
    "https://github.com/rhysd/actionlint/releases/download/v$version/$archive" \
    --output "$work_dir/$archive"
fi

# Check a private copy on every invocation, including cache hits, before extraction.
if ! (cd "$work_dir" && printf '%s  %s\n' "$checksum" "$archive" | shasum -a 256 -c -); then
  echo "actionlint: checksum mismatch; remove the cached archive and retry: $cache_dir/$archive" >&2
  exit 1
fi
tar -xzf "$work_dir/$archive" -C "$work_dir" actionlint
mv -f "$work_dir/$archive" "$cache_dir/$archive"

cd "$repo_root"
echo "Checking workflows with actionlint $version" >&2
# Keep optional, unpinned external linters out of this reproducible check.
"$work_dir/actionlint" -shellcheck= -pyflakes= "$@"
