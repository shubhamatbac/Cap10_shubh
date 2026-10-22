#!/usr/bin/env bash
# Tiny lab registry kept on the orphan branch "lab-registry" of THIS repository.
# One JSON file per live lab. The reaper workflow reads it to find expired labs.
#   registry.sh put    <name> <cloud> <region> <expires_epoch> <owner>
#   registry.sh remove <name> <cloud>
set -euo pipefail
cmd="$1"; shift
dir="$(mktemp -d)"
repo_url="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
git config --global user.name "lab-bot"
git config --global user.email "lab-bot@users.noreply.github.com"
if git ls-remote --exit-code --heads "$repo_url" lab-registry >/dev/null 2>&1; then
  git clone --quiet --depth 1 --branch lab-registry "$repo_url" "$dir"
else
  git init --quiet "$dir"; git -C "$dir" checkout --quiet --orphan lab-registry
fi
case "$cmd" in
  put)
    name="$1"; cloud="$2"; region="$3"; exp="$4"; owner="$5"
    printf '{"name":"%s","cloud":"%s","region":"%s","expires_epoch":%s,"owner":"%s"}\n' \
      "$name" "$cloud" "$region" "$exp" "$owner" > "$dir/${cloud}__${name}.json" ;;
  remove)
    rm -f "$dir/$2__$1.json" ;;
  *) echo "unknown command $cmd" >&2; exit 2 ;;
esac
git -C "$dir" add -A
if git -C "$dir" diff --cached --quiet; then echo "registry unchanged"; exit 0; fi
git -C "$dir" commit --quiet -m "registry: $cmd $*"
for i in 1 2 3; do
  git -C "$dir" push --quiet "$repo_url" HEAD:lab-registry && exit 0
  git -C "$dir" pull --quiet --rebase "$repo_url" lab-registry || true
done
echo "failed to update registry" >&2; exit 1
