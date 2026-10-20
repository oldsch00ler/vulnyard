#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
#
# Prepares the public GitHub branch.
#
#   scripts/publish-github.sh [-m "title"] [source-ref]   (default source: main)
#
# The `github` branch has a history of its own: every run adds one commit whose
# tree is the source commit minus the paths in .publishignore. No commit of the
# source branch ever becomes part of it, so nothing that was once committed
# there - an internal file, an old revision - can reach GitHub through history.
#
# Before the commit is made, the published tree and the message are scanned:
# every domain mentioned in an excluded file, the `deny` texts of
# .publishignore, embedded metadata in images (C2PA), private keys and secret
# files (.env, *.pem, ...) abort the run. Extra fixed strings to refuse can be listed,
# one per line, in .git/info/publish-denylist (local, never committed).
#
# When the source commit carries a release tag (vX.Y.Z, made by
# scripts/release.py), the snapshot is tagged `github/vX.Y.Z` locally, to be
# pushed to GitHub as `vX.Y.Z` - the tag of the source commit itself never
# leaves.
#
# The script also installs a pre-push hook that refuses to push anything to a
# github.com remote except the `github` branch and `github/v*` tags of its
# snapshots, and scans what is pushed again.
#
# It never pushes; it prints the command to do so.

set -euo pipefail

BRANCH="github"
TRAILER="Source-Commit"
# Local tags of release snapshots: github/v1.2.0 is pushed as v1.2.0.
TAG_PREFIX="github/"
HOOK_MARKER="vulnyard-publish-guard"
# Public domains an excluded file may mention without them being secret.
BUILTIN_ALLOWED_DOMAINS="github.com gitlab.com example.com example.org example.net localhost.localdomain"
# File extensions that look like domains to the extraction regex.
NOT_A_TLD='md|toml|json|py|ts|tsx|js|mjs|cjs|ya?ml|txt|sh|html|css|lock|ini|cfg|env|example|svg|png|jpe?g|ico|gz|tar|zip|pem|sql|log|conf|xml|csv|db'

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

die() {
  echo "publish-github: $*" >&2
  exit 1
}

# --- what is excluded ---------------------------------------------------------

# Lines of .publishignore as of a commit: path patterns, or allowed domains.
ignore_lines() {
  git show "$1:.publishignore" 2>/dev/null | sed -e 's/#.*//' -e 's/[[:space:]]*$//' | grep -v '^[[:space:]]*$' || true
}

exclude_patterns() {
  ignore_lines "$1" | grep -v '^allow-domain \|^deny ' || true
}

# Texts that must never be published ("deny <text>" lines).
deny_lines() {
  ignore_lines "$1" | sed -n 's/^deny[[:space:]]\{1,\}//p'
}

allowed_domains() {
  echo "$BUILTIN_ALLOWED_DOMAINS" | tr ' ' '\n'
  ignore_lines "$1" | sed -n 's/^allow-domain[[:space:]]\{1,\}//p'
}

# Is path $1 matched by one of the patterns (one per line in $2)?
is_excluded() {
  local path="$1" pattern
  while IFS= read -r pattern; do
    [ -z "$pattern" ] && continue
    pattern="${pattern#/}"
    if [[ "$pattern" == */ ]]; then
      [[ "$path" == "$pattern"* ]] && return 0
    else
      # shellcheck disable=SC2053 # glob match on purpose
      [[ "$path" == $pattern ]] && return 0
    fi
  done <<<"$2"
  return 1
}

# Registrable domains (example.com) mentioned in the excluded files of a commit.
forbidden_domains() {
  local commit="$1" patterns path
  patterns="$(exclude_patterns "$commit")"
  [ -z "$patterns" ] && return 0
  git ls-tree -r --name-only "$commit" | while IFS= read -r path; do
    if is_excluded "$path" "$patterns"; then
      git show "$commit:$path" 2>/dev/null || true
    fi
  done \
    | grep -oiE '([a-z0-9-]+\.)+[a-z]{2,}' \
    | tr 'A-Z' 'a-z' \
    | grep -viE "\.($NOT_A_TLD)\$" \
    | awk -F. '{ print $(NF-1) "." $NF }' \
    | sort -u \
    | grep -vxF -f <(allowed_domains "$commit") || true
}

local_denylist() {
  local file
  file="$(git rev-parse --git-path info/publish-denylist)"
  [ -f "$file" ] && grep -v '^[[:space:]]*\(#.*\)\{0,1\}$' "$file" || true
}

# --- scanning -----------------------------------------------------------------

# Scan a commit or tree that is about to be published. $1 = tree-ish,
# $2 = commit whose excluded files define the forbidden domains, $3 = message.
# Prints every problem and returns non-zero when there is one.
scan() {
  local tree="$1" source="$2" message="$3" problems=0 patterns needles path
  patterns="$(exclude_patterns "$source")"
  needles="$( { forbidden_domains "$source"; deny_lines "$source"; local_denylist; } | sort -u)"

  while IFS= read -r path; do
    if [ -n "$patterns" ] && is_excluded "$path" "$patterns"; then
      echo "  excluded path present: $path" >&2
      problems=1
    fi
    case "/$path" in
      */.env.example) ;;
      */.env | */.env.* | *.pem | *.key | *.p12 | *.pfx | */id_rsa* | */id_ed25519*)
        echo "  secret-looking file: $path" >&2
        problems=1
        ;;
    esac
  done < <(git ls-tree -r --name-only "$tree")

  local args=() needle
  if [ -n "$needles" ]; then
    while IFS= read -r needle; do args+=(-e "$needle"); done <<<"$needles"
    if git grep -I -i -n -F "${args[@]}" "$tree" -- >&2; then
      echo "  ^ forbidden text (domains of excluded files, deny lines of .publishignore, .git/info/publish-denylist)" >&2
      problems=1
    fi
    if grep -i -n -F "${args[@]}" <<<"$message" >&2; then
      echo "  ^ forbidden text in the commit message" >&2
      problems=1
    fi
  fi

  # Binary files: embedded provenance metadata (C2PA) and the same texts.
  local binary=(-e c2pa)
  [ -n "$needles" ] && binary+=("${args[@]}")
  if git grep -a -l -i -F "${binary[@]}" "$tree" -- '*.png' '*.jpg' '*.jpeg' '*.gif' '*.webp' '*.ico' '*.pdf' '*.avif' >&2; then
    echo "  ^ binary file with embedded metadata or forbidden text - strip it before publishing" >&2
    problems=1
  fi

  if git grep -I -n -E -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$tree" -- >&2; then
    echo "  ^ private key" >&2
    problems=1
  fi

  return "$problems"
}

# --- pre-push hook ------------------------------------------------------------

install_hook() {
  local hook
  hook="$(git rev-parse --git-path hooks/pre-push)"
  if [ -f "$hook" ] && ! grep -q "$HOOK_MARKER" "$hook"; then
    echo "publish-github: $hook exists and is not ours - not replacing it." >&2
    echo "  Add a call to 'scripts/publish-github.sh --pre-push \"\$1\" \"\$2\"' to it yourself." >&2
    return 0
  fi
  mkdir -p "$(dirname "$hook")"
  cat >"$hook" <<'HOOK'
#!/bin/sh
# vulnyard-publish-guard - installed by scripts/publish-github.sh
case "$2" in
  *github.com*) ;;
  *) exit 0 ;;
esac
script="$(git rev-parse --show-toplevel)/scripts/publish-github.sh"
if [ ! -x "$script" ]; then
  echo "pre-push: $script is missing, refusing to push to GitHub." >&2
  exit 1
fi
exec "$script" --pre-push "$1" "$2"
HOOK
  chmod +x "$hook"
}

pre_push() {
  local remote="$1" url="$2" local_ref local_sha remote_ref remote_sha zero commit source message failed=0
  zero="0000000000000000000000000000000000000000"
  case "$url" in *github.com*) ;; *) return 0 ;; esac

  while read -r local_ref local_sha remote_ref remote_sha; do
    [ "$local_sha" = "$zero" ] && continue # deleting a remote ref
    case "$local_ref" in
      "refs/heads/$BRANCH") ;;
      "refs/tags/$TAG_PREFIX"v*)
        if [ "$remote_ref" != "refs/tags/${local_ref#refs/tags/$TAG_PREFIX}" ]; then
          echo "pre-push: push $local_ref as refs/tags/${local_ref#refs/tags/$TAG_PREFIX}, not $remote_ref." >&2
          failed=1
          continue
        fi
        if ! git log -1 --format=%B "$local_sha^{commit}" | grep -q "^$TRAILER: "; then
          echo "pre-push: tag $local_ref does not point to a snapshot of '$BRANCH'." >&2
          failed=1
          continue
        fi
        ;;
      *)
        echo "pre-push: only the '$BRANCH' branch and its '$TAG_PREFIX'v* tags may go to GitHub, not $local_ref." >&2
        echo "  Run scripts/publish-github.sh and push what it prints." >&2
        failed=1
        continue
        ;;
    esac
    for commit in $(git rev-list "$local_sha" --not --remotes="$remote"); do
      message="$(git log -1 --format=%B "$commit")"
      source="$(sed -n "s/^$TRAILER: //p" <<<"$message" | head -n 1)"
      if [ -z "$source" ] || [ "$(git rev-list --parents -n 1 "$commit" | wc -w)" -gt 2 ]; then
        echo "pre-push: commit $(git rev-parse --short "$commit") was not made by scripts/publish-github.sh." >&2
        failed=1
        continue
      fi
      git cat-file -e "$source^{commit}" 2>/dev/null || source="$(git rev-parse main)"
      if ! scan "$commit" "$source" "$message"; then
        echo "pre-push: commit $(git rev-parse --short "$commit") would publish something it must not." >&2
        failed=1
      fi
    done
  done
  return "$failed"
}

# --- building the snapshot ----------------------------------------------------

publish() {
  local title="" source_ref="main"
  while [ $# -gt 0 ]; do
    case "$1" in
      -m) title="$2"; shift 2 ;;
      -h | --help) sed -n '5,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
      *) source_ref="$1"; shift ;;
    esac
  done

  [ "$(git symbolic-ref --short -q HEAD || true)" = "$BRANCH" ] \
    && die "switch away from '$BRANCH' first (the branch is generated, not edited)."

  local source parent="" previous_source="" index tree patterns path
  source="$(git rev-parse --verify "$source_ref^{commit}")" || die "unknown ref $source_ref"
  if git rev-parse -q --verify "refs/heads/$BRANCH" >/dev/null; then
    parent="$(git rev-parse "refs/heads/$BRANCH")"
    previous_source="$(git log -1 --format=%B "$parent" | sed -n "s/^$TRAILER: //p" | head -n 1)"
    if [ -z "$previous_source" ]; then
      local last
      last="$(git log --format='%H %B' "$parent" | awk -v t="$TRAILER:" '$0 ~ "^[0-9a-f]{40} " { c = $1 } index($0, t) == 1 { print c; exit }')"
      die "the tip of '$BRANCH' was not made by this script (edited by hand?). Changes belong in the source branch.
  Reset '$BRANCH' to the last published snapshot and run again:  git branch -f $BRANCH ${last:-<last snapshot>}"
    fi
  fi

  if ! git diff --quiet "$source" 2>/dev/null || ! git diff --cached --quiet "$source" 2>/dev/null; then
    echo "publish-github: note - uncommitted changes are not published, only $source_ref as committed." >&2
  fi

  # The source tree minus the excluded paths, built in a scratch index.
  index="$(mktemp)"
  # shellcheck disable=SC2064 # expand now: $index is local to this function
  trap "rm -f '$index'" EXIT
  GIT_INDEX_FILE="$index" git read-tree "$source"
  patterns="$(exclude_patterns "$source")"
  local removed=()
  if [ -n "$patterns" ]; then
    while IFS= read -r path; do
      if is_excluded "$path" "$patterns"; then
        removed+=("$path")
        GIT_INDEX_FILE="$index" git update-index --force-remove -- "$path"
      fi
    done < <(git ls-tree -r --name-only "$source")
  fi
  tree="$(GIT_INDEX_FILE="$index" git write-tree)"

  local release
  release="$(git tag --points-at "$source" --list 'v[0-9]*' | head -n 1)"

  if [ -n "$parent" ] && [ "$(git rev-parse "$parent^{tree}")" = "$tree" ]; then
    install_hook
    if [ -n "$release" ] && ! git rev-parse -q --verify "refs/tags/$TAG_PREFIX$release" >/dev/null; then
      # Released after the content was already published: tag that snapshot.
      git tag "$TAG_PREFIX$release" "$parent"
      echo "publish-github: '$BRANCH' already has this content; tagged it as $TAG_PREFIX$release."
      print_push "$release"
    else
      echo "publish-github: '$BRANCH' already has this content, nothing to do."
    fi
    exit 0
  fi

  if [ -z "$title" ]; then
    if [ -n "$release" ]; then
      title="Release $release"
    elif [ -z "$parent" ]; then
      title="Initial public release"
    else
      title="Update $(date +%Y-%m-%d)"
    fi
  fi
  local message
  message="$(printf '%s\n\n%s: %s\n' "$title" "$TRAILER" "$source")"

  echo "Scanning what would be published…"
  scan "$tree" "$source" "$message" || die "aborted - nothing was created. Fix the above in $source_ref and run again."

  local commit
  if [ -n "$parent" ]; then
    commit="$(git commit-tree "$tree" -p "$parent" <<<"$message")"
    git update-ref "refs/heads/$BRANCH" "$commit" "$parent"
  else
    commit="$(git commit-tree "$tree" <<<"$message")"
    git update-ref "refs/heads/$BRANCH" "$commit" ""
  fi
  if [ -n "$release" ]; then
    git tag -f "$TAG_PREFIX$release" "$commit" >/dev/null
  fi
  install_hook

  echo
  echo "Created $(git rev-parse --short "$commit") on '$BRANCH' from $source_ref ($(git rev-parse --short "$source"))."
  [ ${#removed[@]} -gt 0 ] && echo "Left out: ${removed[*]}"
  if [ -n "$parent" ]; then
    echo "Changes since the previous snapshot${previous_source:+ ($(git rev-parse --short "$previous_source" 2>/dev/null || echo "$previous_source"))}:"
    git --no-pager diff --stat "$parent" "$commit" | tail -n 15
  fi

  print_push "$release"
}

# How to push what was prepared; $1 = release tag of the snapshot, if any.
print_push() {
  local release="${1:-}" remote refs
  remote="$(git remote -v | awk '/github\.com/ && /\(push\)/ { print $1; exit }')"
  refs="$BRANCH:main${release:+ refs/tags/$TAG_PREFIX$release:refs/tags/$release}"
  echo
  if [ -n "$remote" ]; then
    echo "Push it with:  git push $remote $refs"
  else
    echo "Add the GitHub remote once:  git remote add github git@github.com:<user>/vulnyard.git"
    echo "Then push with:              git push github $refs"
  fi
  if [ -n "$release" ]; then
    echo "Release notes for GitHub:    scripts/release.py notes $release"
  fi
}

case "${1:-}" in
  --pre-push) shift; pre_push "$@" ;;
  --install-hook) install_hook ;;
  *) publish "$@" ;;
esac
