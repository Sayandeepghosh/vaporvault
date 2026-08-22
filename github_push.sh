#!/usr/bin/env bash
#
# Link this existing repository to a new GitHub remote and push the full history.
#
# Usage:
#   1. Replace YOUR_GITHUB_USERNAME below.
#   2. ./github_push.sh
#
# If the GitHub CLI (`gh`) is installed and authenticated, the remote repository is
# created for you. Otherwise create an EMPTY repo on GitHub first -- no README, no
# .gitignore, no licence -- so the push is not rejected as a non-fast-forward.

set -euo pipefail

GITHUB_USERNAME="YOUR_GITHUB_USERNAME"
REPO_NAME="vaporvault"
VISIBILITY="public" # or: private
PROTOCOL="https"    # or: ssh

DESCRIPTION="Zero-knowledge, one-time secret sharing. Encrypted in the browser, destroyed on first read."

# --- preflight ---------------------------------------------------------------

# Format check rather than a literal placeholder comparison, so that a global
# find-and-replace of the placeholder cannot accidentally rewrite the guard itself.
# GitHub usernames are letters, digits and single hyphens only -- the placeholder's
# underscores fail this on purpose.
if [[ ! "$GITHUB_USERNAME" =~ ^[A-Za-z0-9](-?[A-Za-z0-9])*$ ]]; then
  echo "\"$GITHUB_USERNAME\" is not a valid GitHub username." >&2
  echo "Set GITHUB_USERNAME at the top of this script (letters, digits, hyphens)." >&2
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Not a git repository. Run this from the project root." >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit or stash first:" >&2
  git status --short >&2
  exit 1
fi

BRANCH="$(git symbolic-ref --short HEAD)"
COMMITS="$(git rev-list --count HEAD)"

if [[ "$PROTOCOL" == "ssh" ]]; then
  REMOTE_URL="git@github.com:${GITHUB_USERNAME}/${REPO_NAME}.git"
else
  REMOTE_URL="https://github.com/${GITHUB_USERNAME}/${REPO_NAME}.git"
fi

# --- create the remote repository, if we can --------------------------------

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  if gh repo view "${GITHUB_USERNAME}/${REPO_NAME}" >/dev/null 2>&1; then
    echo "Remote repository already exists; reusing it."
  else
    echo "Creating ${GITHUB_USERNAME}/${REPO_NAME} (${VISIBILITY})..."
    gh repo create "${GITHUB_USERNAME}/${REPO_NAME}" \
      "--${VISIBILITY}" --description "$DESCRIPTION"
  fi
else
  echo "gh CLI not available; assuming ${GITHUB_USERNAME}/${REPO_NAME} already exists."
fi

# --- wire up the remote and push --------------------------------------------

if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "$REMOTE_URL"
else
  git remote add origin "$REMOTE_URL"
fi

echo "Pushing ${COMMITS} commits to ${REMOTE_URL} (branch: ${BRANCH})"
git push -u origin "$BRANCH"

echo
echo "Done. Next: import the repo at https://vercel.com/new"
echo "Environment variables to set are listed in README.md under 'Deploy to Vercel'."
