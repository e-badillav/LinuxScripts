#!/usr/bin/env bash
#
# Pushes a prepared integration to wazuh/operations as a new branch and opens the PR.
#
# Forks are disabled on wazuh/operations, so the branch is pushed directly to the
# repo from your local clone, as in the manual process.
#
# Usage:
#   new_operations_pr.sh <ticket> <source_dir> [dest_path] [title]
#
#   ticket      Jira ticket key, e.g. WS-39601
#   source_dir  Prepared folder, e.g. prs/WS-39601/okta
#   dest_path   Path inside the repo (default: integrations/<basename of source_dir>)
#   title       PR title (default: "Add <name> integration")
#
# The PR body is read from <source_dir>/../PR_DESCRIPTION.md if it exists.
#
# Environment:
#   OPS_REPO    Path to your local clone of wazuh/operations (default: ~/operations)
#   BASE        Base branch (default: main)
#
# If the GitHub CLI (gh) is installed and logged in, the PR is created automatically.
# Otherwise the script prints the URL to open it from the browser.

set -euo pipefail

if [[ $# -lt 2 ]]; then
    sed -n '3,22p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

TICKET="$1"
SRC="$(cd "$2" && pwd)"
NAME="$(basename "$SRC")"
DEST="${3:-integrations/$NAME}"
TITLE="${4:-Add $NAME integration}"
OPS_REPO="${OPS_REPO:-$HOME/operations}"
BASE="${BASE:-main}"
BRANCH="$(echo "${TICKET}-${NAME}" | tr '[:upper:]' '[:lower:]' | tr '_' '-')"
BODY_FILE="$(dirname "$SRC")/PR_DESCRIPTION.md"

if [[ ! "$NAME" =~ ^[a-z0-9_]+$ ]]; then
    echo "Error: '$NAME' must be lowercase and underscore_separated (CONTRIBUTING.md)." >&2
    exit 1
fi
if [[ ! -f "$SRC/README.md" ]]; then
    echo "Error: $SRC/README.md is missing (every integration needs one)." >&2
    exit 1
fi
for f in $(find "$SRC" -name '*.xml'); do
    python3 -c "import sys, xml.dom.minidom as m; m.parseString('<r>' + open(sys.argv[1]).read() + '</r>')" "$f" \
        || { echo "Error: invalid XML in $f" >&2; exit 1; }
done
for f in $(find "$SRC" -name '*.py'); do
    python3 -m py_compile "$f" || { echo "Error: syntax error in $f" >&2; exit 1; }
done
if grep -rnEi '(api[_-]?key|token|password|secret)\s*=\s*"[^"]{20,}"' "$SRC"; then
    echo "Error: looks like a real credential is in the files above. Use placeholders." >&2
    exit 1
fi

if [[ ! -d "$OPS_REPO/.git" ]]; then
    echo "Error: $OPS_REPO is not a git clone of wazuh/operations." >&2
    echo "Set OPS_REPO with 'export OPS_REPO=/path/to/operations' or run 'OPS_REPO=/path/to/operations $0 ...'." >&2
    exit 1
fi
cd "$OPS_REPO"
if [[ -n "$(git status --porcelain)" ]]; then
    echo "Error: $OPS_REPO has uncommitted changes. Commit or stash them first." >&2
    exit 1
fi

git fetch origin "$BASE"
git checkout -B "$BRANCH" "origin/$BASE"

if [[ -e "$DEST" ]]; then
    echo "Warning: $DEST already exists in $BASE; files will be overwritten." >&2
fi
mkdir -p "$DEST"
cp -R "$SRC/." "$DEST/"
find "$DEST" -name '__pycache__' -type d -prune -exec rm -rf {} +

git add "$DEST"
git commit -m "$TITLE" -m "Related ticket: $TICKET"
git push -u origin "$BRANCH"

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    if [[ -f "$BODY_FILE" ]]; then
        gh pr create --repo wazuh/operations --base "$BASE" --head "$BRANCH" --title "$TITLE" --body-file "$BODY_FILE"
    else
        gh pr create --repo wazuh/operations --base "$BASE" --head "$BRANCH" --title "$TITLE" --body "Related ticket: $TICKET"
    fi
else
    echo
    echo "Branch pushed. Open the PR here:"
    echo "  https://github.com/wazuh/operations/compare/${BASE}...${BRANCH}?expand=1"
    [[ -f "$BODY_FILE" ]] && echo "PR description to paste: $BODY_FILE"
fi
