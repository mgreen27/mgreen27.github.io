#!/bin/sh
# Build checked output; optionally refresh the current branch-root Pages files.
set -eu
cd "$(dirname "$0")/.."
case "${1:-}" in
    ''|--publish-root) ;;
    *) echo 'Usage: scripts/build-site.sh [--publish-root]' >&2; exit 2 ;;
esac
python3 scripts/check_external_posts.py --write
hugo --gc --minify
python3 scripts/check_external_posts.py --site-dir public
mkdir -p public/static
rsync -a static/ public/static/
if [ "${1:-}" = '--publish-root' ]; then
    rsync -a public/ ./
fi
