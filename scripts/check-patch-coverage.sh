#!/bin/sh
set -eu

BASE="${1:-origin/main}"
THRESHOLD="${2:-90}"
PROFILE="${3:-coverage.out}"

if [ ! -f "$PROFILE" ]; then
	echo "patch-coverage: $PROFILE not found; run 'make test-coverage' first" >&2
	exit 2
fi

git rev-parse --verify --quiet "$BASE" >/dev/null 2>&1 || git fetch origin main >/dev/null 2>&1 || true

BASE="$BASE" THRESHOLD="$THRESHOLD" PROFILE="$PROFILE" python3 - <<'PY'
import collections, os, re, subprocess, sys

base = os.environ["BASE"]
threshold = float(os.environ["THRESHOLD"])
profile = os.environ["PROFILE"]

diff = subprocess.run(
    ["git", "diff", "--unified=0", f"{base}...HEAD", "--", "internal/**/*.go", ":!**/*_test.go"],
    capture_output=True, text=True,
).stdout

changed = collections.defaultdict(set)
cur = None
for line in diff.splitlines():
    m = re.match(r"\+\+\+ b/(.+)", line)
    if m:
        cur = m.group(1)
        continue
    h = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
    if h and cur:
        start = int(h.group(1))
        cnt = int(h.group(2) or "1")
        for ln in range(start, start + cnt):
            changed[cur].add(ln)

if not changed:
    print(f"patch-coverage: no changed internal source lines vs {base}")
    sys.exit(0)

covered = collections.defaultdict(dict)
for line in open(profile):
    m = re.match(r"github\.com/outgate-ai/og-local/(.+):(\d+)\.\d+,(\d+)\.\d+ \d+ (\d+)", line)
    if not m:
        continue
    f, s, e, c = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
    for ln in range(s, e + 1):
        covered[f].setdefault(ln, False)
        if c > 0:
            covered[f][ln] = True

tot = hit = 0
misses = collections.defaultdict(list)
for f, lines in changed.items():
    for ln in lines:
        if f in covered and ln in covered[f]:
            tot += 1
            if covered[f][ln]:
                hit += 1
            else:
                misses[f].append(ln)

if tot == 0:
    print("patch-coverage: no measurable changed lines")
    sys.exit(0)

pct = 100 * hit / tot
print(f"patch-coverage: {hit}/{tot} changed lines covered = {pct:.2f}% (threshold {threshold:g}%)")
if pct < threshold:
    print("patch-coverage: FAIL — uncovered changed lines:", file=sys.stderr)
    for f in sorted(misses):
        print(f"  {f}: {sorted(misses[f])}", file=sys.stderr)
    sys.exit(1)
PY
