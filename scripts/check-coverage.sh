#!/bin/sh
set -eu

PROFILE="${1:-coverage.out}"
IGNORE_FILE="${2:-.coverageignore}"

if [ ! -f "$PROFILE" ]; then
  echo "coverage profile not found: $PROFILE" >&2
  exit 2
fi

go tool cover -func="$PROFILE" |
  awk -v ignfile="$IGNORE_FILE" '
    BEGIN {
      while ((getline line < ignfile) > 0) {
        if (line ~ /^#/ || line ~ /^$/) continue
        ign[line] = 1
      }
      close(ignfile)
    }
    $1 == "total:" { total = $NF; next }
    {
      pkg = $1
      sub(/\/[^\/]+$/, "", pkg)
      pct = $NF
      sub(/%$/, "", pct)
      cov[pkg] = (pkg in cov) ? cov[pkg] " " pct : pct
    }
    END {
      for (pkg in cov) {
        ignored = 0
        for (p in ign) {
          if (index(pkg, p) == 1) { ignored = 1; break }
        }
        if (ignored) {
          printf "  ignored  %s\n", pkg
          continue
        }
        n = split(cov[pkg], a, / /)
        sum = 0
        for (i = 1; i <= n; i++) sum += a[i]
        avg = (n > 0) ? sum / n : 0
        printf "  %s  %.2f%%\n", pkg, avg
      }
      if (total) printf "  TOTAL    %s\n", total
    }
  '
