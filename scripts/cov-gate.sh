#!/usr/bin/env bash
# cov-gate.sh — coverage gate over a cargo-llvm-cov full-detail JSON report.
#
# Purpose: enforces minimum line and branch coverage percentages in CI and
# locally. cargo-llvm-cov (0.8.x/0.9.x) has --fail-under-lines but no
# --fail-under-branches. The lcov formatter in LLVM nightly SIGSEGVs when
# branch data is requested (`--branch --lcov`), while the JSON path
# (`--branch --json`, full detail) is stable, so the gate consumes JSON.
#
# Usage:
#   cov-gate.sh [--lines N] [--branches N] [--strict] <summary.json>
#
# Produce the input with (nightly toolchain, full detail — NOT
# --summary-only, the gate needs the per-function records and the merged
# per-file segments):
#   cargo llvm-cov --workspace --all-features --branch \
#       --json --output-path summary.json
#
# Contract:
#   --lines N      minimum line coverage percent (default 100).
#   --branches N   minimum branch coverage percent (default 100).
#   --strict       disable the zero-count-record carve-out (see below) and
#                  take both metrics from the raw llvm-cov summary — the
#                  pre-carve-out behaviour, phantom misses included.
#   <summary.json> cargo-llvm-cov JSON report (version 3.x, full detail);
#                  the gate reads data[0].totals, data[0].files[].segments
#                  and data[0].functions[].
#
# Exit codes:
#   0  both metrics are at or above their thresholds and no carve-out
#      check tripped.
#   1  at least one metric is below its threshold, or a zero-count
#      function record exposes genuinely dead lines or a one-sided live
#      branch inside its span (details on stderr).
#   2  usage error, unreadable/malformed JSON, zero total lines, zero
#      total branches, or a summary-only input (no per-function detail) —
#      a branch-less or detail-less report is never accepted, otherwise
#      the gate would silently pass on a weaker measurement.
#
# Coverage metrics — what is measured and why (2026-09-07):
#
#   lines     RECOMPUTED from the merged per-file segment view
#             (data[0].files[].segments) with llvm-cov's own
#             LineCoverageStats algorithm (wrapped segment + region-entry
#             maximum, gap/skipped segments excluded) — the same view the
#             `llvm-cov show` line renderer displays. The raw summary
#             (data[0].totals.lines) is NOT used by default because of
#             the llvm-cov function-aggregation artifact:
#
#             llvm-cov builds the JSON summary per function record
#             (CoverageReport::prepareSingleFileReport ->
#             FunctionCoverageSummary::get per record), so a never
#             executed duplicate instantiation record drags the lines of
#             its span down as uncovered even though another
#             instantiation of the same source lines executed — the
#             renderer (merged per-file view) shows them covered.
#             Observed 2026-09-06..07 on master: 9 dangling zero-count
#             records in core/psbt.rs (4 closure monomorphizations in
#             parse/extract/sign_input at lines 809/1476/1815/1855 + 5
#             `independent_p2wsh_*` test-helper closures at
#             6311/6318/6336/6394/6398), phantom-missing 5 lines in
#             data[0].totals.lines (20210/20215 = 99.98%) while the line
#             renderer reports zero uncovered lines for psbt.rs
#             (`--show-missing-lines` triage: no psbt.rs entries).
#
#             Carve-out (the owner-approved variant 1): a function record
#             with count == 0 is treated as covered IF every line and
#             branch within its span (from the record's regions and
#             filenames) has a nonzero count per the same JSON's
#             line/branch data. The recomputed merged view satisfies the
#             line part by construction; the gate additionally verifies
#             each zero-count record's span and FAILS if a dangling
#             record exposes a genuinely dead line (covered by no
#             execution) or hides a one-sided live branch position.
#             Reproduce the artifact with:
#               rustup run nightly cargo llvm-cov --workspace \
#                 --all-features --branch --json \
#                 --output-path cov-summary.json \
#                 --ignore-filename-regex '(^|/)(prompt_tty|tui_term)\.rs$'
#               python3 -c 'import json; d=json.load(open("cov-summary.json"))["data"][0]; \
#                 print(d["totals"]["lines"]); \
#                 print(sum(1 for f in d["functions"] if f["count"]==0 and \
#                           any(x.endswith("core/src/psbt.rs") for x in f["filenames"])))'
#               # -> 5 phantom line misses, 9 dangling records
#
#   branches  taken from data[0].totals.branches unchanged. The JSON
#             export does not carry the per-condition fold flags
#             (TrueFolded/FalseFolded, see llvm's sumBranches), so a
#             faithful branch recomputation is impossible from the JSON
#             alone: naive per-side accounting over data[0].functions[]
#             reports 1006 conditions / 20 misses against llvm-cov's
#             fold-aware 974 / 8 on the same profile. The summary is the
#             only fold-aware source. The dangling-record artifact does
#             not affect it in practice (the observed zero-count records
#             carry no branch regions, and same-name instantiations are
#             max-merged per InstantiationGroup), and the carve-out span
#             check below still fails the gate if a dangling record
#             hides a one-sided live branch.
#
# Notes:
#   - Comparison is `measured >= threshold` in double precision; line and
#     branch counts are far below the range where that matters.
#   - Requires bash and python3 (used as the JSON parser); no jq.

set -u

usage() {
    sed -n '2,23p' "$0" >&2
    exit 2
}

min_lines=100
min_branches=100
strict=0

while [ $# -gt 1 ]; do
    case "$1" in
        --lines)    min_lines="$2";    shift 2 ;;
        --branches) min_branches="$2"; shift 2 ;;
        --strict)   strict=1;          shift 1 ;;
        *) usage ;;
    esac
done

[ $# -eq 1 ] || usage
summary="$1"

[ -r "$summary" ] || { echo "cov-gate: cannot read '$summary'" >&2; exit 2; }

vals=$(python3 - "$summary" "$strict" <<'PY'
import json, sys
from collections import defaultdict

strict = sys.argv[2] == "1"

try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        data = json.load(fh)["data"][0]
    totals = data["totals"]
    files = data["files"]
    functions = data["functions"]
except (OSError, KeyError, IndexError, TypeError, ValueError):
    sys.exit(1)

# Full detail is mandatory: the carve-out needs the per-function records
# and the merged per-file segments. A summary-only input is rejected.
if not files or "segments" not in files[0] or not functions:
    sys.exit(3)

# --- Line coverage, renderer-equivalent, from the merged segment view ---
# Port of llvm-cov's LineCoverageStats: for each line, LineSegments are
# the segments starting on it and WrappedSegment is the segment
# immediately preceding them. A line is mapped unless it only starts a
# skipped region (hasCount=False region entry); its execution count is
# the wrapped count maxed with the non-gap region-entry counts on the
# line; count 0 => uncovered.

def line_coverage(segments):
    by_line = defaultdict(list)
    for s in segments:
        by_line[s[0]].append(s)
    mapped = 0
    uncovered = []
    prev = None  # the segment immediately preceding the current line
    for line in sorted(by_line):
        segs = by_line[line]
        first = segs[0]
        start_skipped = (not first[3]) and first[4]
        wrapped = prev is not None and prev[3]
        if not start_skipped and (wrapped or first[3]):
            mapped += 1
            count = prev[2] if wrapped else 0
            entries = [s[2] for s in segs if s[3] and not s[5] and s[4]]
            if entries:
                count = max([count] + entries)
            if count == 0:
                uncovered.append(line)
        prev = segs[-1]
    return mapped, uncovered

total_lines = 0
uncovered_lines = 0
unc_by_file = {}
for fl in files:
    mapped, unc = line_coverage(fl.get("segments") or [])
    total_lines += mapped
    uncovered_lines += len(unc)
    unc_by_file[fl["filename"]] = set(unc)

# --- Branch positions: per-position side maximum over LIVE records -----
# Zero-count (dangling) records are excluded — that is the carve-out:
# a never executed duplicate instantiation must not mask live counts.
# Records outside the measured file set (ignore-filename-regex) do not
# exist for the gate: the summary still carries their function records
# even though their files are filtered out of data[0].files.
measured = {fl["filename"] for fl in files}
live_max = defaultdict(lambda: [0, 0])
for fn in functions:
    if fn["count"] == 0:
        continue
    fn_files = fn["filenames"]
    for b in fn.get("branches") or ():
        fname = fn_files[b[6]] if b[6] < len(fn_files) else fn_files[0]
        if fname not in measured:
            continue
        key = (fname, b[0], b[1], b[2], b[3])
        m = live_max[key]
        m[0] = max(m[0], b[4])
        m[1] = max(m[1], b[5])

# --- Carve-out verification over every zero-count record ---------------
# Treated as covered iff every line of its span is covered per the merged
# segment data (no dead lines) and no branch position inside its span is
# one-sided across live records (both sides taken, or never evaluated —
# llvm-cov folds the latter). Otherwise the gate fails.
dangling = 0
forgiven_lines = set()
dead_lines = set()
one_sided = set()
for fn in functions:
    if fn["count"] != 0:
        continue
    fn_files = fn["filenames"]
    if not any(name in measured for name in fn_files):
        continue  # outside the measured file set (ignore-filename-regex)
    dangling += 1
    for reg in fn.get("regions") or ():
        fname = fn_files[reg[5]] if reg[5] < len(fn_files) else fn_files[0]
        unc = unc_by_file.get(fname)
        if unc is None:
            continue  # outside the measured file set (ignore-filename-regex)
        for line in range(reg[0], reg[2] + 1):
            if line in unc:
                dead_lines.add((fname, line))
            else:
                forgiven_lines.add((fname, line))
    for b in fn.get("branches") or ():
        key = (fn_files[b[6]], b[0], b[1], b[2], b[3])
        t, f = live_max.get(key, (0, 0))
        if (t > 0) != (f > 0):
            one_sided.add((key[0], key[1]))

if strict:
    # Carve-out disabled: raw llvm-cov summary for both metrics.
    lines_covered = totals["lines"]["covered"]
    lines_total = totals["lines"]["count"]
else:
    lines_covered = total_lines - uncovered_lines
    lines_total = total_lines

br_total = totals["branches"]["count"]
br_covered = totals["branches"]["covered"]

print(lines_covered, lines_total, br_covered, br_total)
print("carve-out: %d dangling zero-count record(s), %d span line(s) verified covered"
      % (dangling, len(forgiven_lines)), file=sys.stderr)
for fname, line in sorted(dead_lines):
    print("carve-out: DEAD LINE not covered by any execution: %s:%d" % (fname, line),
          file=sys.stderr)
for fname, line in sorted(one_sided):
    print("carve-out: one-sided live branch in a dangling record span: %s:%d"
          % (fname, line), file=sys.stderr)
if dead_lines or one_sided:
    sys.exit(4)
PY
) ; rc=$?

case $rc in
    0) ;;
    3) echo "cov-gate: summary-only JSON lacks function detail — regenerate with 'cargo llvm-cov --json' (no --summary-only): $summary" >&2; exit 2 ;;
    4) echo "cov-gate: zero-count record carve-out refused (see details above)" >&2; exit 1 ;;
    *) echo "cov-gate: malformed cargo-llvm-cov JSON summary: $summary" >&2; exit 2 ;;
esac

read -r LF LH BRF BRH <<EOF
$vals
EOF

[ -n "${LF:-}" ] || { echo "cov-gate: malformed cargo-llvm-cov JSON summary: $summary" >&2; exit 2; }
[ "$LF" -gt 0 ]  || { echo "cov-gate: summary has zero total lines: $summary" >&2; exit 2; }
[ "$BRF" -gt 0 ] || { echo "cov-gate: summary has zero total branches — regenerate with 'cargo llvm-cov --branch ...' (nightly)" >&2; exit 2; }

fail=0

check() { # label, covered, total, threshold
    local label="$1" covered="$2" total="$3" min="$4" pct ok
    pct=$(awk -v c="$covered" -v t="$total" 'BEGIN { printf "%.2f", c * 100 / t }')
    ok=$(awk -v p="$pct" -v m="$min" 'BEGIN { print (p + 0 >= m + 0) ? "yes" : "no" }')
    if [ "$ok" = yes ]; then
        printf 'cov-gate: %-8s OK    %d/%d = %s%% (min %s%%)\n' "$label" "$covered" "$total" "$pct" "$min"
    else
        printf 'cov-gate: %-8s FAIL  %d/%d = %s%% (min %s%%)\n' "$label" "$covered" "$total" "$pct" "$min"
        fail=1
    fi
}

check lines    "$LF"  "$LH"  "$min_lines"
check branches "$BRF" "$BRH" "$min_branches"

exit "$fail"
