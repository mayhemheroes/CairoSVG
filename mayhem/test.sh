#!/usr/bin/env bash
#
# mayhem/test.sh — run the CairoSVG pytest suite via the compiled ELF runner and emit CTRF.
# RUNs the tests; does NOT compile (build.sh already installed the package and built run_tests).
set -uo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
SRC="${SRC:-/mayhem}"
cd "$SRC"

emit_ctrf() {
    local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
    local tests=$(( passed + failed + skipped + pending + other ))
    cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
    printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
        "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
    [ "$failed" -eq 0 ]
}

RUNNER="$SRC/run_tests"
if [ ! -x "$RUNNER" ]; then
    echo "test.sh: $RUNNER missing/not executable — mayhem/build.sh must build it first" >&2
    emit_ctrf "cairosvg-pytest" 0 1 0
    exit 1
fi

echo ">> running CairoSVG test suite via $RUNNER"
raw=$("$RUNNER" 2>&1) || true

echo "$raw"

# pytest -q summary: "N passed" or "X failed, Y passed"
passed=$(echo "$raw" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' | tail -1 || echo 0)
failed=$(echo "$raw" | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+' | tail -1 || echo 0)
skipped=$(echo "$raw" | grep -oE '[0-9]+ skipped' | grep -oE '[0-9]+' | tail -1 || echo 0)
passed="${passed:-0}"
failed="${failed:-0}"
skipped="${skipped:-0}"

if [ "$passed" -eq 0 ] && [ "$failed" -eq 0 ] && [ "$skipped" -eq 0 ]; then
    if echo "$raw" | grep -qiE 'error|traceback|collected 0'; then
        failed=1
    fi
fi

emit_ctrf "pytest" "$passed" "$failed" "$skipped"
