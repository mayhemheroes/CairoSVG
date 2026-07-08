#!/usr/bin/env bash
#
# mayhem/build.sh — build the CairoSVG Atheris fuzz harness (PyInstaller onefile ELF) and test oracle.
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem.
#
# PyInstaller bundles Python+atheris into one ELF so Mayhem can collect edges_covered (>0).
#
# AIR-GAPPED CONTRACT (SPEC §6.2 item 9 / §6.5): the PATCH tier re-runs THIS script OFFLINE.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"

PY_PREFIX=/opt/toolchains/python
WHEELHOUSE="$PY_PREFIX/wheelhouse"
PY="$(command -v python3)"

graft_dwarf() {
  local bin="$1"
  # shellcheck disable=SC2086
  $CC -c $DEBUG_FLAGS "$SRC/mayhem/asan_defaults.c" -o /tmp/dwarf_anchor.o
  for sect in .debug_info .debug_abbrev .debug_line .debug_str; do
    if objcopy --dump-section "${sect}=/tmp/dwarf_sect.bin" /tmp/dwarf_anchor.o 2>/dev/null; then
      objcopy --add-section "${sect}=/tmp/dwarf_sect.bin" \
        --set-section-flags "${sect}=alloc,merge,debug" "$bin" /tmp/bin_grafted
      mv /tmp/bin_grafted "$bin"
    fi
  done
}

setup_test_fonts() {
  if [ -d "$HOME/.fonts" ] && ls "$HOME/.fonts"/*.otf >/dev/null 2>&1; then
    return 0
  fi
  mkdir -p "$HOME/.fonts"
  cp "$SRC"/test_non_regression/resources/*.*tf "$HOME/.fonts/" 2>/dev/null || true
  fc-cache -f -v >/dev/null 2>&1 || true
}

ensure_test_reference() {
  local ref_dir="$SRC/test_non_regression/cairosvg_reference"
  if [ -f "$ref_dir/cairosvg/__init__.py" ]; then
    return 0
  fi
  echo ">> populating cairosvg_reference from in-repo git (submodule url=./ breaks in Docker/CI)"
  local ref_sha
  ref_sha="$(git -C "$SRC" ls-tree HEAD test_non_regression/cairosvg_reference | awk '{print $3}')"
  if [ -z "$ref_sha" ]; then
    echo "build.sh: missing gitlink for test_non_regression/cairosvg_reference" >&2
    exit 1
  fi
  rm -rf "$ref_dir"
  mkdir -p "$ref_dir"
  git -C "$SRC" archive "$ref_sha" | tar -x -C "$ref_dir"
}

# ── 1) Wheelhouse (online first pass; offline re-run) ───────────────────────────────────
mkdir -p "$WHEELHOUSE"
if ls "$WHEELHOUSE"/atheris-*.whl >/dev/null 2>&1 && ls "$WHEELHOUSE"/pyinstaller-*.whl >/dev/null 2>&1; then
  echo ">> wheelhouse already populated — reusing (air-gapped re-run path)"
else
  echo ">> populating wheelhouse (online) at $WHEELHOUSE"
  "$PY" -m pip download --dest "$WHEELHOUSE" atheris pyinstaller
  "$PY" -m pip download --dest "$WHEELHOUSE" --prefer-binary ".[test]"
fi

# ── 2) Test oracle: clean venv (no sanitizers) ──────────────────────────────────────────
if [ -x /mayhem/test-venv/bin/python3 ] && /mayhem/test-venv/bin/python3 -c "import cairosvg" 2>/dev/null; then
  echo ">> test venv already ready — skipping"
else
  echo ">> installing CairoSVG for test oracle (clean)"
  python3 -m venv /mayhem/test-venv
  /mayhem/test-venv/bin/pip install --upgrade pip setuptools wheel
  (
    unset CFLAGS CXXFLAGS LDFLAGS
    /mayhem/test-venv/bin/pip install --no-index --find-links="$WHEELHOUSE" ".[test]" 2>/dev/null \
      || /mayhem/test-venv/bin/pip install ".[test]"
  )
fi
ensure_test_reference
setup_test_fonts

# ── 3) Fuzz build: atheris + PyInstaller onefile ELF ────────────────────────────────────
if [ -x /mayhem/fuzz-svg ] && /mayhem/fuzz-venv/bin/python3 -c "import atheris" 2>/dev/null; then
  echo ">> fuzz-svg ELF already built — skipping PyInstaller (idempotent re-run)"
else
  echo ">> building fuzz-svg PyInstaller ELF"
  python3 -m venv /mayhem/fuzz-venv
  /mayhem/fuzz-venv/bin/pip install --upgrade pip setuptools wheel
  export CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" CXXFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" LDFLAGS="$SANITIZER_FLAGS"
  /mayhem/fuzz-venv/bin/pip install --no-index --find-links="$WHEELHOUSE" atheris pyinstaller 2>/dev/null \
    || /mayhem/fuzz-venv/bin/pip install atheris pyinstaller
  /mayhem/fuzz-venv/bin/pip install --no-index --find-links="$WHEELHOUSE" . 2>/dev/null \
    || /mayhem/fuzz-venv/bin/pip install .

  # shellcheck disable=SC2086
  $CC -shared -fPIC $DEBUG_FLAGS -o /mayhem/asan_defaults.so "$SRC/mayhem/asan_defaults.c"

  /mayhem/fuzz-venv/bin/pyinstaller \
    --distpath /tmp/pyinst-out \
    --workpath /tmp/pyinst-work \
    --specpath /tmp/pyinst-spec \
    --onefile \
    --name fuzz-svg \
    --paths "$SRC/mayhem" \
    --collect-all cairosvg \
    --hidden-import fuzz_helpers \
    --add-binary /mayhem/asan_defaults.so:. \
    "$SRC/mayhem/fuzz_svg.py"

  install -m 0755 /tmp/pyinst-out/fuzz-svg /mayhem/fuzz-svg
  graft_dwarf /mayhem/fuzz-svg
fi

# ── 4) ELF test runner (anti-reward-hack sabotage requires a non-system binary) ─────────
if [ -x "$SRC/run_tests" ]; then
  echo ">> run_tests already built — skipping"
else
  echo ">> compiling run_tests ELF test runner"
  # shellcheck disable=SC2086
  $CC -c $DEBUG_FLAGS "$SRC/mayhem/asan_defaults.c" -o /tmp/asan_defaults.o
  # shellcheck disable=SC2086
  $CC $DEBUG_FLAGS \
    -DPYTHON="\"/mayhem/test-venv/bin/python3\"" \
    "$SRC/mayhem/run_tests.c" /tmp/asan_defaults.o \
    -o "$SRC/run_tests"
  chmod +x "$SRC/run_tests"
fi

echo ">> build.sh complete"
ls -la /mayhem/fuzz-svg "$SRC/run_tests"
