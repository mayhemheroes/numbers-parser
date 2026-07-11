#!/usr/bin/env bash
#
# numbers-parser/mayhem/build.sh — build the ELF launcher shims for the Atheris fuzz harness and
# the behavioral test runner. numbers-parser (masaccio/numbers-parser) is a PURE-PYTHON package
# (it reads/writes Apple Numbers documents; its only native pieces are the protobuf/python-snappy
# wheels, installed by the Dockerfile). The Atheris harness (mayhem/fuzz_numbers.py) is a `.py`,
# but Mayhem requires the target `cmd:` to be an ELF, so we compile a tiny C shim per Python entry
# point that exec()s `python3 <script>` (see mayhem/launcher.c). The Python deps (atheris, the
# numbers-parser package + its protobuf/python-snappy/sigfig/... runtime deps) are installed into
# the image's system Python by the Dockerfile — that step needs the network and root, which this
# script (re-run offline as the non-root `mayhem` user at the PATCH tier) must NOT require. This
# script only compiles the shims, so it is idempotent and air-gapped (clang, no network).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

SRC="${SRC:-/mayhem}"
cd "$SRC"

: "${CC:=clang}"

# $DEBUG_FLAGS threads DWARF < 4 debug info onto the shims (SPEC §6.2 item 10): clang-19's plain
# `-g` emits DWARF-5, which Mayhem's triage can't read, so force DWARF-3 explicitly.
: "${DEBUG_FLAGS:=-gdwarf-3}"

# The base exports $SANITIZER_FLAGS (ASan+UBSan, halting) for projects with compiled code;
# numbers-parser has none of its own, and the shims are pure exec() wrappers (instrumenting them
# would only add ASan noise on the wrapper, never on the fuzzed Python). The real fuzzed code runs
# under Atheris/libFuzzer at runtime. Referenced here for parity / so an override is visible.
echo "SANITIZER_FLAGS=${SANITIZER_FLAGS:-<unset>} (pure-Python project; not applied to the exec shims)"
echo "DEBUG_FLAGS=$DEBUG_FLAGS"

build_launcher() {
  local out="$1" script="$2"
  echo "--- compiling launcher /mayhem/$out -> $script ---"
  # Dynamically linked (default) so the verify-repo sabotage oracle's LD_PRELOAD can reach it.
  "$CC" $DEBUG_FLAGS -O1 -DPY_SCRIPT="\"$script\"" -o "/mayhem/$out" mayhem/launcher.c
  chmod +x "/mayhem/$out"
}

# Fuzz target: the preserved Atheris harness (parses an Apple Numbers document).
build_launcher fuzz-numbers   /mayhem/mayhem/fuzz_numbers.py
# Test oracle runner: runs the numbers-parser known-answer suite (driven by mayhem/test.sh through
# this ELF so the sabotage check can neuter it).
build_launcher numbers-tests  /mayhem/mayhem/run_tests.py

echo "build.sh complete:"
ls -la /mayhem/fuzz-numbers /mayhem/numbers-tests
