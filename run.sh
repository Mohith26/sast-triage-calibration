#!/usr/bin/env bash
# Reproduce everything from a fresh clone: fetch pinned inputs, run Semgrep, run the study.
set -euo pipefail
cd "$(dirname "$0")"
BENCH_SHA=d4f6f3a53be73c3c8a24dafc7f4e486d82e6744a
RULES_SHA=16b9e6d45f10649f6a531ec4838ed9924372c3bc

fetch() {  # fetch <url> <dir> <sha>
  if [ ! -d "$2" ]; then
    git init -q "$2" && git -C "$2" remote add origin "$1"
    git -C "$2" fetch -q --depth 1 origin "$3" && git -C "$2" checkout -q FETCH_HEAD
  fi
}
fetch https://github.com/OWASP-Benchmark/BenchmarkJava.git BenchmarkJava "$BENCH_SHA"
fetch https://github.com/semgrep/semgrep-rules.git semgrep-rules "$RULES_SHA"

semgrep scan --metrics=off --config semgrep-rules/java --json -o semgrep_java.json -j 4 --timeout 30 \
  BenchmarkJava/src/main/java/org/owasp/benchmark/testcode
python study/run_study.py semgrep_java.json > study/results.json
cat study/results.json
