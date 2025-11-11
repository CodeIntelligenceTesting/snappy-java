#!/bin/bash

set -euo pipefail

FUZZ_TIME="${FUZZ_TIME:-60}"
COVERAGE_DIR="target/coverage"
mkdir -p "${COVERAGE_DIR}"

if ! command -v lcov >/dev/null || ! command -v genhtml >/dev/null; then
  echo "Error: lcov and genhtml are required to merge coverage reports." >&2
  exit 1
fi

mapfile -t FUZZ_FILES < <(find src/test/java \( -name '*FuzzTest.java' -o -name '*FuzzerTest.java' \) | sort)
if [[ ${#FUZZ_FILES[@]} -eq 0 ]]; then
  echo "No *FuzzTest.java files found." >&2
  exit 1
fi

COMBINED_INFOS=()

for file in "${FUZZ_FILES[@]}"; do
  rel="${file#src/test/java/}"
  class="${rel%.java}"
  class="${class//\//.}"

  echo "=== Running fuzz coverage for ${class} (FUZZ_TIME=${FUZZ_TIME}s) ==="
  ./run.sh "${class}" "-max_total_time=${FUZZ_TIME}"

  sanitized="${class//./_}"
  combined_info="${COVERAGE_DIR}/combined-${sanitized}.info"
  if [[ -f "${combined_info}" ]]; then
    COMBINED_INFOS+=("${combined_info}")
  else
    echo "Warning: Combined coverage file ${combined_info} not found; skipping." >&2
  fi
done

if [[ ${#COMBINED_INFOS[@]} -eq 0 ]]; then
  echo "No combined LCOV files were produced; aborting merge." >&2
  exit 1
fi

OVERALL_INFO="${COVERAGE_DIR}/combined-all.info"
OVERALL_HTML="${COVERAGE_DIR}/html-all"
rm -f "${OVERALL_INFO}"
rm -rf "${OVERALL_HTML}"

echo "Merging ${#COMBINED_INFOS[@]} LCOV reports into ${OVERALL_INFO}..."

lcov -q -a "${COMBINED_INFOS[0]}" -o "${OVERALL_INFO}"
for info in "${COMBINED_INFOS[@]:1}"; do
  lcov -q -a "${OVERALL_INFO}" -a "${info}" -o "${OVERALL_INFO}.tmp"
  mv "${OVERALL_INFO}.tmp" "${OVERALL_INFO}"
done

genhtml -q "${OVERALL_INFO}" --output-directory "${OVERALL_HTML}"

echo "Global LCOV coverage written to ${OVERALL_INFO}"
echo "Global HTML report available at ${OVERALL_HTML}/index.html"
