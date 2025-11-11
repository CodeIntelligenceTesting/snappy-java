#!/bin/bash

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target_class> [jazzer_flags...]" >&2
  exit 1
fi

CLASS="$1"
shift
REST_ARGS=("$@")

COVERAGE_DIR="target/coverage"
mkdir -p "${COVERAGE_DIR}"
SANITIZED_CLASS="${CLASS//./_}"

NATIVE_COVERAGE_LCOV="${COVERAGE_DIR}/native-${SANITIZED_CLASS}.info"

# Build coverage-instrumented native library.
COV_CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping"
COV_LINKFLAGS="-fprofile-instr-generate"
MAKE_BIN="${MAKE:-make}"

if ! command -v "${MAKE_BIN}" >/dev/null; then
  echo "Error: make not found on PATH." >&2
  exit 1
fi

if ! command -v clang >/dev/null || ! command -v clang++ >/dev/null; then
  echo "Error: clang/clang++ are required for coverage builds." >&2
  exit 1
fi

export CC=clang
export CXX=clang++

#echo "Rebuilding native library with coverage instrumentation..."
#"${MAKE_BIN}" clean-native >/dev/null
#CXXFLAGS_EXTRA="${COV_CXXFLAGS}" LINKFLAGS_EXTRA="${COV_LINKFLAGS}" STRIP=: "${MAKE_BIN}" native >/dev/null

# Clear out stale native coverage files to avoid mixing runs.
find "${COVERAGE_DIR}" -maxdepth 1 -type f -name "native-${SANITIZED_CLASS}-*.profraw" -delete || true

export LLVM_PROFILE_FILE="${COVERAGE_DIR}/native-${SANITIZED_CLASS}-%m.profraw"

JAVA_COVERAGE_EXEC="${COVERAGE_DIR}/java-${SANITIZED_CLASS}.exec"
JAVA_COVERAGE_XML="${COVERAGE_DIR}/java-${SANITIZED_CLASS}.xml"
JAVA_COVERAGE_LCOV="${COVERAGE_DIR}/java-${SANITIZED_CLASS}.info"
rm -f "${JAVA_COVERAGE_EXEC}" "${JAVA_COVERAGE_XML}" "${JAVA_COVERAGE_LCOV}" "${NATIVE_COVERAGE_LCOV}"

./sbt package

java -cp target/classes:target/test-classes:/home/simon/.m2/repository/com/code-intelligence/jazzer-junit/0.0.0-dev/jazzer-junit-0.0.0-dev.jar:/home/simon/.m2/repository/com/code-intelligence/jazzer/0.0.0-dev/jazzer-0.0.0-dev.jar:/home/simon/.m2/repository/com/code-intelligence/jazzer-api/0.0.0-dev/jazzer-api-0.0.0-dev.jar \
  com.code_intelligence.jazzer.Jazzer --target_class="${CLASS}" --asan --coverage_dump="${JAVA_COVERAGE_EXEC}" "${REST_ARGS[@]}"

# Generate native coverage report if instrumentation data is available.
shopt -s nullglob
PROFRAWS=("${COVERAGE_DIR}"/native-"${SANITIZED_CLASS}"-*.profraw)
shopt -u nullglob

if [[ ${#PROFRAWS[@]} -gt 0 ]]; then
  if ! command -v llvm-profdata >/dev/null || ! command -v llvm-cov >/dev/null; then
    echo "Skipping native coverage report: llvm-profdata/llvm-cov not found on PATH." >&2
    exit 0
  fi

  PROF_DATA="${COVERAGE_DIR}/native-${SANITIZED_CLASS}.profdata"
  llvm-profdata merge -sparse "${PROFRAWS[@]}" -o "${PROF_DATA}"

  NATIVE_LIB="target/classes/org/xerial/snappy/native/Linux/x86_64/libsnappyjava.so"
  if [[ ! -f "${NATIVE_LIB}" ]]; then
    ALTERNATE_LIB="src/main/resources/org/xerial/snappy/native/Linux/x86_64/libsnappyjava.so"
    if [[ -f "${ALTERNATE_LIB}" ]]; then
      NATIVE_LIB="${ALTERNATE_LIB}"
    else
NATIVE_LIB=""
    fi
  fi

  if [[ -z "${NATIVE_LIB}" ]]; then
    echo "Skipping native coverage report: unable to locate libsnappyjava.so in target/ or src/main/resources/." >&2
    exit 0
  fi

  COVERAGE_TXT="${COVERAGE_DIR}/native-${SANITIZED_CLASS}.txt"
  llvm-cov report "${NATIVE_LIB}" --instr-profile="${PROF_DATA}" > "${COVERAGE_TXT}"
  echo "Native coverage report written to ${COVERAGE_TXT}"

  llvm-cov export "${NATIVE_LIB}" --instr-profile="${PROF_DATA}" --format=lcov > "${NATIVE_COVERAGE_LCOV}"
  echo "Native LCOV coverage written to ${NATIVE_COVERAGE_LCOV}"

  if command -v lcov >/dev/null 2>&1; then
    FILTERED_LCOV="${NATIVE_COVERAGE_LCOV}.tmp"
    if lcov -q --remove "${NATIVE_COVERAGE_LCOV}" '*/lib/inc_*' --ignore-errors unused -o "${FILTERED_LCOV}" 2>/dev/null; then
      mv "${FILTERED_LCOV}" "${NATIVE_COVERAGE_LCOV}"
      echo "Filtered native LCOV to exclude bundled headers."
    else
      rm -f "${FILTERED_LCOV}"
    fi
  fi
else
  echo "No native coverage data (.profraw files) found for ${CLASS}; ensure the native library is built with coverage instrumentation." >&2
fi

# Generate Java coverage reports if the JaCoCo exec file is present.
if [[ -f "${JAVA_COVERAGE_EXEC}" ]]; then
  JACOCO_VERSION="0.8.11"
  JACOCO_CLI_JAR="${COVERAGE_DIR}/jacoco-cli-${JACOCO_VERSION}.jar"
  if [[ ! -f "${JACOCO_CLI_JAR}" ]]; then
    echo "Downloading JaCoCo CLI ${JACOCO_VERSION}..."
    curl -fsSL "https://repo1.maven.org/maven2/org/jacoco/org.jacoco.cli/${JACOCO_VERSION}/org.jacoco.cli-${JACOCO_VERSION}-nodeps.jar" -o "${JACOCO_CLI_JAR}"
  fi

  java -jar "${JACOCO_CLI_JAR}" report "${JAVA_COVERAGE_EXEC}" \
    --classfiles target/classes \
    --sourcefiles src/main/java \
    --xml "${JAVA_COVERAGE_XML}" >/dev/null

  export COVERAGE_XML="${JAVA_COVERAGE_XML}"
  export COVERAGE_LCOV="${JAVA_COVERAGE_LCOV}"

  python3 - <<'PY'
import os
import xml.etree.ElementTree as ET

xml_path = os.environ["COVERAGE_XML"]
lcov_path = os.environ["COVERAGE_LCOV"]
source_roots = [os.path.abspath("src/main/java")]

tree = ET.parse(xml_path)
root = tree.getroot()

records = []
for package in root.findall(".//package"):
    pkg_name = package.get("name", "")
    pkg_path = pkg_name.replace(".", os.sep)
    for source in package.findall("sourcefile"):
        name = source.get("name")
        relative_path = os.path.join(pkg_path, name) if pkg_path else name
        full_path = None
        for prefix in source_roots:
            candidate = os.path.join(prefix, relative_path)
            if os.path.exists(candidate):
                full_path = os.path.relpath(candidate)
                break
        if full_path is None:
            full_path = relative_path

        lines = source.findall("line")
        if not lines:
            continue

        entries = []
        lf = 0
        lh = 0
        for line in lines:
            nr = line.get("nr")
            if nr is None:
                continue
            nr = int(nr)
            ci = int(line.get("ci", "0"))
            mi = int(line.get("mi", "0"))
            hits = ci
            if mi == 0 and ci == 0:
                continue
            lf += 1
            if hits > 0:
                lh += 1
            entries.append(f"DA:{nr},{hits}")
        if not entries:
            continue

        records.append("\n".join([
            "TN:",
            f"SF:{full_path}"
        ] + entries + [
            f"LF:{lf}",
            f"LH:{lh}",
            "end_of_record"
        ]))

with open(lcov_path, "w", encoding="utf-8") as out:
    out.write("\n".join(records))
PY
  echo "Java LCOV coverage written to ${JAVA_COVERAGE_LCOV}"

  if command -v lcov >/dev/null 2>&1; then
    FILTERED_JAVA_LCOV="${JAVA_COVERAGE_LCOV}.tmp"
    if lcov -q --remove "${JAVA_COVERAGE_LCOV}" '*/src/test/java/*' --ignore-errors unused -o "${FILTERED_JAVA_LCOV}" 2>/dev/null; then
      mv "${FILTERED_JAVA_LCOV}" "${JAVA_COVERAGE_LCOV}"
      echo "Filtered Java LCOV to exclude test sources."
    else
      rm -f "${FILTERED_JAVA_LCOV}"
    fi
  fi
else
  echo "No Java coverage data found; Jazzer did not produce ${JAVA_COVERAGE_EXEC}." >&2
fi

# Merge Java and native coverage and emit HTML report if both LCOV files exist.
if [[ -f "${JAVA_COVERAGE_LCOV}" && -f "${NATIVE_COVERAGE_LCOV}" ]]; then
  if ! command -v lcov >/dev/null || ! command -v genhtml >/dev/null; then
    echo "Skipping combined coverage: lcov/genhtml not found on PATH." >&2
  else
    COMBINED_LCOV="${COVERAGE_DIR}/combined-${SANITIZED_CLASS}.info"
    HTML_DIR="${COVERAGE_DIR}/html-${SANITIZED_CLASS}"
    rm -f "${COMBINED_LCOV}"
    rm -rf "${HTML_DIR}"

    lcov -q -a "${NATIVE_COVERAGE_LCOV}" -a "${JAVA_COVERAGE_LCOV}" -o "${COMBINED_LCOV}"
    echo "Combined LCOV coverage written to ${COMBINED_LCOV}"

    genhtml -q "${COMBINED_LCOV}" --output-directory "${HTML_DIR}"
    echo "Combined HTML report generated at ${HTML_DIR}/index.html"
  fi
else
  echo "Skipping combined report: missing Java or native LCOV file." >&2
fi
