#!/bin/bash

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target_class> [jazzer_flags...]" >&2
  exit 1
fi

CLASS="$1"
shift
REST_ARGS=("$@")

SANITIZED_CLASS="${CLASS//./_}"
CORPUS_ROOT="${CORPUS_ROOT:-target/corpus}"
mkdir -p "${CORPUS_ROOT}"
DEFAULT_CORPUS_DIR="${CORPUS_ROOT}/${SANITIZED_CLASS}"
CORPUS_DIR="${CORPUS_DIR:-${DEFAULT_CORPUS_DIR}}"
mkdir -p "${CORPUS_DIR}"
echo "Using corpus directory: ${CORPUS_DIR}"

export CC=clang
export CXX=clang++
MAKE_BIN="${MAKE:-make}"

echo "Ensuring native library is built with fuzzing + ASAN instrumentation..."
"${MAKE_BIN}" native >/dev/null

echo "Building JVM classes and exporting classpath via sbt..."
./sbt package

JAZZER_CLASSPATH="$(
  ./sbt -error 'export Test / fullClasspath' | tail -n 1
)"

if [[ -z "${JAZZER_CLASSPATH}" ]]; then
  echo "Unable to determine Jazzer classpath from sbt output" >&2
  exit 1
fi

echo  "java -cp ${JAZZER_CLASSPATH} com.code_intelligence.jazzer.Jazzer --target_class=${CLASS} --asan ${CORPUS_DIR} ${REST_ARGS[@]}"

java \
  -Xmx2000m \
  -cp "${JAZZER_CLASSPATH}" \
  com.code_intelligence.jazzer.Jazzer \
  --target_class="${CLASS}" \
  --asan \
  "${CORPUS_DIR}" \
  "${REST_ARGS[@]}"
