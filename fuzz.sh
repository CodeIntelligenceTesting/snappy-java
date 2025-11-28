#!/bin/bash

set -euo pipefail

FUZZ_TIME="${FUZZ_TIME:-3600}"
COVERAGE_DIR="target/coverage"
CORPUS_ROOT="${CORPUS_ROOT:-target/corpus}"
mkdir -p "${COVERAGE_DIR}" "${CORPUS_ROOT}"

JACOCO_VERSION="0.8.14"
JACOCO_CLI_JAR="${COVERAGE_DIR}/jacoco-cli-${JACOCO_VERSION}.jar"
JACOCO_AGENT_JAR="${COVERAGE_DIR}/jacocoagent-${JACOCO_VERSION}.jar"

download_jacoco_cli() {
  if [[ ! -f "${JACOCO_CLI_JAR}" ]]; then
    echo "Downloading JaCoCo CLI ${JACOCO_VERSION}..."
    curl -fsSL "https://repo1.maven.org/maven2/org/jacoco/org.jacoco.cli/${JACOCO_VERSION}/org.jacoco.cli-${JACOCO_VERSION}-nodeps.jar" \
      -o "${JACOCO_CLI_JAR}"
  fi
  if [[ ! -f "${JACOCO_AGENT_JAR}" ]]; then
    echo "Downloading JaCoCo Agent ${JACOCO_VERSION}..."
    curl -fsSL "https://repo1.maven.org/maven2/org/jacoco/org.jacoco.agent/${JACOCO_VERSION}/org.jacoco.agent-${JACOCO_VERSION}-runtime.jar" \
      -o "${JACOCO_AGENT_JAR}"
  fi
}


download_jacoco_cli

echo "Building JVM classes and exporting classpath via sbt..."
JAZZER_CLASSPATH="$(
  ./sbt -error 'package' 'export Test / fullClasspath' | tail -n 1
)"

if [[ -z "${JAZZER_CLASSPATH}" ]]; then
  echo "Unable to determine Jazzer classpath from sbt output" >&2
  exit 1
fi

mapfile -t FUZZ_FILES < <(find src/test/java -name '*FuzzTest.java' | sort)
if [[ ${#FUZZ_FILES[@]} -eq 0 ]]; then
  echo "No *FuzzTest.java files found." >&2
  exit 1
fi

for file in "${FUZZ_FILES[@]}"; do
  rel="${file#src/test/java/}"
  class="${rel%.java}"
  class="${class//\//.}"

  echo "=== Running fuzzing for ${class} (FUZZ_TIME=${FUZZ_TIME}s) ==="
  ./run.sh "${class}" "-max_total_time=${FUZZ_TIME}" --keep_going=100 -use_value_profile=1 -jobs=6

  sanitized="${class//./_}"
  corpus_dir="${CORPUS_ROOT}/${sanitized}"
  exec_file="${COVERAGE_DIR}/java-${sanitized}.exec"
  xml_file="${COVERAGE_DIR}/java-${sanitized}.xml"
  html_dir="${COVERAGE_DIR}/html-${sanitized}"
  mkdir -p "${corpus_dir}"

  echo "=== Replaying corpus for coverage: ${class} ==="
  rm -f "${exec_file}" "${xml_file}"
  rm -rf "${html_dir}"
  temp_corpus="$(mktemp -d)"

  java \
    -cp "${JAZZER_CLASSPATH}" \
    -javaagent:${JACOCO_AGENT_JAR}=destfile=${exec_file},excludes=com.code_intelligence.jazzer.*:com.sun.tools.attach.VirtualMachine \
    com.code_intelligence.jazzer.Jazzer \
    --target_class="${class}" \
    --nohooks \
    --asan \
    -runs=0 \
    -merge=1 \
    ${temp_corpus} \
    "${corpus_dir}"


  if [[ -f "${exec_file}" ]]; then
    java -jar "${JACOCO_CLI_JAR}" report "${exec_file}" \
      --classfiles target/classes \
      --sourcefiles src/main/java \
      --xml "${xml_file}" \
      --html "${html_dir}" >/dev/null

  else
    echo "Warning: JaCoCo exec file ${exec_file} not found; skipping." >&2
  fi
done

mapfile -t EXEC_FILES < <(find "${COVERAGE_DIR}" -maxdepth 1 -name 'java-*.exec' | sort)
if [[ ${#EXEC_FILES[@]} -eq 0 ]]; then
  echo "No JaCoCo execution data was produced; aborting merge." >&2
  exit 1
fi

MERGED_EXEC="${COVERAGE_DIR}/jacoco-merged.exec"
MERGED_XML="${COVERAGE_DIR}/jacoco-merged.xml"
MERGED_HTML="${COVERAGE_DIR}/html-merged"
rm -f "${MERGED_EXEC}" "${MERGED_XML}"
rm -rf "${MERGED_HTML}"

echo "Merging ${#EXEC_FILES[@]} JaCoCo exec files into ${MERGED_EXEC}..."
java -jar "${JACOCO_CLI_JAR}" merge "${EXEC_FILES[@]}" --destfile "${MERGED_EXEC}"

java -jar "${JACOCO_CLI_JAR}" report "${MERGED_EXEC}" \
  --classfiles target/classes \
  --sourcefiles src/main/java \
  --xml "${MERGED_XML}" \
  --html "${MERGED_HTML}" >/dev/null

echo "Merged JaCoCo execution data written to ${MERGED_EXEC}"
echo "Merged XML coverage report available at ${MERGED_XML}"
echo "Merged HTML report available at ${MERGED_HTML}/index.html"
