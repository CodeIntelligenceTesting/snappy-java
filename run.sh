#!/bin/bash

all_args=("$@")
class="$1"
rest_args=("${all_args[@]:1}")

./sbt package
java -cp target/classes:target/test-classes:/home/simon/.m2/repository/com/code-intelligence/jazzer-junit/0.0.0-dev/jazzer-junit-0.0.0-dev.jar:/home/simon/.m2/repository/com/code-intelligence/jazzer/0.0.0-dev/jazzer-0.0.0-dev.jar:/home/simon/.m2/repository/com/code-intelligence/jazzer-api/0.0.0-dev/jazzer-api-0.0.0-dev.jar   com.code_intelligence.jazzer.Jazzer  --target_class=$class --asan $rest_args
