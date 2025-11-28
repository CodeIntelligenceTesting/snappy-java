# Fuzz Testing in Snappy for Java

Fuzz tests can be found in `src/test/java/org/xerial/snappy/*FuzzTest.java`. They don't run with the JUnit integration
because this project uses Junit 4 and it requires native libraries (currently not supported with the JUnit runner).

The fuzz test with the highest coverage is `ManualFuzzTest.java` which tests the 3 scenarios:

- "Normal" snappy format
- Streams of "normal" snappy format data
- Framed snappy format

For all scenarios round trips are tested and compared with the implementation of commons-compress. The `@ValuePool`
annotation is used to generate a variety of valid compressed input data.

Additional fuzz tests to mention:

- `OSInfoFuzzTest.java`: exercises OS information retrieval code paths
- `SnappyHadoopCompatibleFuzzTest.java`: exercises the Hadoop compatible snappy format


## Running the Fuzz Tests

Individual fuzz tests can be run with the `./run.sh` script. For example:

```bash
./run.sh org.xerial.snappy.ManualFuzzTest --keep_going=10 -use_value_profile=1
```

All fuzz tests can be run for 10 seconds with the `fuzz.sh` script:

```bash
FUZZ_TIME=10 ./fuzz.sh
```

This will also generate a coverage report in the `target/coverage` directory.