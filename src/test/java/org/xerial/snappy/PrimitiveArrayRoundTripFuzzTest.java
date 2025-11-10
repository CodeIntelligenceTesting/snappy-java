// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
/// /////////////////////////////////////////////////////////////////////////////

package org.xerial.snappy;

import com.code_intelligence.jazzer.mutation.annotation.InRange;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class PrimitiveArrayRoundTripFuzzTest {
    private static final int MAX_INPUT_SIZE = 1 << 20; // 1 MiB safety bound.

    public static void fuzzerTestOneInput(byte @NotNull [] data, @InRange(max=4) short selector ) {
        if (data.length == 0) {
            return;
        }
        if (data.length > MAX_INPUT_SIZE) {
            return;
        }

        byte[] payload = Arrays.copyOfRange(data, 1, data.length);

        try {
            switch (selector % 6) {
                case 0:
                    fuzzChars(payload);
                    break;
                case 1:
                    fuzzShorts(payload);
                    break;
                case 2:
                    fuzzInts(payload);
                    break;
                case 3:
                    fuzzLongs(payload);
                    break;
                case 4:
                    fuzzFloats(payload);
                    break;
                default:
                    fuzzDoubles(payload);
                    break;
            }
        } catch (IOException | SnappyError ignored) {
        }
    }

    private static void fuzzChars(byte[] payload) throws IOException {
        char[] input = new char[payload.length];
        for (int i = 0; i < payload.length; i++) {
            input[i] = (char) (payload[i] & 0xFF);
        }
        byte[] compressed = Snappy.compress(input);
        char[] roundTrip = Snappy.uncompressCharArray(compressed);
        if (!Arrays.equals(input, roundTrip)) {
            throw new AssertionError("char[] round-trip mismatch");
        }
    }

    private static void fuzzShorts(byte[] payload) throws IOException {
        int count = payload.length / 2;
        short[] input = new short[count];
        if (count > 0) {
            ByteBuffer.wrap(payload, 0, count * 2).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().get(input);
        }
        byte[] compressed = Snappy.compress(input);
        short[] roundTrip = Snappy.uncompressShortArray(compressed);
        if (!Arrays.equals(input, roundTrip)) {
            throw new AssertionError("short[] round-trip mismatch");
        }
    }

    private static void fuzzInts(byte[] payload) throws IOException {
        int count = payload.length / 4;
        int[] input = new int[count];
        if (count > 0) {
            ByteBuffer.wrap(payload, 0, count * 4).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(input);
        }
        byte[] compressed = Snappy.compress(input);
        int[] roundTrip = Snappy.uncompressIntArray(compressed);
        if (!Arrays.equals(input, roundTrip)) {
            throw new AssertionError("int[] round-trip mismatch");
        }
    }

    private static void fuzzLongs(byte[] payload) throws IOException {
        int count = payload.length / 8;
        long[] input = new long[count];
        if (count > 0) {
            ByteBuffer.wrap(payload, 0, count * 8).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer().get(input);
        }
        byte[] compressed = Snappy.compress(input);
        long[] roundTrip = Snappy.uncompressLongArray(compressed);
        if (!Arrays.equals(input, roundTrip)) {
            throw new AssertionError("long[] round-trip mismatch");
        }
    }

    private static void fuzzFloats(byte[] payload) throws IOException {
        int count = payload.length / 4;
        float[] input = new float[count];
        if (count > 0) {
            ByteBuffer.wrap(payload, 0, count * 4).order(ByteOrder.LITTLE_ENDIAN).asFloatBuffer().get(input);
        }
        byte[] compressed = Snappy.compress(input);
        float[] roundTrip = Snappy.uncompressFloatArray(compressed);
        if (!Arrays.equals(input, roundTrip)) {
            throw new AssertionError("float[] round-trip mismatch");
        }
    }

    private static void fuzzDoubles(byte[] payload) throws IOException {
        int count = payload.length / 8;
        double[] input = new double[count];
        if (count > 0) {
            ByteBuffer.wrap(payload, 0, count * 8).order(ByteOrder.LITTLE_ENDIAN).asDoubleBuffer().get(input);
        }
        byte[] compressed = Snappy.compress(input);
        double[] roundTrip = Snappy.uncompressDoubleArray(compressed);
        if (!Arrays.equals(input, roundTrip)) {
            throw new AssertionError("double[] round-trip mismatch");
        }
    }
}
