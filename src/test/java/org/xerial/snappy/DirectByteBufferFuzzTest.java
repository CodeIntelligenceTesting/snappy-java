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

import com.code_intelligence.jazzer.mutation.annotation.NotNull;

import java.io.IOException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class DirectByteBufferFuzzTest {
    private static final int MAX_INPUT_SIZE = 1 << 20; // 1 MiB guard to avoid OOM during fuzzing.

    public static void fuzzerTestOneInput(byte @NotNull [] data) {
        if (data.length > MAX_INPUT_SIZE) {
            return;
        }

        ByteBuffer inputBuffer = ByteBuffer.allocateDirect(Math.max(1, data.length));
        inputBuffer.put(data);
        ((Buffer) inputBuffer).flip();

        try {
            int maxCompressedLength = Math.max(1, Snappy.maxCompressedLength(data.length));
            ByteBuffer compressedBuffer = ByteBuffer.allocateDirect(maxCompressedLength);

            int compressedSize = Snappy.compress(inputBuffer, compressedBuffer);
            ((Buffer) compressedBuffer).limit(compressedSize);
            ((Buffer) compressedBuffer).position(0);

            ByteBuffer compressedView = compressedBuffer.duplicate();
            ((Buffer) compressedView).position(0);
            ((Buffer) compressedView).limit(compressedSize);

            ByteBuffer uncompressedBuffer = ByteBuffer.allocateDirect(Math.max(1, data.length + 32));
            int uncompressedSize = Snappy.uncompress(compressedView, uncompressedBuffer);
            if (uncompressedSize != data.length) {
                throw new AssertionError("Unexpected uncompressed length");
            }

            byte[] roundTrip = new byte[uncompressedSize];
            ((Buffer) uncompressedBuffer).limit(uncompressedSize);
            ((Buffer) uncompressedBuffer).position(0);
            uncompressedBuffer.get(roundTrip);

            if (!Arrays.equals(data, roundTrip)) {
                throw new AssertionError("Round-trip mismatch for direct ByteBuffer API");
            }
        } catch (IOException | SnappyError ignored) {
        }
    }
}
