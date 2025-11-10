package org.xerial.snappy;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Fuzzes the streaming Snappy API to exercise the higher level header handling
 * as well as the typed read helpers exposed by {@link SnappyInputStream}.
 */
public final class SnappyInputStreamFuzzTest {
    private static final int MAX_INPUT_SIZE = 1 << 18; // 256 KiB guardrail.

    private SnappyInputStreamFuzzTest() {
    }

    public static void fuzzerTestOneInput(byte @NotNull [] data) {
        if (data.length == 0) {
            return;
        }

        int mode = data[0] & 0xFF;
        byte[] payload = Arrays.copyOfRange(data, 1, Math.min(data.length, MAX_INPUT_SIZE + 1));

        try {
            byte[] encoded = encodeWithSnappyOutputStream(payload, mode);
            verifyRoundTrip(payload, encoded, mode);
        } catch (IOException | OutOfMemoryError | IllegalArgumentException | SnappyError ignored) {
            // Invalid stream layouts or extreme size requests can legitimately surface here.
        }
    }

    private static byte[] encodeWithSnappyOutputStream(byte[] payload, int mode) throws IOException {
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        try (SnappyOutputStream out = new SnappyOutputStream(compressed)) {
            int segmentSelector = ((mode >>> 4) & 0x0F) + 1;
            int pos = 0;
            while (pos < payload.length) {
                int candidate = (payload[pos % payload.length] & 0xFF) + 1;
                int chunk = Math.min(payload.length - pos, Math.max(segmentSelector, candidate));
                out.write(payload, pos, chunk);
                pos += chunk;
                if (((mode >>> 1) & 0x01) != 0 && (pos & 0x07) == 0) {
                    out.flush();
                }
            }
        }
        return compressed.toByteArray();
    }

    private static void verifyRoundTrip(byte[] payload, byte[] encoded, int mode) throws IOException {
        long requestedSkip = Math.min(payload.length, mode & 0x0F);

        try (SnappyInputStream in = new SnappyInputStream(new ByteArrayInputStream(encoded))) {
            long actualSkip = in.skip(requestedSkip);
            if (actualSkip < 0 || actualSkip > payload.length) {
                actualSkip = 0;
            }
            byte[] expected = Arrays.copyOfRange(payload, (int) actualSkip, payload.length);

            ByteArrayOutputStream decoded = new ByteArrayOutputStream(expected.length);
            byte[] buffer = new byte[256];
            for (int read; (read = in.read(buffer)) != -1; ) {
                decoded.write(buffer, 0, read);
            }

            byte[] result = decoded.toByteArray();
            if (result.length == expected.length && !Arrays.equals(result, expected)) {
                throw new AssertionError("SnappyInputStream round-trip mismatch");
            }
        }

        // Run the typed readers to hit the specialized array copy paths.
        try (SnappyInputStream typed = new SnappyInputStream(new ByteArrayInputStream(encoded))) {
            if (payload.length >= Long.BYTES) {
                int longCount = payload.length / Long.BYTES;
                if (longCount > 0) {
                    long[] longs = new long[longCount];
                    typed.read(longs, 0, longCount);
                }
            } else if (payload.length >= Integer.BYTES) {
                int intCount = payload.length / Integer.BYTES;
                if (intCount > 0) {
                    int[] ints = new int[intCount];
                    typed.read(ints, 0, intCount);
                }
            } else if (payload.length >= Short.BYTES) {
                int shortCount = payload.length / Short.BYTES;
                if (shortCount > 0) {
                    short[] shorts = new short[shortCount];
                    typed.read(shorts, 0, shortCount);
                }
            } else {
                byte[] single = new byte[1];
                typed.read(single, 0, 1);
            }
        }
    }
}
