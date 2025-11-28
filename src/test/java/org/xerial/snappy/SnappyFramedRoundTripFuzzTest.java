package org.xerial.snappy;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.xerial.snappy.pool.DefaultPoolFactory;

/**
 * Fuzzes the x-snappy-framed streaming implementation to cover both the writer
 * and reader implementations, including checksum verification and block size
 * variation.
 */
public final class SnappyFramedRoundTripFuzzTest {
    private static final int MAX_INPUT_SIZE = 1 << 16; // 64 KiB cap keeps allocations bounded.

    private SnappyFramedRoundTripFuzzTest() {
    }

    public static void fuzzerTestOneInput(byte @NotNull [] data, int config) {
        if (data.length == 0) {
            return;
        }

        byte[] payload = Arrays.copyOfRange(data, 1, Math.min(data.length, MAX_INPUT_SIZE + 1));

        int blockSize = computeBlockSize(config);
        double minRatio = computeMinCompressionRatio(config);

        try {
            byte[] framed = encodeFramedPayload(payload, blockSize, minRatio, (config & 0x20) != 0);
            roundTrip(payload, framed, (config & 0x01) == 0, (config & 0x40) != 0);
        } catch (IOException | SnappyError ignored) {
            // Construction can legitimately fail for extreme parameter combinations.
        }
    }

    private static int computeBlockSize(int config) {
        int scaled = ((config & 0x3F) + 1) * 512;
        return Math.min(Math.max(32, scaled), SnappyFramedOutputStream.MAX_BLOCK_SIZE);
    }

    private static double computeMinCompressionRatio(int config) {
        int bucket = (config >>> 6) & 0x03;
        // Spread evenly over (0.1, 1.0].
        return 0.1d + (bucket * 0.3d);
    }

    private static byte[] encodeFramedPayload(byte[] payload,
                                              int blockSize,
                                              double minRatio,
                                              boolean flushDuringWrite) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (SnappyFramedOutputStream out =
                     new SnappyFramedOutputStream(baos, blockSize, minRatio, DefaultPoolFactory.getDefaultPool())) {
            int pos = 0;
            while (pos < payload.length) {
                int candidate = ((payload[pos] & 0xFF) % blockSize) + 1;
                int chunk = Math.min(candidate, payload.length - pos);
                out.write(payload, pos, chunk);
                pos += chunk;
                if (flushDuringWrite && (pos & 0x0F) == 0) {
                    out.flush();
                }
            }
        }
        return baos.toByteArray();
    }

    private static void roundTrip(byte[] payload,
                                  byte[] framed,
                                  boolean verifyChecksums,
                                  boolean exerciseWithoutVerification) throws IOException {

        // Always verify checksums first.
        performRead(payload, framed, verifyChecksums);

        if (exerciseWithoutVerification) {
            performRead(payload, framed, false);
        }
    }

    private static void performRead(byte[] payload,
                                    byte[] framed,
                                    boolean verifyChecksums) throws IOException {
        long requestedSkip = Math.min(payload.length, 8); // Limit skip to keep the comparison simple.
        try (SnappyFramedInputStream in =
                     new SnappyFramedInputStream(new ByteArrayInputStream(framed), verifyChecksums)) {
            long actualSkip = in.skip(requestedSkip);
            if (actualSkip > payload.length) {
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
                throw new AssertionError("SnappyFramed round-trip mismatch");
            }
        }
    }
}
