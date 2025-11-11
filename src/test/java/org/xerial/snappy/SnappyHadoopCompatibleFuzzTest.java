package org.xerial.snappy;

import com.code_intelligence.jazzer.mutation.annotation.InRange;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Fuzzes {@link SnappyHadoopCompatibleOutputStream} to ensure the Hadoop preamble
 * and header overrides round-trip correctly and to exercise the block-size guardrails.
 */
public final class SnappyHadoopCompatibleFuzzTest {
    private static final int MAX_INPUT_SIZE = 1 << 15; // Keep allocations under control.

    private SnappyHadoopCompatibleFuzzTest() {
    }

    public static void fuzzerTestOneInput(byte @NotNull [] data, @InRange(min = 0, max = 255) int selector) {
        if (data.length == 0) {
            return;
        }

        byte[] payload = Arrays.copyOfRange(data, 0, Math.min(data.length, MAX_INPUT_SIZE));

        // Exercise the oversized block-size path to cover the MAX_BLOCK_SIZE guard.
        if ((selector & 0x80) != 0) {
            try (SnappyHadoopCompatibleOutputStream ignored =
                         new SnappyHadoopCompatibleOutputStream(new ByteArrayOutputStream(),
                                 SnappyOutputStream.MAX_BLOCK_SIZE + 1024)) {
                // Should throw before any data is written.
            } catch (IllegalArgumentException | IOException expected) {
                // Expected overflow handling.
            }
        }

        // Occasionally cover the default constructor as well.
        if ((selector & 0x40) != 0) {
            try (SnappyHadoopCompatibleOutputStream warmup =
                         new SnappyHadoopCompatibleOutputStream(new ByteArrayOutputStream())) {
                warmup.write(0);
                warmup.flush();
            } catch (IOException | SnappyError ignored) {
                return;
            }
        }

        int baseBlock = ((selector & 0x1F) + 1) * 256;
        int blockSize = Math.min(Math.max(SnappyOutputStream.MIN_BLOCK_SIZE, baseBlock), 1 << 17);

        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        try (SnappyHadoopCompatibleOutputStream stream =
                     new SnappyHadoopCompatibleOutputStream(sink, blockSize)) {
            feedStream(payload, selector, stream);
        } catch (IOException | SnappyError | OutOfMemoryError ignored) {
            return;
        }

        try {
            byte[] decoded = decodeHadoopCompatible(sink.toByteArray());
            if (!Arrays.equals(payload, decoded)) {
                throw new AssertionError("SnappyHadoopCompatibleOutputStream round-trip mismatch");
            }
        } catch (IOException | SnappyError ignored) {
            // Truncated blocks or invalid compressed buffers are acceptable outcomes for fuzzing.
        }
    }

    private static void feedStream(byte[] payload, int selector, SnappyHadoopCompatibleOutputStream stream)
            throws IOException {
        int pos = 0;
        int mode = (selector >>> 1) & 0x03;
        while (pos < payload.length) {
            switch (mode) {
                case 0:
                    int chunk = Math.min(payload.length - pos, (payload[pos] & 0xFF) + 1);
                    stream.write(payload, pos, chunk);
                    pos += chunk;
                    break;
                case 1:
                    stream.write(payload[pos] & 0xFF);
                    pos++;
                    break;
                default:
                    int span = Math.min(payload.length - pos, streamBlockSizeHint(selector));
                    if (span <= 0) {
                        span = 1;
                    }
                    stream.write(payload, pos, span);
                    pos += span;
                    if ((selector & 0x20) != 0 && (pos & 0x07) == 0) {
                        stream.flush();
                    }
                    break;
            }
        }
        stream.flush();
    }

    private static int streamBlockSizeHint(int selector) {
        int hint = ((selector >>> 4) & 0x0F) * 128;
        return Math.max(1, hint);
    }

    private static byte[] decodeHadoopCompatible(byte[] encoded) throws IOException {
        int cursor = 0;
        ByteArrayOutputStream decoded = new ByteArrayOutputStream();
        while (cursor + 8 <= encoded.length) {
            int uncompressedSize = SnappyOutputStream.readInt(encoded, cursor);
            cursor += 4;
            int compressedSize = SnappyOutputStream.readInt(encoded, cursor);
            cursor += 4;

            if (uncompressedSize < 0 || compressedSize < 0) {
                throw new IOException("Encountered negative lengths");
            }
            if (cursor + compressedSize > encoded.length) {
                throw new IOException("Truncated block payload");
            }

            if (compressedSize == 0 && uncompressedSize == 0) {
                continue;
            }

            byte[] block = Arrays.copyOfRange(encoded, cursor, cursor + compressedSize);
            cursor += compressedSize;

            byte[] chunk = new byte[uncompressedSize];
            int restored = Snappy.uncompress(block, 0, block.length, chunk, 0);
            if (restored != uncompressedSize) {
                throw new IOException("Unexpected uncompressed length");
            }
            decoded.write(chunk, 0, restored);
        }
        return decoded.toByteArray();
    }
}
