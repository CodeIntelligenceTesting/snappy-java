package org.xerial.snappy;

import com.code_intelligence.jazzer.mutation.annotation.InRange;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Fuzzes the negative and edge-case paths of {@link SnappyInputStream} to raise
 * the coverage of error handling, including {@link SnappyIOException}.
 */
public final class SnappyInputStreamErrorFuzzTest {
    private static final int MAX_PAYLOAD = 1 << 14; // 16 KiB.

    private SnappyInputStreamErrorFuzzTest() {
    }

    public static void fuzzerTestOneInput(byte @NotNull [] data, @InRange(min = 0, max = 255) int selector) {
        byte[] payload = Arrays.copyOf(data, Math.min(data.length, MAX_PAYLOAD));
        int scenario = selector & 0x03;
        try {
            switch (scenario) {
                case 0:
                    exerciseEmptyInput();
                    break;
                case 1:
                    exerciseTruncatedConcatenatedHeader(payload);
                    break;
                case 2:
                    exerciseIncompatibleVersion(payload);
                    break;
                default:
                    exerciseFailedChunkRead(payload, selector);
                    break;
            }
        } catch (IOException | SnappyError ignored) {
            // Expected failure modes for malformed data.
        }
    }

    private static void exerciseEmptyInput() {
        try {
            new SnappyInputStream(new ByteArrayInputStream(new byte[0]));
            throw new AssertionError("Expected SnappyIOException for empty input");
        } catch (SnappyIOException expected) {
            if (expected.getErrorCode() != SnappyErrorCode.EMPTY_INPUT) {
                throw new AssertionError("Unexpected error code: " + expected.getErrorCode());
            }
            expected.getMessage();
        } catch (IOException e) {
            throw new AssertionError("Unexpected IOException type", e);
        }
    }

    private static void exerciseTruncatedConcatenatedHeader(byte[] payload) throws IOException {
        byte[] validStream = encodePayload(payload);
        byte[] truncated = appendHeaderFragment(validStream, payload.length % (SnappyCodec.headerSize() - 4));

        try (SnappyInputStream in = new SnappyInputStream(new ByteArrayInputStream(truncated))) {
            drainStream(in);
            throw new AssertionError("Expected SnappyIOException for truncated header");
        } catch (SnappyIOException expected) {
            if (expected.getErrorCode() != SnappyErrorCode.FAILED_TO_UNCOMPRESS) {
                throw expected;
            }
            expected.getMessage();
        }
    }

    private static void exerciseIncompatibleVersion(byte[] payload) throws IOException {
        byte[] validStream = encodePayload(payload);
        byte[] incompatible = appendIncompatibleHeader(validStream);

        try (SnappyInputStream in = new SnappyInputStream(new ByteArrayInputStream(incompatible))) {
            drainStream(in);
            throw new AssertionError("Expected SnappyIOException for incompatible header");
        } catch (SnappyIOException expected) {
            if (expected.getErrorCode() != SnappyErrorCode.INCOMPATIBLE_VERSION) {
                throw expected;
            }
            expected.getMessage();
        }
    }

    private static void exerciseFailedChunkRead(byte[] payload, int selector) throws IOException {
        byte[] validStream = encodePayload(payload);

        ByteBuffer bogusLength = ByteBuffer.allocate(validStream.length + 4);
        bogusLength.put(validStream);
        int inflated = SnappyOutputStream.MAX_BLOCK_SIZE + ((selector & 0xFF) + 1);
        bogusLength.putInt(inflated);
        byte[] mutated = bogusLength.array();

        try (SnappyInputStream in = new SnappyInputStream(new ByteArrayInputStream(mutated), SnappyOutputStream.DEFAULT_BLOCK_SIZE)) {
            drainStream(in);
        }
    }

    private static byte[] encodePayload(byte[] payload) throws IOException {
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        try (SnappyOutputStream out = new SnappyOutputStream(encoded)) {
            if (payload.length == 0) {
                out.write(0);
            } else {
                out.write(payload, 0, payload.length);
            }
        }
        return encoded.toByteArray();
    }

    private static byte[] appendHeaderFragment(byte[] validStream, int extraBytes) {
        byte[] marker = ByteBuffer.allocate(4).putInt(SnappyCodec.MAGIC_HEADER_HEAD).array();
        int remainder = Math.max(1, Math.min(extraBytes, SnappyCodec.headerSize() - 5));
        byte[] fragment = Arrays.copyOfRange(SnappyCodec.getMagicHeader(), 4, 4 + remainder);

        byte[] result = Arrays.copyOf(validStream, validStream.length + marker.length + fragment.length);
        System.arraycopy(marker, 0, result, validStream.length, marker.length);
        System.arraycopy(fragment, 0, result, validStream.length + marker.length, fragment.length);
        return result;
    }

    private static byte[] appendIncompatibleHeader(byte[] validStream) {
        byte[] marker = ByteBuffer.allocate(4).putInt(SnappyCodec.MAGIC_HEADER_HEAD).array();
        byte[] header = new byte[SnappyCodec.headerSize()];
        System.arraycopy(SnappyCodec.getMagicHeader(), 0, header, 0, SnappyCodec.MAGIC_LEN);
        ByteBuffer.wrap(header, SnappyCodec.MAGIC_LEN, 8)
                  .putInt(SnappyCodec.MINIMUM_COMPATIBLE_VERSION - 1)
                  .putInt(SnappyCodec.MINIMUM_COMPATIBLE_VERSION);

        byte[] tail = Arrays.copyOfRange(header, 4, header.length);
        byte[] result = Arrays.copyOf(validStream, validStream.length + marker.length + tail.length);
        System.arraycopy(marker, 0, result, validStream.length, marker.length);
        System.arraycopy(tail, 0, result, validStream.length + marker.length, tail.length);
        return result;
    }

    private static void drainStream(SnappyInputStream in) throws IOException {
        byte[] buffer = new byte[256];
        while (in.read(buffer) != -1) {
            // discard
        }
    }
}
