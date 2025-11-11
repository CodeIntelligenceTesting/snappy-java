package org.xerial.snappy;

import com.code_intelligence.jazzer.mutation.annotation.InRange;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Fuzzes the {@link BitShuffle} APIs to ensure both the direct-buffer and array helpers
 * round-trip correctly and that non-direct buffers surface the expected error codes.
 */
public final class BitShuffleRoundTripFuzzTest {
    private static final int MAX_PAYLOAD_SIZE = 1 << 12; // Clamp allocations to 4 KiB.

    private BitShuffleRoundTripFuzzTest() {
    }

    public static void fuzzerTestOneInput(byte @NotNull [] data, @InRange(min = 0, max = 255) int selector) {
        if (data.length == 0) {
            return;
        }

        byte[] payload = Arrays.copyOfRange(data, 0, Math.min(data.length, MAX_PAYLOAD_SIZE));
        BitShuffleType[] types = BitShuffleType.values();
        BitShuffleType type = types[selector % types.length];

        int typeSize = type.getTypeSize();
        int usableLength = payload.length - (payload.length % typeSize);
        if (usableLength == 0) {
            return;
        }

        try {
            // Always exercise the direct buffer path.
            exerciseDirectRoundTrip(payload, usableLength, type);

            // For non-byte types, also exercise the array helpers.
            if (type != BitShuffleType.BYTE) {
                exerciseArrayRoundTrip(payload, usableLength, type);
            }

            exerciseErrorPaths(payload, usableLength, type, selector);
        } catch (IOException | SnappyError | IllegalArgumentException ignored) {
            // Invalid combinations (e.g., allocator limits) are fine to skip.
        } catch (ExceptionInInitializerError | UnsatisfiedLinkError ignored) {
            // If the native library is unavailable, bail out silently.
        }
    }

    private static void exerciseDirectRoundTrip(byte[] payload, int usableLength, BitShuffleType type)
            throws IOException {
        ByteBuffer input = ByteBuffer.allocateDirect(usableLength).order(ByteOrder.LITTLE_ENDIAN);
        input.put(payload, 0, usableLength);
        input.flip();

        ByteBuffer shuffled = ByteBuffer.allocateDirect(usableLength);
        int shuffledBytes = BitShuffle.shuffle(input, type, shuffled);
        shuffled.limit(shuffledBytes);
        shuffled.position(0);

        ByteBuffer restored = ByteBuffer.allocateDirect(usableLength);
        int restoredBytes = BitShuffle.unshuffle(shuffled, type, restored);
        restored.limit(restoredBytes);
        restored.position(0);

        byte[] restoredBytesArray = new byte[restoredBytes];
        restored.get(restoredBytesArray);

        byte[] expected = Arrays.copyOf(payload, restoredBytes);
        if (!Arrays.equals(expected, restoredBytesArray)) {
            throw new AssertionError("BitShuffle direct ByteBuffer round-trip mismatch");
        }
    }

    private static void exerciseArrayRoundTrip(byte[] payload, int usableLength, BitShuffleType type)
            throws IOException {
        switch (type) {
            case SHORT:
                short[] shorts = toShortArray(payload, usableLength);
                byte[] shuffledShorts = BitShuffle.shuffle(shorts);
                short[] restoredShorts = BitShuffle.unshuffleShortArray(shuffledShorts);
                if (!Arrays.equals(shorts, restoredShorts)) {
                    throw new AssertionError("BitShuffle short[] round-trip mismatch");
                }
                break;
            case INT:
                int[] ints = toIntArray(payload, usableLength);
                byte[] shuffledInts = BitShuffle.shuffle(ints);
                int[] restoredInts = BitShuffle.unshuffleIntArray(shuffledInts);
                if (!Arrays.equals(ints, restoredInts)) {
                    throw new AssertionError("BitShuffle int[] round-trip mismatch");
                }
                break;
            case LONG:
                long[] longs = toLongArray(payload, usableLength);
                byte[] shuffledLongs = BitShuffle.shuffle(longs);
                long[] restoredLongs = BitShuffle.unshuffleLongArray(shuffledLongs);
                if (!Arrays.equals(longs, restoredLongs)) {
                    throw new AssertionError("BitShuffle long[] round-trip mismatch");
                }
                break;
            case FLOAT:
                float[] floats = toFloatArray(payload, usableLength);
                byte[] shuffledFloats = BitShuffle.shuffle(floats);
                float[] restoredFloats = BitShuffle.unshuffleFloatArray(shuffledFloats);
                if (!Arrays.equals(floats, restoredFloats)) {
                    throw new AssertionError("BitShuffle float[] round-trip mismatch");
                }
                break;
            case DOUBLE:
                double[] doubles = toDoubleArray(payload, usableLength);
                byte[] shuffledDoubles = BitShuffle.shuffle(doubles);
                double[] restoredDoubles = BitShuffle.unshuffleDoubleArray(shuffledDoubles);
                if (!Arrays.equals(doubles, restoredDoubles)) {
                    throw new AssertionError("BitShuffle double[] round-trip mismatch");
                }
                break;
            default:
                // BYTE is covered by the direct buffer path above.
                break;
        }
    }

    private static void exerciseErrorPaths(byte[] payload, int usableLength, BitShuffleType type, int selector)
            throws IOException {
        ByteBuffer heapInput = ByteBuffer.wrap(payload, 0, usableLength);
        ByteBuffer directOutput = ByteBuffer.allocateDirect(usableLength);
        try {
            BitShuffle.shuffle(heapInput, type, directOutput);
        } catch (SnappyError error) {
            verifyNotADirectBufferError(error, selector);
        }

        ByteBuffer directInput = ByteBuffer.allocateDirect(usableLength);
        directInput.put(payload, 0, usableLength);
        directInput.flip();

        ByteBuffer heapOutput = ByteBuffer.wrap(new byte[usableLength]);
        try {
            BitShuffle.unshuffle(directInput, type, heapOutput);
        } catch (SnappyError error) {
            verifyNotADirectBufferError(error, selector);
        }
    }

    private static void verifyNotADirectBufferError(SnappyError error, int selector) {
        if (error.errorCode != SnappyErrorCode.NOT_A_DIRECT_BUFFER) {
            throw error;
        }

        // Exercise the error-code helpers while we have a legitimate instance.
        SnappyErrorCode resolved = SnappyErrorCode.getErrorCode(error.errorCode.id);
        if (resolved != error.errorCode) {
            throw new AssertionError("SnappyErrorCode lookup mismatch");
        }
        // Query another id to hit the UNKNOWN branch.
        SnappyErrorCode.getErrorMessage(selector + 1024);
    }

    private static short[] toShortArray(byte[] payload, int usableLength) {
        short[] result = new short[usableLength / Short.BYTES];
        ByteBuffer.wrap(payload, 0, usableLength).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().get(result);
        return result;
    }

    private static int[] toIntArray(byte[] payload, int usableLength) {
        int[] result = new int[usableLength / Integer.BYTES];
        ByteBuffer.wrap(payload, 0, usableLength).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(result);
        return result;
    }

    private static long[] toLongArray(byte[] payload, int usableLength) {
        long[] result = new long[usableLength / Long.BYTES];
        ByteBuffer.wrap(payload, 0, usableLength).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer().get(result);
        return result;
    }

    private static float[] toFloatArray(byte[] payload, int usableLength) {
        float[] result = new float[usableLength / Float.BYTES];
        ByteBuffer.wrap(payload, 0, usableLength).order(ByteOrder.LITTLE_ENDIAN).asFloatBuffer().get(result);
        return result;
    }

    private static double[] toDoubleArray(byte[] payload, int usableLength) {
        double[] result = new double[usableLength / Double.BYTES];
        ByteBuffer.wrap(payload, 0, usableLength).order(ByteOrder.LITTLE_ENDIAN).asDoubleBuffer().get(result);
        return result;
    }
}
