package org.xerial.snappy;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.ValuePool;
import org.apache.commons.compress.compressors.snappy.FramedSnappyCompressorInputStream;
import org.apache.commons.compress.compressors.snappy.FramedSnappyCompressorOutputStream;
import org.apache.commons.compress.compressors.snappy.SnappyCompressorInputStream;
import org.apache.commons.compress.compressors.snappy.SnappyCompressorOutputStream;
import org.xerial.snappy.pool.QuiescentBufferPool;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Stream;

public class ManualFuzzTest {

    public enum CompressionType {
        SNAPPY,
        SNAPPY_FRAMED,
        SNAPPY_STREAM,
    }

    public static Stream<?> validInputs() throws IOException {
        ByteArrayOutputStream combined = new ByteArrayOutputStream( );
        combined.write(Snappy.compress(new byte[0]));
        combined.write(Snappy.compress("foo"));
        return Stream.of(
                Snappy.compress(new byte[0]),
                Snappy.compress("foo"),
                Snappy.compress("The quick brown fox jumps over the lazy dog"),
                Snappy.compress(new byte[1024]),
                Snappy.compress(new byte[2048]),
                compressWithSnappyFramed(new byte[0]),
                compressWithSnappyFramed(new byte[16]),
                compressWithSnappyFramed(new byte[128]),
                compressWithSnappyFramed(new byte[1024]),
                compressWithSnappyFramed(new byte[20248]),
                combined.toByteArray()
        );
    }

//    @ValuePool(value = {"validInputs"})
    public static void fuzzerTestOneInput(byte @NotNull [] data, @NotNull CompressionType compressionType) throws IOException {
        Snappy.getNativeLibraryVersion();
        exerciseChecksum(data);
        switch(compressionType) {
            case SNAPPY_FRAMED:
                testSnappyFramed(data);
            case SNAPPY:
                testSnappy(data);
            case SNAPPY_STREAM:
                testSnappyStream(data);
        }
    }

    public static void testSnappyStream(byte[] data) throws IOException {
        byte[] uncompressedSnappy;
        try {
            uncompressedSnappy = uncompressWithSnappyStream(data);
        } catch (IOException | SnappyError ignored) {
            return;
        }
        byte[] recompressedSnappy = compressWithSnappyStream(uncompressedSnappy);

        if (!Arrays.equals(uncompressedSnappy, uncompressWithSnappyStream(recompressedSnappy))) {
            throw new AssertionError("Different compressed bytes!");
        }
    }

    public static void testSnappyFramed(byte[] data) throws IOException {
        byte[] uncompressedSnappy;
        try {
            uncompressedSnappy = uncompressWithSnappyFramed(data);
        } catch (IOException ignored) {
            return;
        }
        // The recompressed has the correct checksums etc.
        byte[] recompressedSnappy = compressWithSnappyFramed(uncompressedSnappy);
        byte[] uncompressedCommons = uncompressWithCommonsFramedSnappy(recompressedSnappy);
        if (!Arrays.equals(uncompressedSnappy, uncompressedCommons)) {
            throw new AssertionError("Different uncompressed bytes!");
        }

        byte[] recompressedSnappyFramed = compressWithSnappyFramed(uncompressedSnappy);
        byte[] recompressedCommons = compressWithCommonsFramedSnappy(uncompressedSnappy);
        if (!Arrays.equals(uncompressedSnappy, uncompressWithSnappyFramed(recompressedCommons))) {
            throw new AssertionError("Different compressed bytes!");
        }
        if (!Arrays.equals(uncompressedSnappy, uncompressWithCommonsFramedSnappy(recompressedSnappyFramed))) {
            throw new AssertionError("Different compressed bytes!");
        }

        smallChunkRoundtrip(uncompressedSnappy);
        byteBufferRoundtrip(uncompressedCommons);
        transferRoundtrip(uncompressedCommons);
        transferChannelRoundtrip(uncompressedCommons);
    }

    public static void testSnappy(byte[] data) throws IOException {
        boolean isValid = Snappy.isValidCompressedBuffer(data);
        int uncompressedLength = 0;
        byte[] uncompressedSnappy;
        byte[] uncompressedCommons;
        byte[] uncompressedStream;
        try {
            uncompressedLength = Snappy.uncompressedLength(data);
            uncompressedSnappy = Snappy.uncompress(data);
            uncompressedCommons = uncompressWithCommons(data);
            uncompressedStream = uncompressWithSnappyStream(data);
        } catch (IOException ignored) {
            if (isValid && uncompressedLength >= 0)
                throw new AssertionError("Decompression failed for valid input!");
            return;
        }
        if (!isValid) {
            throw new AssertionError("Decompression succeeded for invalid input!");
        }
        if (!Arrays.equals(uncompressedSnappy, uncompressedCommons)) {
            throw new AssertionError("Different uncompressed bytes!");
        }
        if (!Arrays.equals(uncompressedSnappy, uncompressedStream)) {
            throw new AssertionError("Different uncompressed bytes!");
        }
        if (uncompressedLength != uncompressedSnappy.length) {
            throw new AssertionError("Uncompressed length mismatch!");
        }

        byte[] recompressedSnappy = compressWithSnappy(uncompressedSnappy);
        byte[] recompressedCommons = compressWithCommons(uncompressedSnappy);
        byte[] recompressedStream = compressWithSnappyStream(uncompressedSnappy);

        if (!Arrays.equals(uncompressedSnappy, Snappy.uncompress(recompressedCommons))) {
            throw new AssertionError("Different compressed bytes!");
        }
        if (!Arrays.equals(uncompressedSnappy, uncompressWithCommons(recompressedSnappy))) {
            throw new AssertionError("Different compressed bytes!");
        }
        if (!Arrays.equals(uncompressedSnappy, uncompressWithSnappyStream(recompressedStream))) {
            throw new AssertionError("Different compressed bytes!");
        }

        // Byte Buffer decompression
        ByteBuffer compressedBuffer = ByteBuffer.allocateDirect(data.length);
        compressedBuffer.put(data);
        compressedBuffer.flip();
        Snappy.isValidCompressedBuffer(compressedBuffer);
        compressedBuffer.rewind();

        ByteBuffer uncompressedBuffer = ByteBuffer.allocateDirect(uncompressedSnappy.length);
        Snappy.uncompress(compressedBuffer, uncompressedBuffer);
        byte[] uncompressedFromByteBuffer = new byte[uncompressedSnappy.length];
        uncompressedBuffer.get(uncompressedFromByteBuffer);
        if (!Arrays.equals(uncompressedSnappy, uncompressedFromByteBuffer)) {
            throw new AssertionError("Different uncompressed bytes from ByteBuffer!");
        }
        Snappy.compress(uncompressedBuffer, compressedBuffer);
        rawWriteRoundtrip(uncompressedSnappy);

        // BitShuffle round trips
        roundTripTypes(data);

    }

    public static byte[] compressWithSnappy(byte[] data) throws IOException {
        return Snappy.compress(data);
    }

    public static byte[] compressWithSnappyFramed(byte[] data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (SnappyFramedOutputStream snappyFramedOut =
                     new SnappyFramedOutputStream(baos)) {
            snappyFramedOut.write(data);
        }
        return baos.toByteArray();
    }

    public static byte[] uncompressWithSnappyFramed(byte[] data) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (SnappyFramedInputStream inputStream = new SnappyFramedInputStream(new ByteArrayInputStream(data), false, QuiescentBufferPool.getInstance())) {
            inputStream.transferTo(outputStream);
        }
        return outputStream.toByteArray();
    }

    public static byte[] compressWithCommonsFramedSnappy(byte[] data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (FramedSnappyCompressorOutputStream framedSnappyOut =
                     new FramedSnappyCompressorOutputStream(baos)) {
            framedSnappyOut.write(data);
        }
        return baos.toByteArray();
    }

    public static byte[] compressWithCommons(byte[] data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (SnappyCompressorOutputStream snappyOut = new SnappyCompressorOutputStream(baos, data.length)) {
            snappyOut.write(data);
        }
        return baos.toByteArray();
    }

    public static byte[] uncompressWithSnappyStream(byte[] data) throws IOException {
        try (SnappyInputStream inputStream = new SnappyInputStream(new ByteArrayInputStream(data), SnappyOutputStream.MIN_BLOCK_SIZE)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8];
            int n;
            while ((n = inputStream.read(buffer)) != -1) {
                out.write(buffer, 0, n);
            }
            assert inputStream.read(new double[0], 0, 0) == 0;
            assert inputStream.read(new short[0], 0, 0) == 0;
            assert inputStream.read(new int[0], 0, 0) == 0;
            assert inputStream.read(new float[0], 0, 0) == 0;
            return out.toByteArray();
        }
    }

    public static byte[] compressWithSnappyStream(byte[] data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (SnappyOutputStream snappyOut = new SnappyOutputStream(baos, SnappyOutputStream.MIN_BLOCK_SIZE)) {
            snappyOut.write(data);
            snappyOut.write(new double[0], 0, 0);
            snappyOut.write(new float[0], 0, 0);
            snappyOut.write(new int[0], 0, 0);
            snappyOut.write(new short[0], 0, 0);
        }
        return baos.toByteArray();
    }

    public static void rawWriteRoundtrip(byte[] data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (SnappyOutputStream snappyOut = new SnappyOutputStream(baos, SnappyOutputStream.MIN_BLOCK_SIZE)) {
            snappyOut.rawWrite(data, 0, data.length);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (SnappyInputStream snappyIn = new SnappyInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
            byte[] buffer = new byte[8];
            int n;
            while ((n = snappyIn.rawRead(buffer, 0, buffer.length)) != -1) {
                out.write(buffer, 0, n);
            }
        }
        if (!Arrays.equals(data, out.toByteArray())) {
            throw new AssertionError("Different uncompressed bytes from rawWrite/rawRead!");
        }
    }

    public static byte[] uncompressWithCommons(byte[] data) throws IOException {
        try (SnappyCompressorInputStream inputStream = new SnappyCompressorInputStream(new ByteArrayInputStream(data))) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = inputStream.read(buffer)) != -1) {
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        }
    }

    public static byte[] uncompressWithCommonsFramedSnappy(byte[] data) throws IOException {
        try (FramedSnappyCompressorInputStream inputStream = new FramedSnappyCompressorInputStream(new ByteArrayInputStream(data))) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = inputStream.read(buffer)) != -1) {
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        }
    }

    public static void smallChunkRoundtrip(byte[] uncompressed) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (SnappyFramedOutputStream out = new SnappyFramedOutputStream(baos)) {
            int chunkSize = 8;
            for (int i = 0; i < uncompressed.length; i += chunkSize) {
                int len = Math.min(chunkSize, uncompressed.length - i);
                out.write(uncompressed, i, len);
            }
        }
        byte[] compressed = baos.toByteArray();
        ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
        ByteArrayOutputStream recovered = new ByteArrayOutputStream();
        try (SnappyFramedInputStream in = new SnappyFramedInputStream(bais)) {
            byte[] buf = new byte[10];
            int n;
            while ((n = in.read(buf)) != -1) {
                recovered.write(buf, 0, n);
            }
        }
        if (!Arrays.equals(uncompressed, recovered.toByteArray())) {
            throw new AssertionError("Different uncompressed bytes from small chunk read!");
        }
    }

    public static void byteBufferRoundtrip(byte[] uncompressed) throws IOException {
        final int writeChunkSize = 16; // small input chunks
        final int readChunkSize  = 16; // small output chunks

        ByteBuffer writeBuffer = ByteBuffer.allocateDirect(writeChunkSize);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (SnappyFramedOutputStream out = new SnappyFramedOutputStream(baos, 8, 0.5f, QuiescentBufferPool.getInstance())) {
            int offset = 0;
            while (offset < uncompressed.length) {
                int len = Math.min(writeChunkSize, uncompressed.length - offset);
                writeBuffer.clear();
                writeBuffer.put(uncompressed, offset, len);
                writeBuffer.flip();
                out.write(writeBuffer);
                offset += len;
            }
        }
        byte[] compressed = baos.toByteArray();

        ByteBuffer readBuffer = ByteBuffer.allocateDirect(readChunkSize);
        ByteArrayOutputStream recovered = new ByteArrayOutputStream(uncompressed.length);

        ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
        try (SnappyFramedInputStream in = new SnappyFramedInputStream(bais, true, QuiescentBufferPool.getInstance())) {
            while (true) {
                readBuffer.clear();
                if (in.read(readBuffer) == -1) {
                    break;
                }
                readBuffer.flip();
                byte[] tmp = new byte[readBuffer.remaining()];
                readBuffer.get(tmp);
                recovered.write(tmp);
            }
        }

        byte[] roundTrip = recovered.toByteArray();
        if (!Arrays.equals(uncompressed, roundTrip)) {
            throw new AssertionError("Round-trip mismatch using reusable ByteBuffer chunk test!");
        }
    }

    public static void transferRoundtrip(byte[] uncompressed) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (SnappyFramedOutputStream out = new SnappyFramedOutputStream(baos)) {
            out.transferFrom(new ByteArrayInputStream(uncompressed));
        }
        byte[] compressed = baos.toByteArray();

        ByteArrayOutputStream uncompressedOut = new ByteArrayOutputStream();
        ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
        try (SnappyFramedInputStream in = new SnappyFramedInputStream(bais)) {
            in.transferTo(uncompressedOut);
        }
        if (!Arrays.equals(uncompressed, uncompressedOut.toByteArray())) {
            throw new AssertionError("Different uncompressed bytes from transferTo/From read!");
        }
    }

    public static void transferChannelRoundtrip(byte[] uncompressed) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (SnappyFramedOutputStream out = new SnappyFramedOutputStream(baos)) {
            out.transferFrom(Channels.newChannel(new ByteArrayInputStream(uncompressed)));
        }
        byte[] compressed = baos.toByteArray();

        ByteArrayOutputStream uncompressedBytes = new ByteArrayOutputStream();
        WritableByteChannel uncompressedChannel = Channels.newChannel(uncompressedBytes);
        ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
        try (SnappyFramedInputStream in = new SnappyFramedInputStream(bais)) {
            in.transferTo(uncompressedChannel);
        }
        if (!Arrays.equals(uncompressed, uncompressedBytes.toByteArray())) {
            throw new AssertionError("Different uncompressed bytes from transferTo/From read!");
        }
    }

    public static void exerciseChecksum(byte[] data) {
        PureJavaCrc32C crc32C = new PureJavaCrc32C();
        crc32C.update(data, 0, data.length);
        crc32C.getValue();
        crc32C.getIntegerValue();
        crc32C.reset();
    }

    public static void roundTripTypes(byte[] data) throws IOException {
        String s = Snappy.uncompressString(data, 0, data.length);
        if (!Snappy.uncompressString(Snappy.compress(s)).equals(s)) {
            throw new AssertionError("Round trip failed for String");
        }
        String s2 = Snappy.uncompressString(data, 0, data.length, StandardCharsets.UTF_16);
        if (!Snappy.uncompressString(Snappy.compress(s2, StandardCharsets.UTF_16), StandardCharsets.UTF_16).equals(s2)) {
            throw new AssertionError("Round trip failed for String");
        }
        char[] chars = Snappy.uncompressCharArray(data, 0, data.length);
        if (!Arrays.equals(Snappy.uncompressCharArray(Snappy.compress(chars)), chars)) {
            throw new AssertionError("Round trip failed for char[]");
        }

        double[] doubles = Snappy.uncompressDoubleArray(data, 0, data.length);
        if (!Arrays.equals(BitShuffle.unshuffleDoubleArray(Snappy.uncompress(Snappy.compress(BitShuffle.shuffle(doubles)))), doubles)) {
            throw new AssertionError("Round trip failed for double[]");
        }
        if (!Arrays.equals(doubles, Snappy.uncompressDoubleArray(Snappy.compress(doubles)))) {
            throw new AssertionError("Round trip failed for double[]");
        }

        int[] ints = Snappy.uncompressIntArray(data, 0, data.length);
        if (!Arrays.equals(BitShuffle.unshuffleIntArray(Snappy.uncompress(Snappy.compress(BitShuffle.shuffle(ints)))), ints)) {
            throw new AssertionError("Round trip failed for int[]");
        }
        if (!Arrays.equals(ints, Snappy.uncompressIntArray(Snappy.compress(ints)))) {
            throw new AssertionError("Round trip failed for int[]");
        }

        long[] longs = Snappy.uncompressLongArray(data, 0, data.length);
        if (!Arrays.equals(BitShuffle.unshuffleLongArray(Snappy.uncompress(Snappy.compress(BitShuffle.shuffle(longs)))), longs)) {
            throw new AssertionError("Round trip failed for long[]");
        }
        if (!Arrays.equals(longs, Snappy.uncompressLongArray(Snappy.compress(longs)))) {
            throw new AssertionError("Round trip failed for long[]");
        }

        float[] floats = Snappy.uncompressFloatArray(data, 0, data.length);
        if (!Arrays.equals(BitShuffle.unshuffleFloatArray(Snappy.uncompress(Snappy.compress(BitShuffle.shuffle(floats)))), floats)) {
            throw new AssertionError("Round trip failed for float[]");
        }
        if (!Arrays.equals(floats, Snappy.uncompressFloatArray(Snappy.compress(floats)))) {
            throw new AssertionError("Round trip failed for float[]");
        }

        short[] shorts = Snappy.uncompressShortArray(data, 0, data.length);
        if (!Arrays.equals(BitShuffle.unshuffleShortArray(Snappy.uncompress(Snappy.compress(BitShuffle.shuffle(shorts)))), shorts)) {
            throw new AssertionError("Round trip failed for short[]");
        }
        if (!Arrays.equals(shorts, Snappy.uncompressShortArray(Snappy.compress(shorts)))) {
            throw new AssertionError("Round trip failed for short[]");
        }
    }
}
