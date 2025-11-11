package org.xerial.snappy;

import com.code_intelligence.jazzer.mutation.annotation.InRange;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.zip.Checksum;

/**
 * Fuzzes {@link PureJavaCrc32C} and the helper utilities in {@link SnappyFramed}
 * to ensure their results agree with the platform CRC32C implementation and
 * exercise the masking helpers.
 */
public final class PureJavaCrc32CFuzzTest {
    private static final int MAX_INPUT_SIZE = 1 << 13; // 8 KiB.

    private PureJavaCrc32CFuzzTest() {
    }

    public static void fuzzerTestOneInput(byte @NotNull [] data, @InRange(min = 0, max = 255) int selector) {
        byte[] payload = Arrays.copyOf(data, Math.min(data.length, MAX_INPUT_SIZE));

        Checksum reference = newReferenceChecksum();
        PureJavaCrc32C subject = new PureJavaCrc32C();

        feedChecksums(payload, selector, subject, reference);
        long referenceValue = reference.getValue();
        long subjectValue = subject.getValue();
        if (referenceValue != subjectValue) {
            throw new AssertionError(String.format("CRC mismatch: ref=%d, pure=%d", referenceValue, subjectValue));
        }

        // Exercise getIntegerValue and reset.
        int intValue = subject.getIntegerValue();
        if (((intValue ^ subjectValue) & 0xFFFFFFFFL) != 0) {
            throw new AssertionError("getIntegerValue disagrees with getValue()");
        }
        subject.reset();
        reference.reset();

        if (payload.length > 0) {
            int index = selector % payload.length;
            int unsigned = payload[index] & 0xFF;
            subject.update(unsigned);
            reference.update(unsigned);
            if (reference.getValue() != subject.getValue()) {
                throw new AssertionError("Single-byte update mismatch");
            }
        }

        // Compare masked CRC calculations using two different checksum instances.
        Checksum freshPure = new PureJavaCrc32C();
        int maskFromPure = SnappyFramed.maskedCrc32c(freshPure, payload, 0, payload.length);

        Checksum supplierInstance = SnappyFramed.getCRC32C();
        int maskFromSupplier = SnappyFramed.maskedCrc32c(supplierInstance, payload, 0, payload.length);
        if (maskFromPure != maskFromSupplier) {
            throw new AssertionError(String.format("Masked CRC mismatch: %d vs %d", maskFromPure, maskFromSupplier));
        }

        // Derive an unmasked value to keep the integer operations covered.
        unmask(maskFromPure);
    }

    private static void feedChecksums(byte[] payload, int selector, PureJavaCrc32C subject, Checksum reference) {
        int pos = 0;
        while (pos < payload.length) {
            int spanHint = ((selector + pos) & 0x0F) + 1;
            int span = Math.min(payload.length - pos, spanHint);
            subject.update(payload, pos, span);
            reference.update(payload, pos, span);
            pos += span;

            if ((selector & 0x20) != 0 && pos < payload.length) {
                // Feed an extra byte via ByteBuffer to vary call patterns.
                ByteBuffer single = ByteBuffer.wrap(payload, pos, 1);
                byte b = single.get();
                subject.update(b & 0xFF);
                reference.update(b & 0xFF);
                pos++;
            }
        }
    }

    private static Checksum newReferenceChecksum() {
        try {
            Class<?> crc32cClass = Class.forName("java.util.zip.CRC32C");
            return (Checksum) crc32cClass.getDeclaredConstructor().newInstance();
        } catch (ReflectiveOperationException | LinkageError ignored) {
            return new PureJavaCrc32C();
        }
    }

    private static int unmask(int masked) {
        // Reverse of SnappyFramed.mask().
        int rot = masked - 0xa282ead8;
        return (rot >>> 17) | (rot << 15);
    }
}
