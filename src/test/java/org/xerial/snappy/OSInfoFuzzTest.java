package org.xerial.snappy;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;

import java.io.IOException;

public class OSInfoFuzzTest {

    public static void fuzzerTestOneInput(@NotNull String os, @NotNull String arch) throws IOException {
        System.setProperty("os.arch", arch);
        System.setProperty("os.name", os);
        OSInfo.getArchName();
        OSInfo.getHardwareName();
        OSInfo.getOSName();
        OSInfo.getNativeLibFolderPathForCurrentOS();
    }
}
