package com.seregy77.dss.service.encryption.des.triple;

import lombok.Value;

import java.util.Arrays;

@Value
public class TripleDesKey {
    private static final int KEY_SIZE_IN_BLOCKS = 3;
    private static final int KEY_SIZE_IN_BYTES = 8;
    private static final int MINIMAL_KEY_SIZE_IN_BYTES = 2 * KEY_SIZE_IN_BYTES;

    private byte[] firstKey;
    private byte[] secondKey;

    public byte[] getThirdKey() {
        return firstKey;
    }

    public static TripleDesKey from(byte[] key) {
        if (key.length < MINIMAL_KEY_SIZE_IN_BYTES) {
            throw new IllegalArgumentException(String.format("Key must be %s bits long", MINIMAL_KEY_SIZE_IN_BYTES));
        }

        return new TripleDesKey(extractKeyBlock(key, 0), extractKeyBlock(key, 1));
    }

    private static byte[] extractKeyBlock(byte[] key, int offset) {
        return Arrays.copyOfRange(key, offset * KEY_SIZE_IN_BYTES, (offset + 1) * KEY_SIZE_IN_BYTES);
    }
}
