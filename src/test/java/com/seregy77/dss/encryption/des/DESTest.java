package com.seregy77.dss.encryption.des;

import com.seregy77.dss.encryption.md5.MD5;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class DESTest {
    @Test
    public void encrypt() throws Exception {
        // Given
        String message = "some message";
        String key = "my key";
        String keyHash = new MD5().encrypt(key);
        keyHash = keyHash.substring(0, 16);

        byte[] customEncrypted = new DES().encrypt(message.getBytes(), new BigInteger(keyHash, 16).toByteArray());
        assertArrayEquals(Hex.decodeHex("7de1102e64687a3d979610cc80b5fb3b"), customEncrypted);
    }

    @Test
    public void decrypt() throws Exception {
        // Given
        String encryptedMessage = "7de1102e64687a3d979610cc80b5fb3b";
        String key = "my key";
        String keyHash = new MD5().encrypt(key);
        keyHash = keyHash.substring(0, 16);

        byte[] customEncrypted = new DES().decrypt(Hex.decodeHex(encryptedMessage), Hex.decodeHex(keyHash));
        assertEquals("some message", new String(customEncrypted).trim());
    }
}