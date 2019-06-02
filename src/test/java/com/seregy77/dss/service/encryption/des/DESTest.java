package com.seregy77.dss.service.encryption.des;

import com.seregy77.dss.service.encryption.md5.Md5Impl;
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
        String keyHash = new Md5Impl().encrypt(key);
        keyHash = keyHash.substring(0, 16);

        byte[] customEncrypted = new DesImpl().encrypt(message.getBytes(), new BigInteger(keyHash, 16).toByteArray());
        assertArrayEquals(Hex.decodeHex("7de1102e64687a3d979610cc80b5fb3b"), customEncrypted);
    }

    @Test
    public void encrypt3() throws Exception {
        // Given
        String message = "something long";
        String key = "my key";
        String keyHash = new Md5Impl().encrypt(key);
        keyHash = keyHash.substring(0, 16);

        byte[] customEncrypted = new DesImpl().encrypt(message.getBytes(), new BigInteger(keyHash, 16).toByteArray());
        assertArrayEquals(Hex.decodeHex("c4bf1775f316632819cd53c2949225e67916c09ab6c876a8"), customEncrypted);
    }

    @Test
    public void encrypt2() throws Exception {
        // Given
        byte[] message = Hex.decodeHex("91004909c6f5eb24");
        byte[] key = Hex.decodeHex("cd52951f7c0dc085");

        byte[] customEncrypted = new DesImpl().encrypt(message, key);
        assertArrayEquals(Hex.decodeHex("cdd9a511c1b409e4"), customEncrypted);
    }

    @Test
    public void encrypt4() throws Exception {
        // Given
        String message = "g really";
        String key = "my key";
        String keyHash = new Md5Impl().encrypt(key);
        keyHash = keyHash.substring(0, 16);

        byte[] customEncrypted = new DesImpl().encrypt(message.getBytes(), new BigInteger(keyHash, 16).toByteArray());
        assertArrayEquals(Hex.decodeHex("52ffabbaba23ec35"), customEncrypted);
    }

    @Test
    public void decrypt() throws Exception {
        // Given
        String encryptedMessage = "7de1102e64687a3d979610cc80b5fb3b";
        String key = "my key";
        String keyHash = new Md5Impl().encrypt(key);
        keyHash = keyHash.substring(0, 16);

        byte[] customEncrypted = new DesImpl().decrypt(Hex.decodeHex(encryptedMessage), Hex.decodeHex(keyHash));
        assertEquals("some message", new String(customEncrypted).trim());
    }

    @Test
    public void decrypt2() throws Exception {
        // Given
        String encryptedMessage = "bc6d8d3661959e286bddf13612c6aa4a";
        String key = "my key";
        String keyHash = new Md5Impl().encrypt(key);
        keyHash = keyHash.substring(0, 16);

        byte[] customEncrypted = new DesImpl().decrypt(Hex.decodeHex(encryptedMessage), Hex.decodeHex(keyHash));
        assertEquals("something long", new String(customEncrypted));
    }

    @Test
    public void decrypt3() throws Exception {
        // Given
        String encryptedMessage = "52ffabbaba23ec35";
        String key = "my key";
        String keyHash = new Md5Impl().encrypt(key);
        keyHash = keyHash.substring(0, 16);

        byte[] customEncrypted = new DesImpl().decrypt(Hex.decodeHex(encryptedMessage), Hex.decodeHex(keyHash));
        assertEquals("g really", new String(customEncrypted));
    }
}