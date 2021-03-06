package com.seregy77.dss.service.encryption;

import com.seregy77.dss.service.encryption.md5.Md5Impl;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class Md5ImplTest {
    @Test
    void encrypt_rfcTestSuit() {
        // Given
        Md5Impl md5Impl = new Md5Impl();

        // When
        String emptyStringHash = md5Impl.encrypt("");
        String aHash = md5Impl.encrypt("a");
        String abcHash = md5Impl.encrypt("abc");
        String messageDigestHash = md5Impl.encrypt("message digest");
        String allCharsHash = md5Impl.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        String numbersHash = md5Impl.encrypt("12345678901234567890123456789012345678901234567890123456789012345678901234567890");

        // Then
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", emptyStringHash);
        assertEquals("0cc175b9c0f1b6a831c399e269772661", aHash);
        assertEquals("900150983cd24fb0d6963f7d28e17f72", abcHash);
        assertEquals("f96b697d7cb7938d525a2f31aaf161d0", messageDigestHash);
        assertEquals("d174ab98d277d9f5a5611c2c9f419d9f", allCharsHash);
        assertEquals("57edf4a22be3c955ac49da2e2107b67a", numbersHash);
    }


    @Test
    void encrypt_withSalt_shouldConcatenate() {
        // Given
        Md5Impl md5Impl = new Md5Impl();
        String message = "abc";
        String salt = "some random salt";

        // When
        String actualHash = md5Impl.encrypt(message, salt);

        // Then
        assertEquals("06ce46adfdc8c82c83eed82b58c304c5", actualHash);
    }
}