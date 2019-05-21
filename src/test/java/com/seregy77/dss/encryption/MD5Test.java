package com.seregy77.dss.encryption;

import com.seregy77.dss.encryption.md5.MD5;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MD5Test {
    @Test
    void encrypt_rfcTestSuit() {
        // Given
        MD5 md5 = new MD5();

        // When
        String emptyStringHash = md5.encrypt("");
        String aHash = md5.encrypt("a");
        String abcHash = md5.encrypt("abc");
        String messageDigestHash = md5.encrypt("message digest");
        String allCharsHash = md5.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        String numbersHash = md5.encrypt("12345678901234567890123456789012345678901234567890123456789012345678901234567890");

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
        MD5 md5 = new MD5();
        String message = "abc";
        String salt = "some random salt";

        // When
        String actualHash = md5.encrypt(message, salt);

        // Then
        assertEquals("06ce46adfdc8c82c83eed82b58c304c5", actualHash);
    }
}