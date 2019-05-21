package com.seregy77.dss.encryption.des;

import org.junit.jupiter.api.Test;


import static org.junit.jupiter.api.Assertions.*;

class DESTest {
    @Test
    public void encrypt() throws Exception {
        // Given
        String message = "some message";
        String key = "my key";

        String customEncrypted = new DES().encrypt(message, key);
        assertEquals("7de1102e64687a3d979610cc80b5fb3b", customEncrypted);
    }

    @Test
    public void decrypt() throws Exception {
        // Given
        String encryptedMessage = "7de1102e64687a3d979610cc80b5fb3b";
        String key = "my key";

        String customEncrypted = new DES().decrypt(encryptedMessage, key);
        assertEquals("some message", customEncrypted);
    }
}