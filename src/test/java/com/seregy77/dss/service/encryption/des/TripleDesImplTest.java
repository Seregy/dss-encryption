package com.seregy77.dss.service.encryption.des;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TripleDesImplTest {

    @Test
    void encrypt_withoutPadding() throws DecoderException {
        String message = "some mes";

        byte[] key = new byte[3 * 8];

        System.arraycopy(Hex.decodeHex("42a888a8fd10b4d7"), 0, key, 0, 8);
        System.arraycopy(Hex.decodeHex("04d17f2861196cdb"), 0, key, 8, 8);
        System.arraycopy(Hex.decodeHex("42a888a8fd10b4d7"), 0, key, 16, 8);

        byte[] customEncrypted = new TripleDesImpl(new DesImpl()).encrypt(message.getBytes(), key);
        assertEquals("e9cedc88e61bf5cd", new String(Hex.encodeHex(customEncrypted)));
    }

    @Test
    void encrypt() throws DecoderException {
        String message = "some message";

        byte[] key = new byte[3 * 8];

        System.arraycopy(Hex.decodeHex("42a888a8fd10b4d7"), 0, key, 0, 8);
        System.arraycopy(Hex.decodeHex("04d17f2861196cdb"), 0, key, 8, 8);
        System.arraycopy(Hex.decodeHex("42a888a8fd10b4d7"), 0, key, 16, 8);

        byte[] customEncrypted = new TripleDesImpl(new DesImpl()).encrypt(message.getBytes(), key);
        assertEquals("e9cedc88e61bf5cd7aa3d40ffeb74415", new String(Hex.encodeHex(customEncrypted)));
    }

    @Test
    void decrypt_withoutPadding() throws DecoderException {
        // Given
        String encryptedMessage = "e9cedc88e61bf5cd";

        byte[] key = new byte[3 * 8];

        System.arraycopy(Hex.decodeHex("42a888a8fd10b4d7"), 0, key, 0, 8);
        System.arraycopy(Hex.decodeHex("04d17f2861196cdb"), 0, key, 8, 8);
        System.arraycopy(Hex.decodeHex("42a888a8fd10b4d7"), 0, key, 16, 8);

        byte[] customEncrypted = new TripleDesImpl(new DesImpl()).decrypt(Hex.decodeHex(encryptedMessage), key);
        assertEquals("some mes", new String(customEncrypted).trim());
    }

    @Test
    void decrypt() throws DecoderException {
        // Given
        String encryptedMessage = "e9cedc88e61bf5cd7aa3d40ffeb74415";

        byte[] key = new byte[3 * 8];

        System.arraycopy(Hex.decodeHex("42a888a8fd10b4d7"), 0, key, 0, 8);
        System.arraycopy(Hex.decodeHex("04d17f2861196cdb"), 0, key, 8, 8);
        System.arraycopy(Hex.decodeHex("42a888a8fd10b4d7"), 0, key, 16, 8);

        byte[] customEncrypted = new TripleDesImpl(new DesImpl()).decrypt(Hex.decodeHex(encryptedMessage), key);
        assertEquals("some message", new String(customEncrypted).trim());
    }
}