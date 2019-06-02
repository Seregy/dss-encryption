package com.seregy77.dss.service.encryption.des;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
@AllArgsConstructor
public class TripleDesImpl implements TripleDes {
    private final Des des;

    @Override
    public byte[] encrypt(byte[] message, byte[] key) {
        byte[][] keys = generateKeys(key);

        byte[] encryptedFirstKey = des.encrypt(message, keys[0]);
        byte[] decryptedSecondKey = des.decrypt(encryptedFirstKey, keys[1]);

        return des.encrypt(decryptedSecondKey, keys[2]);
    }

    @Override
    public byte[] decrypt(byte[] message, byte[] key) {
        byte[][] keys = generateKeys(key);

        byte[] decryptedThirdKey = des.decrypt(message, keys[2]);
        byte[] encryptedSecondKey = des.encrypt(decryptedThirdKey, keys[1]);

        return des.decrypt(encryptedSecondKey, keys[0]);
    }

    private byte[][] generateKeys(byte[] key) {
        if (key.length < 2 * 8) {
            throw new IllegalArgumentException("Key must be 192 bits long");
        }

        byte[][] keys = new byte[3][8];
        keys[0] = Arrays.copyOfRange(key, 0, 8);
        keys[1] = Arrays.copyOfRange(key, 8, 16);
        keys[2] = Arrays.copyOfRange(key, 0, 8);

        return keys;
    }
}
