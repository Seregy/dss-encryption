package com.seregy77.dss.encryption.des;

import com.seregy77.dss.encryption.SymmetricAlgorithm;
import lombok.AllArgsConstructor;

import java.util.Arrays;

@AllArgsConstructor
public class TripleDes implements SymmetricAlgorithm {
    private final DES des;

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
        byte[][] keys = new byte[3][8];
        for (int i = 0; i < keys.length; i++) {
            int currentIndex = i * 8;
            keys[i] = Arrays.copyOfRange(key, currentIndex, currentIndex + 8);
        }

        return keys;
    }
}
