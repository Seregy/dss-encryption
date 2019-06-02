package com.seregy77.dss.service.encryption;

public interface SymmetricAlgorithm {
    byte[] encrypt(byte[] message, byte[] key);

    byte[] decrypt(byte[] message, byte[] key);
}
