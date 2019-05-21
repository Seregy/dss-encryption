package com.seregy77.dss.encryption;

public interface SymmetricAlgorithm {
    String encrypt(String message, String key);
    String decrypt(String message, String key);
}
