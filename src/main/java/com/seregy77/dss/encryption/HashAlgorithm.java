package com.seregy77.dss.encryption;

public interface HashAlgorithm {
    String encrypt(String message, String salt);
    String encrypt(String message);
}
