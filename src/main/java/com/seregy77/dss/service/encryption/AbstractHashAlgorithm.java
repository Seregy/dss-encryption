package com.seregy77.dss.service.encryption;

public abstract class AbstractHashAlgorithm implements HashAlgorithm {
    @Override
    public String encrypt(String message, String salt) {
        String saltedMessage = message;
        if (salt != null) {
            saltedMessage += salt;
        }

        return encrypt(saltedMessage);
    }
}
