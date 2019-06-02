package com.seregy77.dss.service.encryption.elgamal;

public interface ElGamal {
    Ciphertext encrypt(byte[] message, byte[] prime, byte[] base, byte[] publicKey);

    byte[] decrypt(Ciphertext ciphertext, byte[] prime, byte[] privateKey);

    ElGamalKeys generateKeys();
}
