package com.seregy77.dss.service.encryption.elgamal;

import lombok.Value;

@Value
public class ElGamalKeys {
    private final byte[] prime;
    private final byte[] base;
    private final byte[] privateKey;
    private final byte[] publicKey;
}
