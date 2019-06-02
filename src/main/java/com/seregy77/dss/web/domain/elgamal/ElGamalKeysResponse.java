package com.seregy77.dss.web.domain.elgamal;

import lombok.Value;

@Value
public class ElGamalKeysResponse {
    private final String prime;
    private final String base;
    private final String privateKey;
    private final String publicKey;
}
