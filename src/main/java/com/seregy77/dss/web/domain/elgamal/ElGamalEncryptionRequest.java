package com.seregy77.dss.web.domain.elgamal;

import lombok.Value;

import java.math.BigInteger;

@Value
public class ElGamalEncryptionRequest {
    private String message;
    private BigInteger prime;
    private BigInteger base;
    private BigInteger publicKey;
}
