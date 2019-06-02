package com.seregy77.dss.web.domain.elgamal;

import lombok.Value;

import java.math.BigInteger;

@Value
public class ElGamalDecryptionRequest {
    private String c1;
    private String c2;
    private BigInteger prime;
    private BigInteger privateKey;
}
