package com.seregy77.dss.service.encryption.elgamal;

import lombok.Value;

@Value
public class Ciphertext {
    private byte[] c1;
    private byte[] c2;
}
