package com.seregy77.dss.web.controller;

import com.seregy77.dss.service.converter.HexToBytesConverter;
import com.seregy77.dss.service.converter.Utf8ToBytesConverter;
import com.seregy77.dss.service.encryption.elgamal.Ciphertext;
import com.seregy77.dss.service.encryption.elgamal.ElGamal;
import com.seregy77.dss.service.encryption.elgamal.ElGamalKeys;
import com.seregy77.dss.web.domain.DecryptionResponse;
import com.seregy77.dss.web.domain.elgamal.ElGamalDecryptionRequest;
import com.seregy77.dss.web.domain.elgamal.ElGamalEncryptionRequest;
import com.seregy77.dss.web.domain.elgamal.ElGamalEncryptionResponse;
import com.seregy77.dss.web.domain.elgamal.ElGamalKeysResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;


@RestController
@RequestMapping("elgamal")
@RequiredArgsConstructor
public class ElGamalController {
    private final Utf8ToBytesConverter utf8ToBytesConverter;
    private final HexToBytesConverter hexToBytesConverter;
    private final ElGamal elGamal;

    @PostMapping("/encrypt")
    public ElGamalEncryptionResponse encryptWithHashingTripleDes(@RequestBody ElGamalEncryptionRequest encryptionRequest) {
        byte[] messageBytes = utf8ToBytesConverter.toBytes(encryptionRequest.getMessage());
        byte[] prime = encryptionRequest.getPrime().toByteArray();
        byte[] base = encryptionRequest.getBase().toByteArray();
        byte[] publicKey = encryptionRequest.getPublicKey().toByteArray();

        Ciphertext encryptedResponse = elGamal.encrypt(messageBytes, prime, base, publicKey);
        return new ElGamalEncryptionResponse(hexToBytesConverter.toHex(encryptedResponse.getC1()), hexToBytesConverter.toHex(encryptedResponse.getC2()));
    }

    @PostMapping("/decrypt")
    public DecryptionResponse decryptWithHashingTripleDes(@RequestBody ElGamalDecryptionRequest decryptionRequest) {
        byte[] c1 = hexToBytesConverter.toBytes(decryptionRequest.getC1());
        byte[] c2 = hexToBytesConverter.toBytes(decryptionRequest.getC2());

        byte[] prime = decryptionRequest.getPrime().toByteArray();
        byte[] privateKey = decryptionRequest.getPrivateKey().toByteArray();

        byte[] decryptedResponse = elGamal.decrypt(new Ciphertext(c1, c2), prime, privateKey);
        return new DecryptionResponse(utf8ToBytesConverter.toUtf8String(decryptedResponse));
    }

    @GetMapping("/keys")
    public ElGamalKeysResponse generateKeys() {

        ElGamalKeys elGamalKeys = elGamal.generateKeys();
        String prime = new BigInteger(elGamalKeys.getPrime()).toString();
        String base = new BigInteger(elGamalKeys.getBase()).toString();
        String privateKey = new BigInteger(elGamalKeys.getPrivateKey()).toString();
        String publicKey = new BigInteger(elGamalKeys.getPublicKey()).toString();
        return new ElGamalKeysResponse(prime, base, privateKey, publicKey);
    }
}
