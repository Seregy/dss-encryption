package com.seregy77.dss.web.controller;

import com.seregy77.dss.service.converter.HexToBytesConverter;
import com.seregy77.dss.service.converter.Utf8ToBytesConverter;
import com.seregy77.dss.service.encryption.des.HashingTripleDes;
import com.seregy77.dss.service.encryption.des.TripleDes;
import com.seregy77.dss.web.domain.DecryptionRequest;
import com.seregy77.dss.web.domain.DecryptionResponse;
import com.seregy77.dss.web.domain.EncryptionRequest;
import com.seregy77.dss.web.domain.EncryptionResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("tdes")
@RequiredArgsConstructor
public class TripleDesController {
    private final Utf8ToBytesConverter utf8ToBytesConverter;
    private final HexToBytesConverter hexToBytesConverter;
    private final TripleDes tripleDes;
    private final HashingTripleDes hashingTripleDes;

    @PostMapping("/encrypt-strict")
    public EncryptionResponse encryptWithTripleDes(@RequestBody EncryptionRequest encryptionRequest) {
        byte[] messageBytes = utf8ToBytesConverter.toBytes(encryptionRequest.getMessage());
        byte[] keyBytes = utf8ToBytesConverter.toBytes(encryptionRequest.getKey());

        byte[] encryptedBytes = tripleDes.encrypt(messageBytes, keyBytes);
        return new EncryptionResponse(hexToBytesConverter.toHex(encryptedBytes));
    }

    @PostMapping("/decrypt-strict")
    public DecryptionResponse decryptWithTripleDes(@RequestBody DecryptionRequest decryptionRequest) {
        byte[] messageBytes = hexToBytesConverter.toBytes(decryptionRequest.getEncryptedMessage());
        byte[] keyBytes = utf8ToBytesConverter.toBytes(decryptionRequest.getKey());

        byte[] encryptedBytes = tripleDes.decrypt(messageBytes, keyBytes);
        return new DecryptionResponse(utf8ToBytesConverter.toUtf8String(encryptedBytes));
    }

    @PostMapping("/encrypt")
    public EncryptionResponse encryptWithHashingTripleDes(@RequestBody EncryptionRequest encryptionRequest) {
        byte[] messageBytes = utf8ToBytesConverter.toBytes(encryptionRequest.getMessage());
        byte[] keyBytes = utf8ToBytesConverter.toBytes(encryptionRequest.getKey());

        byte[] encryptedBytes = hashingTripleDes.encrypt(messageBytes, keyBytes);
        return new EncryptionResponse(hexToBytesConverter.toHex(encryptedBytes));
    }

    @PostMapping("/decrypt")
    public DecryptionResponse decryptWithHashingTripleDes(@RequestBody DecryptionRequest decryptionRequest) {
        byte[] messageBytes = hexToBytesConverter.toBytes(decryptionRequest.getEncryptedMessage());
        byte[] keyBytes = utf8ToBytesConverter.toBytes(decryptionRequest.getKey());

        byte[] encryptedBytes = hashingTripleDes.decrypt(messageBytes, keyBytes);
        return new DecryptionResponse(utf8ToBytesConverter.toUtf8String(encryptedBytes));
    }
}
