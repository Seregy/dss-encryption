package com.seregy77.dss.service.encryption.sha256;

import com.seregy77.dss.service.converter.HexToBytesConverter;
import com.seregy77.dss.service.encryption.AbstractHashAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Service
@RequiredArgsConstructor
public class Sha256Impl extends AbstractHashAlgorithm implements Sha256 {
    private final HexToBytesConverter hexToBytesConverter;

    @Override
    public String encrypt(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
            return hexToBytesConverter.toHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
