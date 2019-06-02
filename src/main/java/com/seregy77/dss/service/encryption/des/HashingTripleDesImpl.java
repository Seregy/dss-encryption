package com.seregy77.dss.service.encryption.des;

import com.seregy77.dss.service.converter.HexToBytesConverter;
import com.seregy77.dss.service.converter.Utf8ToBytesConverter;
import com.seregy77.dss.service.encryption.md5.Md5;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class HashingTripleDesImpl implements HashingTripleDes {
    private final TripleDes tripleDes;
    private final Md5 md5;
    private final Utf8ToBytesConverter utf8ToBytesConverter;
    private final HexToBytesConverter hexToBytesConverter;


    @Override
    public byte[] encrypt(byte[] message, byte[] key) {
        String hashedKey = md5.encrypt(utf8ToBytesConverter.toUtf8String(key));
        byte[] hashedKeyBytes = hexToBytesConverter.toBytes(hashedKey);

        return tripleDes.encrypt(message, hashedKeyBytes);
    }

    @Override
    public byte[] decrypt(byte[] message, byte[] key) {
        String hashedKey = md5.encrypt(utf8ToBytesConverter.toUtf8String(key));
        byte[] hashedKeyBytes = hexToBytesConverter.toBytes(hashedKey);

        return tripleDes.decrypt(message, hashedKeyBytes);
    }
}
