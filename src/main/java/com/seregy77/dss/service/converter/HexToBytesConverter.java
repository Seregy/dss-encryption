package com.seregy77.dss.service.converter;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.springframework.stereotype.Component;

@Component
public class HexToBytesConverter {
    public byte[] toBytes(String hexString) {
        try {
            return Hex.decodeHex(hexString);
        } catch (DecoderException e) {
            throw new RuntimeException(e);
        }
    }

    public String toHex(byte[] bytes) {
        return String.valueOf(Hex.encodeHex(bytes));
    }
}
