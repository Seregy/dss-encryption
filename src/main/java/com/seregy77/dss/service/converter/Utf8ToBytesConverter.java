package com.seregy77.dss.service.converter;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

@Component
public class Utf8ToBytesConverter {
    public byte[] toBytes(String utf8String) {
        return utf8String.getBytes(StandardCharsets.UTF_8);
    }

    public String toUtf8String(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
