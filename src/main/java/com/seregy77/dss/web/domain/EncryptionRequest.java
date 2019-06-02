package com.seregy77.dss.web.domain;

import lombok.Value;

@Value
public class EncryptionRequest {
    private String message;
    private String key;
}
