package com.seregy77.dss.web.domain;

import lombok.Value;

@Value
public class DecryptionRequest {
    private String encryptedMessage;
    private String key;
}
