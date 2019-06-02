package com.seregy77.dss.web.domain;

import lombok.Value;

@Value
public class HashingRequest {
    private String message;
    private String salt;
}
