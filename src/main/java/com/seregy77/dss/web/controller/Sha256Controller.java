package com.seregy77.dss.web.controller;

import com.seregy77.dss.service.encryption.sha256.Sha256;
import com.seregy77.dss.web.domain.HashingRequest;
import com.seregy77.dss.web.domain.HashingResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("sha256")
@RequiredArgsConstructor
public class Sha256Controller {
    private final Sha256 sha256;

    @PostMapping("/hash")
    public HashingResponse hashWithMd5(@RequestBody HashingRequest hashingRequest) {
        return new HashingResponse(sha256.encrypt(hashingRequest.getMessage(), hashingRequest.getSalt()));
    }
}
