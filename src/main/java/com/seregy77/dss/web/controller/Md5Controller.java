package com.seregy77.dss.web.controller;

import com.seregy77.dss.service.encryption.md5.Md5;
import com.seregy77.dss.web.domain.HashingRequest;
import com.seregy77.dss.web.domain.HashingResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("md5")
@RequiredArgsConstructor
public class Md5Controller {
    private final Md5 md5;

    @PostMapping("/encrypt")
    public HashingResponse encryptWithMd5(@RequestBody HashingRequest hashingRequest) {
        return new HashingResponse(md5.encrypt(hashingRequest.getMessage(), hashingRequest.getSalt()));
    }
}
