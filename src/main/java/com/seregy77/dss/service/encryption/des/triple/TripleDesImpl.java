package com.seregy77.dss.service.encryption.des.triple;

import com.seregy77.dss.service.encryption.des.Des;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class TripleDesImpl implements TripleDes {
    private final Des des;

    @Override
    public byte[] encrypt(byte[] message, byte[] key) {
        TripleDesKey tripleDesKey = TripleDesKey.from(key);

        byte[] encryptedFirstKey = des.encrypt(message, tripleDesKey.getFirstKey());
        byte[] decryptedSecondKey = des.decrypt(encryptedFirstKey, tripleDesKey.getSecondKey());

        return des.encrypt(decryptedSecondKey, tripleDesKey.getThirdKey());
    }

    @Override
    public byte[] decrypt(byte[] message, byte[] key) {
        TripleDesKey tripleDesKey = TripleDesKey.from(key);

        byte[] decryptedThirdKey = des.decrypt(message, tripleDesKey.getThirdKey());
        byte[] encryptedSecondKey = des.encrypt(decryptedThirdKey, tripleDesKey.getSecondKey());

        return des.decrypt(encryptedSecondKey, tripleDesKey.getFirstKey());
    }
}
