package com.seregy77.dss.encryption.md5;

import lombok.Value;

@Value
class Words {
    private int a;
    private int b;
    private int c;
    private int d;

    Words add(Words anotherResult) {
        return new Words(a + anotherResult.getA(),
                b + anotherResult.getB(),
                c + anotherResult.getC(),
                d + anotherResult.getD());
    }
}
