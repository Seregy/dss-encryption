package com.seregy77.dss.service.encryption.elgamal;

import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

@Service
public class ElGamalImpl implements ElGamal {
    private static final String P_NOT_PRIME_FORMATTED_MESSAGE = "P [%s] must be a prime number";
    private static final String VALUE_MUST_BE_IN_RANGE_FORMATTED_MESSAGE = "%s [%s] must be in range [1; p - 1]";
    private static final int PRIME_CERTAINTY = 100;
    private static final int PRIME_BIT_LENGTH = 160;
    private static final int RANDOM_NUMBER_BIT_LENGTH = PRIME_BIT_LENGTH * 2;

    @Override
    public Ciphertext encrypt(byte[] message, byte[] prime, byte[] base, byte[] publicKey) {
        BigInteger primeInteger = new BigInteger(prime);

        if (isNotPrime(primeInteger)) {
            throw new IllegalArgumentException(String.format(P_NOT_PRIME_FORMATTED_MESSAGE, primeInteger.toString()));
        }

        BigInteger primitiveRoot = new BigInteger(base);
        if (isNotFromOneToPrime(primitiveRoot, primeInteger)) {
            throw new IllegalArgumentException(String.format(VALUE_MUST_BE_IN_RANGE_FORMATTED_MESSAGE, "G", primitiveRoot.toString()));
        }

        BigInteger publicKeyInteger = new BigInteger(publicKey);
        if (isNotFromOneToPrime(publicKeyInteger, primeInteger)) {
            throw new IllegalArgumentException(String.format(VALUE_MUST_BE_IN_RANGE_FORMATTED_MESSAGE, "H", publicKeyInteger.toString()));
        }

        BigInteger intMessage = new BigInteger(message);
        if (isNotFromOneToPrime(intMessage, primeInteger)) {
            throw new IllegalArgumentException(String.format(VALUE_MUST_BE_IN_RANGE_FORMATTED_MESSAGE, "Message", intMessage.toString()));
        }

        BigInteger encryptedMessage1 = primitiveRoot.modPow(publicKeyInteger, primeInteger);
        BigInteger encryptedMessage2 = intMessage.multiply(publicKeyInteger.modPow(publicKeyInteger, primeInteger)).mod(primeInteger);

        return new Ciphertext(encryptedMessage1.toByteArray(), encryptedMessage2.toByteArray());
    }

    @Override
    public byte[] decrypt(Ciphertext encryptedResponse, byte[] prime, byte[] privateKey) {
        BigInteger primeInteger = new BigInteger(prime);

        if (isNotPrime(primeInteger)) {
            throw new IllegalArgumentException(String.format(P_NOT_PRIME_FORMATTED_MESSAGE, primeInteger.toString()));
        }

        BigInteger privateKeyInteger = new BigInteger(privateKey);
        if (isNotFromOneToPrime(privateKeyInteger, primeInteger)) {
            throw new IllegalArgumentException(String.format(VALUE_MUST_BE_IN_RANGE_FORMATTED_MESSAGE, "X", privateKeyInteger.toString()));
        }

        BigInteger c1 = new BigInteger(encryptedResponse.getC1());
        BigInteger c2 = new BigInteger(encryptedResponse.getC2());
        BigInteger s = c1.modPow(privateKeyInteger, primeInteger);
        BigInteger message = c2.multiply(s.modPow(primeInteger.subtract(BigInteger.valueOf(2)), primeInteger)).mod(primeInteger);
        return message.toByteArray();
    }

    public ElGamalKeys generateKeys() {
        BigInteger prime = BigInteger.probablePrime(PRIME_BIT_LENGTH, new Random());
        BigInteger base = generateRandomBigInteger(prime);
        BigInteger privateKey = generateRandomBigInteger(prime);
        BigInteger publicKey = base.modPow(privateKey, prime);

        return new ElGamalKeys(prime.toByteArray(), base.toByteArray(), privateKey.toByteArray(), publicKey.toByteArray());
    }

    private boolean isNotPrime(BigInteger bigInteger) {
        return !bigInteger.isProbablePrime(PRIME_CERTAINTY);
    }

    private boolean isNotFromOneToPrime(BigInteger valueToCheck, BigInteger prime) {
        return isNotInRange(valueToCheck, BigInteger.ONE, prime.subtract(BigInteger.ONE));
    }

    private boolean isNotInRange(BigInteger valueToCheck, BigInteger lowerBound, BigInteger upperBound) {
        return valueToCheck.compareTo(lowerBound) < 0 || valueToCheck.compareTo(upperBound) > 0;
    }

    private BigInteger generateRandomBigInteger(BigInteger upperBound) {
        return new BigInteger(RANDOM_NUMBER_BIT_LENGTH, ThreadLocalRandom.current()).mod(upperBound);
    }
}
