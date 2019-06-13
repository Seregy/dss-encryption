package com.seregy77.dss.service.encryption.des;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;

@Service
public class DesImpl implements Des {
    private static final int BLOCK_SIZE_BITS = 64;
    private static final int HALF_BLOCK_SIZE_BITS = BLOCK_SIZE_BITS / 2;


    @Override
    public byte[] encrypt(byte[] message, byte[] key) {
        long longKey = new BigInteger(key).longValue();
        String[] keys = generateKeys(longKey);

        int sizeInBits = message.length * Byte.SIZE;
        String originalBitString = bytesToBitString(message);

        String bitMessage = appendZeroes(sizeInBits, originalBitString);

        StringBuilder paddedMessage = new StringBuilder().append(bitMessage);
        int messageLength = paddedMessage.length();
        int reminder = messageLength % BLOCK_SIZE_BITS;
        if (reminder != 0) {
            int bytesToAdd = (BLOCK_SIZE_BITS - reminder) / Byte.SIZE;
            String bitsToAdd = appendZeroes(Byte.SIZE, Integer.toBinaryString(bytesToAdd));
            paddedMessage.append(String.join("", Collections.nCopies(bytesToAdd, bitsToAdd)));
        }

        String[] plaintextBlocks = new String[paddedMessage.length() / BLOCK_SIZE_BITS];
        for (int i = 0; i < plaintextBlocks.length; i++) {
            int currentIndex = i * BLOCK_SIZE_BITS;
            plaintextBlocks[i] = paddedMessage.substring(currentIndex, currentIndex + BLOCK_SIZE_BITS);
        }

        String[] encryptedBlocks = new String[plaintextBlocks.length];
        for (int i = 0; i < encryptedBlocks.length; i++) {
            String bitString = appendZeroes(BLOCK_SIZE_BITS, encodeBlock(plaintextBlocks[i], keys));

            encryptedBlocks[i] = String.valueOf(Hex.encodeHex(binaryStringToBytes((bitString))));
        }

        StringBuilder encryptedMessage = new StringBuilder();
        for (String encryptedBlock : encryptedBlocks) {
            bitMessage = appendZeroes(sizeInBits, bitMessage);
            encryptedMessage.append(encryptedBlock);
        }

        try {
            return Hex.decodeHex(encryptedMessage.toString());
        } catch (DecoderException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] message, byte[] key) {
        long longKey = new BigInteger(key).longValue();
        String[] keys = generateKeys(longKey);
        ArrayUtils.reverse(keys);

        String[] plaintextBlocks = new String[message.length / Byte.SIZE];
        for (int i = 0; i < plaintextBlocks.length; i++) {


            int currentIndex = i * Byte.SIZE;
            byte[] block = Arrays.copyOfRange(message, currentIndex, currentIndex + Byte.SIZE);

            String bitString = appendZeroes(BLOCK_SIZE_BITS, Long.toBinaryString(new BigInteger(block).longValue()));
            plaintextBlocks[i] = bitString;
        }

        byte[][] decryptedBlocks = new byte[plaintextBlocks.length][Byte.SIZE];
        for (int i = 0; i < decryptedBlocks.length; i++) {
            String bitString = appendZeroes(BLOCK_SIZE_BITS, encodeBlock(plaintextBlocks[i], keys));
            decryptedBlocks[i] = Arrays.copyOf(binaryStringToBytes(bitString), Byte.SIZE);
        }


        String paddedBlock = appendZeroes(BLOCK_SIZE_BITS, bytesToBitString(decryptedBlocks[decryptedBlocks.length - 1]));

        int paddedCharacters = Integer.parseInt(paddedBlock.substring(paddedBlock.length() - Byte.SIZE), 2);
        int previousPaddedCharacters = Integer.parseInt(paddedBlock.substring(paddedBlock.length() - 16, paddedBlock.length() - Byte.SIZE), 2);
        if (paddedCharacters > BLOCK_SIZE_BITS || paddedCharacters != previousPaddedCharacters) {
            paddedCharacters = 0;
        }
        paddedBlock = paddedBlock.substring(0, paddedBlock.length() - paddedCharacters * Byte.SIZE);
        byte[] paddedBytes = binaryStringToBytes(paddedBlock);
        decryptedBlocks[decryptedBlocks.length - 1] = Arrays.copyOf(paddedBytes, paddedBytes.length);

        byte[] currentArray = new byte[0];
        for (byte[] decryptedBlock : decryptedBlocks) {
            currentArray = ArrayUtils.addAll(currentArray, decryptedBlock);
        }

        return currentArray;
    }

    private static byte[] binaryStringToBytes(String binaryString) {
        int splitSize = Byte.SIZE;

        if (binaryString.length() % splitSize != 0) {
            throw new IllegalArgumentException("Input length. '" + binaryString + "' must be divisible by 8");
        }

        int index = 0;
        int position = 0;

        byte[] resultByteArray = new byte[binaryString.length() / splitSize];
        StringBuilder text = new StringBuilder(binaryString);

        while (index < text.length()) {
            String binaryStringChunk = text.substring(index, Math.min(index + splitSize, text.length()));
            int byteAsInt = Integer.parseInt(binaryStringChunk, 2);
            resultByteArray[position] = (byte) byteAsInt;
            index += splitSize;
            position++;
        }
        return resultByteArray;
    }

    private String[] generateKeys(long key) {
        String binaryString = appendZeroes(BLOCK_SIZE_BITS, Long.toBinaryString(key));

        int[] permutationTable = {57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4};

        StringBuilder permutated = new StringBuilder();

        for (int value : permutationTable) {
            permutated.append(binaryString.charAt(value - 1));
        }

        Key[] keys = new Key[17];

        keys[0] = new Key(permutated.substring(0, 28), permutated.substring(28, permutated.length()), "");

        int[] keyRotationTable = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};


        int[] permutationTable2 = {
                14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32
        };

        for (int i = 1; i < keys.length; i++) {
            Key previous = keys[i - 1];

            String cString = appendZeroes(28, leftShift(previous.getC(), keyRotationTable[i - 1]));

            String dString = appendZeroes(28, leftShift(previous.getD(), keyRotationTable[i - 1]));

            String cd = appendZeroes(56, cString + dString);

            StringBuilder permutatedKey = new StringBuilder();

            for (int value : permutationTable2) {
                permutatedKey.append(cd.charAt(value - 1));
            }

            keys[i] = new Key(cString, dString, permutatedKey.toString());
        }

        String[] resultKeys = new String[16];
        for (int i = 1; i < keys.length; i++) {
            resultKeys[i - 1] = keys[i].getCd();
        }

        return resultKeys;
    }

    private String leftShift(String stringToShift, int shiftAmount) {
        String result = stringToShift;
        for (int i = 0; i < shiftAmount; i++) {
            result = leftShift(result);
        }

        return result;
    }

    private String leftShift(String stringToShift) {
        return stringToShift.substring(1) + stringToShift.charAt(0);
    }

    private String encodeBlock(String bitString, String[] keys) {
        int[] initialPermutation = {
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7
        };

        StringBuilder permutatedBlock = new StringBuilder();
        for (int value : initialPermutation) {
            permutatedBlock.append(bitString.charAt(value - 1));
        }

        long[] l = new long[17];
        l[0] = Long.parseLong(permutatedBlock.substring(0, HALF_BLOCK_SIZE_BITS), 2);
        long[] r = new long[17];
        r[0] = Long.parseLong(permutatedBlock.substring(HALF_BLOCK_SIZE_BITS, permutatedBlock.length()), 2);

        for (int i = 1; i < 17; i++) {
            l[i] = r[i - 1];
            r[i] = l[i - 1] ^ f(r[i - 1], Long.parseLong(keys[i - 1], 2));
        }

        String bitR = appendZeroes(HALF_BLOCK_SIZE_BITS, Long.toBinaryString(r[16]));
        String bitL = appendZeroes(HALF_BLOCK_SIZE_BITS, Long.toBinaryString(l[16]));

        int[] finalPermutation = {
                40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25
        };

        String combined = bitR + bitL;

        StringBuilder finalPermutated = new StringBuilder();
        for (int value : finalPermutation) {
            finalPermutated.append(combined.charAt(value - 1));
        }

        return finalPermutated.toString();
    }

    private long f(long r, long key) {
        long expanded = expandBlock(r);

        long step = key ^ expanded;
        String[] bitStrings = splitIntoSixBitGroups(step);

        int[][][] s = {
                {
                        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
                },
                {
                        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
                },

                {
                        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
                },
                {
                        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
                },
                {
                        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
                },
                {
                        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
                },
                {
                        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
                },
                {
                        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
                }
        };

        StringBuilder bitString = new StringBuilder();
        for (int i = 0; i < Byte.SIZE; i++) {
            int row = getRow(bitStrings[i]);
            int column = getColumn(bitStrings[i]);
            String stepString = appendZeroes(4, Long.toBinaryString(s[i][row][column]));

            bitString.append(stepString);
        }

        int[] finalPermutation = {
                16, 7, 20, 21,
                29, 12, 28, 17,
                1, 15, 23, 26,
                5, 18, 31, 10,
                2, 8, 24, 14,
                32, 27, 3, 9,
                19, 13, 30, 6,
                22, 11, 4, 25
        };

        StringBuilder permutatedString = new StringBuilder();
        for (int i = 0; i < bitString.length(); i++) {
            permutatedString.append(bitString.charAt(finalPermutation[i] - 1));
        }

        return Long.parseLong(permutatedString.toString(), 2);
    }

    private int getRow(String bitString) {
        String bitValue = "" + bitString.charAt(0) + bitString.charAt(bitString.length() - 1);
        return Integer.parseInt(bitValue, 2);
    }

    private int getColumn(String bitString) {
        String bitValue = "" + bitString.substring(1, bitString.length() - 1);
        return Integer.parseInt(bitValue, 2);
    }

    private String[] splitIntoSixBitGroups(long value) {
        String bitString = appendZeroes(48, Long.toBinaryString(value));

        String[] strings = new String[Byte.SIZE];
        for (int i = 0; i < Byte.SIZE; i++) {
            int startIndex = i * 6;
            strings[i] = bitString.substring(startIndex, startIndex + 6);
        }

        return strings;
    }

    private long expandBlock(long block) {
        String bitString = appendZeroes(HALF_BLOCK_SIZE_BITS, Long.toBinaryString(block));

        int[] expansion = new int[]{32, 1, 2, 3, 4, 5,
                4, 5, 6, 7, 8, 9,
                8, 9, 10, 11, 12, 13,
                12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21,
                20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,
                28, 29, 30, 31, 32, 1};

        StringBuilder expandedBlock = new StringBuilder();
        for (int i : expansion) {
            expandedBlock.append(bitString.charAt(i - 1));
        }

        return Long.parseLong(expandedBlock.toString(), 2);
    }

    private String bytesToBitString(byte[] bytes) {
        StringBuilder bitString = new StringBuilder();
        for (byte value : bytes) {
            bitString.append(byteToBitString(value));
        }

        return bitString.toString();
    }

    private String byteToBitString(byte byteValue) {
        return Integer.toBinaryString((byteValue & 0xFF) + 0x100).substring(1);
    }

    private String appendZeroes(int desiredSize, String originalString) {
        StringBuilder stringBuilder = new StringBuilder(originalString);
        while (stringBuilder.length() < desiredSize) {
            stringBuilder.insert(0, "0");
        }
        return stringBuilder.toString();
    }
}
