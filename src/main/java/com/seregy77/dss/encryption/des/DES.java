package com.seregy77.dss.encryption.des;

import com.seregy77.dss.encryption.SymmetricAlgorithm;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;

public class DES implements SymmetricAlgorithm {
    private static final int BLOCK_SIZE = 64 / Byte.SIZE;
    private static final int HALF_BLOCK_SIZE = BLOCK_SIZE / 2;
    private static final int KEY_SIZE = 56 / Byte.SIZE;

    @Override
    public byte[] encrypt(byte[] message, byte[] key) {
        long longKey = new BigInteger(key).longValue();
        String[] keys = generateKeys(longKey);

        int sizeInBits = message.length * 8;
        BigInteger bigInteger = new BigInteger(message);
        String originalBitString = bigInteger.toString(2);
        originalBitString = originalBitString.replace("-", "1");
        StringBuilder bitMessage = new StringBuilder(originalBitString);

        while (bitMessage.length() < sizeInBits) {
            bitMessage.insert(0, "0");
        }


        StringBuilder paddedMessage = new StringBuilder().append(bitMessage);
        int messageLength = paddedMessage.length();
        int reminder = messageLength % 64;
        if (reminder != 0) {
            int bytesToAdd = (64 - reminder) / 8;
            StringBuilder bitsToAdd = new StringBuilder(Integer.toBinaryString(bytesToAdd));
            while (bitsToAdd.length() < 8) {
                bitsToAdd.insert(0, "0");
            }
            paddedMessage.append(String.join("", Collections.nCopies(bytesToAdd, bitsToAdd.toString())));
        }

        String[] plaintextBlocks = new String[paddedMessage.length() / 64];
        for (int i = 0; i < plaintextBlocks.length; i++) {
            int currentIndex = i * 64;
            plaintextBlocks[i] = paddedMessage.substring(currentIndex, currentIndex + 64);
        }

        String[] encryptedBlocks = new String[plaintextBlocks.length];
        for (int i = 0; i < encryptedBlocks.length; i++) {
            StringBuilder bitString = new StringBuilder(encodeBlock(plaintextBlocks[i], keys));
            while (bitString.length() < 64) {
                bitString.insert(0, "0");
            }
            encryptedBlocks[i] = new BigInteger(bitString.toString(), 2).toString(16);
        }

        StringBuilder encryptedMessage = new StringBuilder();
        for (String encryptedBlock : encryptedBlocks) {
            while (bitMessage.length() < sizeInBits) {
                bitMessage.insert(0, "0");
            }
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

        String[] plaintextBlocks = new String[message.length / 8];
        for (int i = 0; i < plaintextBlocks.length; i++) {


            int currentIndex = i * 8;
            byte[] block = Arrays.copyOfRange(message, currentIndex, currentIndex + 8);


            StringBuilder bitString = new StringBuilder(Long.toBinaryString(new BigInteger(block).longValue()));
            while (bitString.length() < 64) {
                bitString.insert(0, "0");
            }
            plaintextBlocks[i] = bitString.toString();
        }

        byte[][] decryptedBlocks = new byte[plaintextBlocks.length][8];
        for (int i = 0; i < decryptedBlocks.length; i++) {
            StringBuilder bitString = new StringBuilder(encodeBlock(plaintextBlocks[i], keys));
            while (bitString.length() < 64) {
                bitString.insert(0, "0");
            }
            decryptedBlocks[i] = new BigInteger(bitString.toString(), 2).toByteArray();
        }

        StringBuilder paddedBlock = new StringBuilder(new BigInteger(decryptedBlocks[decryptedBlocks.length - 1]).toString(2));
        while (paddedBlock.length() < 64) {
            paddedBlock.insert(0, "0");
        }

        int paddedCharacters = Integer.parseInt(paddedBlock.substring(paddedBlock.length() - 8, paddedBlock.length()), 2);
        if (paddedCharacters > 64) {
            paddedCharacters = 0;
        }
        paddedBlock = new StringBuilder(paddedBlock.substring(0, paddedBlock.length() - paddedCharacters * 8));
        decryptedBlocks[decryptedBlocks.length - 1] = Arrays.copyOf(binaryStringToBytes(paddedBlock.toString()), 8);

        byte[] decryptedMessage = new byte[8 * decryptedBlocks.length];
        for (int i = 0; i < decryptedBlocks.length; i++) {
            int currentIndex = i * 8;
            System.arraycopy(decryptedBlocks[i], 0, decryptedMessage, currentIndex, 8);
        }

        return decryptedMessage;
    }

    private static byte[] binaryStringToBytes(String binaryString) {
        int splitSize = 8;

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
        StringBuilder binaryString = new StringBuilder(Long.toBinaryString(key));
        while (binaryString.length() < 64) {
            binaryString.insert(0, "0");
        }

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

            StringBuilder cString = new StringBuilder().append(leftShift(previous.getC(), keyRotationTable[i - 1]));
            while (cString.length() < 28) {
                cString.insert(0, "0");
            }

            StringBuilder dString = new StringBuilder().append(leftShift(previous.getD(), keyRotationTable[i - 1]));
            while (dString.length() < 28) {
                dString.insert(0, "0");
            }

            StringBuilder cd = new StringBuilder().append(cString).append(dString);
            while (cd.length() < 56) {
                cd.insert(0, "0");
            }

            StringBuilder permutatedKey = new StringBuilder();

            for (int value : permutationTable2) {
                permutatedKey.append(cd.charAt(value - 1));
            }

            keys[i] = new Key(cString.toString(), dString.toString(), permutatedKey.toString());
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
        l[0] = Long.parseLong(permutatedBlock.substring(0, 32), 2);
        long[] r = new long[17];
        r[0] = Long.parseLong(permutatedBlock.substring(32, permutatedBlock.length()), 2);

        for (int i = 1; i < 17; i++) {
            l[i] = r[i - 1];
            r[i] = l[i - 1] ^ f(r[i - 1], Long.parseLong(keys[i - 1], 2));
        }

        StringBuilder bitR = new StringBuilder().append(Long.toBinaryString(r[16]));
        while (bitR.length() < 32) {
            bitR.insert(0, "0");
        }

        StringBuilder bitL = new StringBuilder().append(Long.toBinaryString(l[16]));
        while (bitL.length() < 32) {
            bitL.insert(0, "0");
        }

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

        String combined = bitR.append(bitL).toString();

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
        for (int i = 0; i < 8; i++) {
            int row = getRow(bitStrings[i]);
            int column = getColumn(bitStrings[i]);
            StringBuilder stepString = new StringBuilder().append(Long.toBinaryString(s[i][row][column]));
            while (stepString.length() < 4) {
                stepString.insert(0, "0");
            }

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
        StringBuilder bitString = new StringBuilder(Long.toBinaryString(value));
        while (bitString.length() < 48) {
            bitString.insert(0, "0");
        }

        String[] strings = new String[8];
        for (int i = 0; i < 8; i++) {
            int startIndex = i * 6;
            strings[i] = bitString.substring(startIndex, startIndex + 6);
        }

        return strings;
    }

    private long expandBlock(long block) {
        StringBuilder bitString = new StringBuilder(Long.toBinaryString(block));
        while (bitString.length() < 32) {
            bitString.insert(0, "0");
        }

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
}
