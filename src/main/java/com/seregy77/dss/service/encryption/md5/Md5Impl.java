package com.seregy77.dss.service.encryption.md5;

import com.seregy77.dss.service.encryption.AbstractHashAlgorithm;
import org.springframework.stereotype.Service;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;

@Service
public class Md5Impl extends AbstractHashAlgorithm implements Md5 {
    private static final int OPERATION_AMOUNT = 16;
    private static final int ROUND_AMOUNT = 4;

    private static final int BLOCK_SIZE = 512 / Byte.SIZE;
    private static final int HASH_SIZE = 128 / Byte.SIZE;

    private static final byte FIRST_PADDING_SYMBOL = (byte) 0b10000000;
    private static final int[][] SHIFTS = new int[][]{
            {7, 12, 17, 22},
            {5, 9, 14, 20},
            {4, 11, 16, 23},
            {6, 10, 15, 21}
    };

    private static final int INITIAL_A = 0x67452301;
    private static final int INITIAL_B = 0xefcdab89;
    private static final int INITIAL_C = 0x98badcfe;
    private static final int INITIAL_D = 0x10325476;

    private final int[] T = initT();

    @Override
    public String encrypt(String message) {
        byte[] messageBytes = message.getBytes();
        ByteBuffer paddedMessageBuffer = getPaddedByteBuffer(messageBytes);

        Words finalResult = new Words(INITIAL_A, INITIAL_B, INITIAL_C, INITIAL_D);

        while (paddedMessageBuffer.hasRemaining()) {
            // obtain a slice of the buffer from the current position,
            // and view it as an array of 32-bit ints
            IntBuffer messageChunk = paddedMessageBuffer.slice().order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();

            finalResult = processBlock(finalResult, messageChunk);

            paddedMessageBuffer.position(paddedMessageBuffer.position() + BLOCK_SIZE);
        }

        byte[] md5Bytes = generateResultingBytes(finalResult);
        return toHexString(md5Bytes);
    }

    private Words processBlock(Words previousBlockResult, IntBuffer messageChunk) {
        Words currentBlockResult = previousBlockResult;

        for (int j = 0; j < BLOCK_SIZE; j++) {
            int round = j / OPERATION_AMOUNT;

            currentBlockResult = applyOperation(round, j, messageChunk, currentBlockResult);
        }

        return currentBlockResult.add(previousBlockResult);
    }

    private byte[] generateResultingBytes(Words words) {
        ByteBuffer md5 = ByteBuffer.allocate(HASH_SIZE).order(ByteOrder.LITTLE_ENDIAN);

        md5.putInt(words.getA());
        md5.putInt(words.getB());
        md5.putInt(words.getC());
        md5.putInt(words.getD());

        return md5.array();
    }

    private ByteBuffer getPaddedByteBuffer(byte[] messageBytes) {
        int messageLength = messageBytes.length;

        int blocks = ((messageLength + Byte.SIZE) / BLOCK_SIZE) + 1;
        int resultingLength = blocks * BLOCK_SIZE;

        ByteBuffer byteBuffer = ByteBuffer.allocate(resultingLength).order(ByteOrder.LITTLE_ENDIAN);
        byteBuffer.put(messageBytes);
        byteBuffer.put(FIRST_PADDING_SYMBOL);

        long messageLenBits = (long) messageBytes.length * Byte.SIZE;
        byteBuffer.putLong(byteBuffer.capacity() - Byte.SIZE, messageLenBits);

        byteBuffer.rewind();
        return byteBuffer;
    }

    private Words applyOperation(int round, int operationIndex, IntBuffer messageBuffer, Words previousOperationResult) {
        int functionValue;
        int bufferIndex;

        int a = previousOperationResult.getA();
        int b = previousOperationResult.getB();
        int c = previousOperationResult.getC();
        int d = previousOperationResult.getD();

        if (round == 0) {
            functionValue = (b & c) | (~b & d);
            bufferIndex = operationIndex;
        } else if (round == 1) {
            functionValue = (b & d) | (c & ~d);
            bufferIndex = (operationIndex * 5 + 1) % OPERATION_AMOUNT;
        } else if (round == 2) {
            functionValue = b ^ c ^ d;
            bufferIndex = (operationIndex * 3 + 5) % OPERATION_AMOUNT;
        } else {
            functionValue = c ^ (b | ~d);
            bufferIndex = (operationIndex * 7) % OPERATION_AMOUNT;
        }

        int operationStep = b + Integer.rotateLeft(a + functionValue + messageBuffer.get(bufferIndex) + T[operationIndex], getShift(round, operationIndex));

        return new Words(d, operationStep, b, c);
    }

    private int getShift(int roundNumber, int iteration) {
        return SHIFTS[roundNumber][iteration % ROUND_AMOUNT];
    }

    private int[] initT() {
        int[] t = new int[ROUND_AMOUNT * OPERATION_AMOUNT];
        for (int i = 0; i < t.length; i++) {
            t[i] = (int) (long) Math.floor(Math.pow(2, 32) * Math.abs(Math.sin(i + 1)));
        }

        return t;
    }

    private String toHexString(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte value : b) {
            sb.append(String.format("%02x", value & 0xFF));
        }

        return sb.toString();
    }
}
