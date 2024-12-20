package br.unicamp.criptografia.hash_drbg;

import java.security.SecureRandom;
import java.util.UUID;

public class CryptoHelper {
    public static String generateNonce(int length) {
        SecureRandom secureRandom = new SecureRandom();
        long timestamp = System.currentTimeMillis();
        byte[] randomBytes = new byte[length];
        secureRandom.nextBytes(randomBytes);
        byte[] timestampBytes = longToBytes(timestamp);
        byte[] nonceBytes = new byte[length + timestampBytes.length];
        System.arraycopy(timestampBytes, 0, nonceBytes, 0, timestampBytes.length);
        System.arraycopy(randomBytes, 0, nonceBytes, timestampBytes.length, length);
        StringBuilder hexString = new StringBuilder();
        for (byte b : nonceBytes) {
            hexString.append(String.format("%02X", b));
        }

        return hexString.toString();
    }

    private static byte[] longToBytes(long x) {
        byte[] bytes = new byte[8];
        for (int i = 7; i >= 0; i--) {
            bytes[i] = (byte) (x & 0xFF);
            x >>= 8;
        }
        return bytes;
    }

    /**
     * @param byteArray the array to be converted
     * @return 8 block size of bits
     */
    public static String bytesToBits(byte[] byteArray) {
        StringBuilder bits = new StringBuilder();

        for (byte b : byteArray) {
            int noSignalValue = b & 0xFF;
            String binaryString = Integer.toBinaryString(noSignalValue);
            String eightWidthSize = "%8s";
            bits.append(String.format(eightWidthSize, binaryString).replace(' ', '0'));
        }

        return bits.toString();
    }

    public static String generatePersonalizationString() {
        StringBuilder string = new StringBuilder();
        for (int i = 0; i < 5; i++) {
            String randomUUID = UUID.randomUUID().toString();
            string.append(randomUUID);
        }
        return string.toString();
    }
}
