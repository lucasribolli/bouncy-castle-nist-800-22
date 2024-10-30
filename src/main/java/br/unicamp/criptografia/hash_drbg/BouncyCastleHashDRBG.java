package br.unicamp.criptografia.hash_drbg;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG;

import java.security.SecureRandom;

public class BouncyCastleHashDRBG {
    private static int SECURITY_STRENGTH_BITS = 256;
    private static int SECURITY_STRENGTH_BYTES = SECURITY_STRENGTH_BITS / 8;

    public byte[] generateRandomBytes() {
        EntropySourceProvider entropySourceProvider = getEntropySourceProvider();

        SHA256Digest digest = new SHA256Digest();
        // TODO set nonce
        byte[] nonce = "nonce".getBytes();
        // TODO set personalization string
        byte[] personalizationString = "personalization".getBytes();

        HashSP800DRBG drbg = new HashSP800DRBG(
                digest,
                SECURITY_STRENGTH_BITS,
                entropySourceProvider.get(SECURITY_STRENGTH_BITS),
                nonce,
                personalizationString
        );

        byte[] randomBytes = new byte[SECURITY_STRENGTH_BYTES];
        int numberOfGeneratedBits = drbg.generate(randomBytes, null, false);

        while (numberOfGeneratedBits == -1) {
            System.out.println("Erro na geração de bytes aleatórios, precisa de um reseed");
            numberOfGeneratedBits = drbg.generate(randomBytes, null, false);
        }

        return randomBytes;
    }

    private static EntropySourceProvider getEntropySourceProvider() {
        SecureRandom secureRandom = new SecureRandom();
        return bitsRequired -> new EntropySource() {
            @Override
            public boolean isPredictionResistant() {
                return true;
            }

            @Override
            public byte[] getEntropy() {
                // ???
                byte[] entropy = new byte[(bitsRequired + 7) / 8];
                secureRandom.nextBytes(entropy);
                return entropy;
            }

            @Override
            public int entropySize() {
                return bitsRequired;
            }
        };
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
}
