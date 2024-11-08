package br.unicamp.criptografia.hash_drbg;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG;

import java.security.SecureRandom;

public class BouncyCastleHashDRBG {
    private static final int SECURITY_STRENGTH_BITS = 256;
    private static final int SECURITY_STRENGTH_BYTES = SECURITY_STRENGTH_BITS / 8;
    private final String mNonce;
    private final String mPersonalizationString;
    private HashSP800DRBG drbg;

    public BouncyCastleHashDRBG(String nonce, String personalizationString) {
        mNonce = nonce;
        mPersonalizationString = personalizationString;
    }

    public byte[] generateDefaultRandomBytes() {
        return generate(SECURITY_STRENGTH_BYTES);
    }

    public byte[] generateRandomBytesFromSecurityStrengthBits(int securityStrengthBits) {
        return generate(securityStrengthBits / 8);
    }

    private byte[] generate(int securityStrengthBytes) {
        EntropySourceProvider entropySourceProvider = getEntropySourceProvider();

        SHA256Digest digest = new SHA256Digest();
        byte[] nonce = mNonce.getBytes();
        byte[] personalizationString = mPersonalizationString.getBytes();

        drbg = new HashSP800DRBG(
                digest,
                SECURITY_STRENGTH_BITS,
                entropySourceProvider.get(SECURITY_STRENGTH_BITS),
                nonce,
                personalizationString
        );

        byte[] randomBytes = new byte[securityStrengthBytes];
        boolean predictionResistant = true;
        int numberOfGeneratedBits = drbg.generate(randomBytes, null, predictionResistant);

        while (numberOfGeneratedBits == -1) {
            System.out.println("Erro na geração de bytes aleatórios, precisa de um reseed");
            numberOfGeneratedBits = drbg.generate(randomBytes, null, predictionResistant);
        }

        return randomBytes;
    }

    public int getBlockSize() {
        return drbg.getBlockSize();
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
}
