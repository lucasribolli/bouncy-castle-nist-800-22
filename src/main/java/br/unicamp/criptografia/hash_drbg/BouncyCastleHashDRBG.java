package br.unicamp.criptografia.hash_drbg;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG;

import java.security.SecureRandom;

public class BouncyCastleHashDRBG {
    private static final int SECURITY_STRENGTH_BITS = 128;
    private static final int SECURITY_STRENGTH_BYTES = SECURITY_STRENGTH_BITS / 8;
    private final String mNonce;
    private final String mPersonalizationString;
    private HashSP800DRBG hashDrbg;

    public BouncyCastleHashDRBG(String nonce, String personalizationString) {
        mNonce = nonce;
        mPersonalizationString = personalizationString;
    }

    public byte[] generateRandomBytes() {
        EntropySourceProvider entropySourceProvider = getEntropySourceProvider();

        SHA256Digest digest = new SHA256Digest();
        byte[] nonce = mNonce.getBytes();
        byte[] personalizationString = mPersonalizationString.getBytes();

        hashDrbg = new HashSP800DRBG(
                digest,
                SECURITY_STRENGTH_BITS,
                entropySourceProvider.get(SECURITY_STRENGTH_BITS),
                nonce,
                personalizationString
        );

        byte[] randomBytes = new byte[SECURITY_STRENGTH_BYTES];
        int numberOfGeneratedBits = hashDrbg.generate(randomBytes, null, false);

        while (numberOfGeneratedBits == -1) {
            System.out.println("Erro na geração de bytes aleatórios, precisa de um reseed");
            numberOfGeneratedBits = hashDrbg.generate(randomBytes, null, false);
        }

        return randomBytes;
    }

    public int getBlockSize() {
        return hashDrbg.getBlockSize();
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
