package br.unicamp.criptografia.hash_drbg;

import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

public class BouncyCastleHashDRBGTest {
    String randomBits;

    @Before
    public void prepare() {
        byte[] randomBytes = new BouncyCastleHashDRBG().generateRandomBytes();
        randomBits = BouncyCastleHashDRBG.bytesToBits(randomBytes);
    }

    @Test
    public void frequencyMonobitTest() {
        // [800-22] 2.1.4 (1)
        int length = randomBits.length();
        System.out.println("{[800-22] 2.1.4 (1)} length (n): " + length);

        int absoluteSum = 0;

        for (int i = 0; i < length; i++) {
            int bit = Integer.parseInt(String.valueOf(randomBits.charAt(i)));
            if (bit == 1) {
                absoluteSum++;
            } else {
                absoluteSum--;
            }
        }
        System.out.println("{[800-22] 2.1.4 (1)} Absolute sum: " + absoluteSum);


        // [800-22] 2.1.4 (2)
        double referenceDistribution = absoluteSum / Math.sqrt(length);
        System.out.println("{[800-22] 2.1.4 (2)} Reference Distribution: " + referenceDistribution);


        // [800-22] 2.1.4 (3)
        double pValue = org.apache.commons.math3.special.Erf.erfc(referenceDistribution / Math.sqrt(2));
        System.out.println("{[800-22] 2.1.4 (3)} P-value: " + pValue);

        Assertions.assertEquals(1, 1);
    }

    private void frequency(String bits) {

    }
}