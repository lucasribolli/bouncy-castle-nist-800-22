package br.unicamp.criptografia.hash_drbg;

import org.junit.Test;

import static br.unicamp.criptografia.hash_drbg.CryptoHelper.generatePersonalizationString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;

public class BouncyCastleHashDRBGTest {
    @Test
    public void frequencyMonobitTest_NIST_Example() {
        String randomBits = "11001001000011111101101010100010" +
                "0010000101101000110000100011010011" +
                "0001001100011001100010100010111000";
        double pValue = frequencyMonobitPValue(randomBits);

        assertThat(pValue, greaterThanOrEqualTo(0.01));
    }

    @Test
    public void frequencyMonobitTest_BouncyCastle() {
        String nonce = CryptoHelper.generateNonce(128);
        String personalizationString = generatePersonalizationString();
        BouncyCastleHashDRBG bouncyCastle = new BouncyCastleHashDRBG(nonce, personalizationString);
//        BouncyCastleHashDRBG bouncyCastle = new BouncyCastleHashDRBG("nonce", "personalizationString");
        byte[] randomBytes = bouncyCastle.generateRandomBytes();
        String randomBits = CryptoHelper.bytesToBits(randomBytes);
        double pValue = frequencyMonobitPValue(randomBits);

        assertThat(pValue, greaterThanOrEqualTo(0.01));
    }

    /**
     * As "[800-22] 2.1.5", the pValue should be greater than or equal to 0.01 to the randomBits being random
     * @param randomBits to be tested
     * @return pValue to be validated
     */
    private double frequencyMonobitPValue(String randomBits) {
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
        double referenceDistribution = Math.abs(absoluteSum) / Math.sqrt(length);
        System.out.println("{[800-22] 2.1.4 (2)} Reference Distribution: " + referenceDistribution);


        // [800-22] 2.1.4 (3)
        double pValue = org.apache.commons.math3.special.Erf.erfc(referenceDistribution / Math.sqrt(2));
        System.out.println("{[800-22] 2.1.4 (3)} P-value: " + pValue);

        return pValue;
    }

    @Test
    public void frequencyTestWithinABlock() {

    }
}