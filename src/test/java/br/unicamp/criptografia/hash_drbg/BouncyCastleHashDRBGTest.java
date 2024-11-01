package br.unicamp.criptografia.hash_drbg;

import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;

import static br.unicamp.criptografia.hash_drbg.CryptoHelper.generatePersonalizationString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;

public class BouncyCastleHashDRBGTest {
    BouncyCastleHashDRBG bouncyCastle;
    String bouncyCastleRandomBits;

    @Before
    public void before() {
        String nonce = CryptoHelper.generateNonce(128);
        String personalizationString = generatePersonalizationString();
        bouncyCastle = new BouncyCastleHashDRBG(nonce, personalizationString);
//        BouncyCastleHashDRBG bouncyCastle = new BouncyCastleHashDRBG("nonce", "personalizationString");
        byte[] randomBytes = bouncyCastle.generateRandomBytes();
        bouncyCastleRandomBits = CryptoHelper.bytesToBits(randomBytes);
    }

    @Test
    public void frequencyMonobitTest_NIST_Example() {
        String randomBits = "11001001000011111101101010100010" +
                "0010000101101000110000100011010011" +
                "0001001100011001100010100010111000";
        double pValue = getFrequencyMonobitPValue(randomBits);

        assertThat(pValue, greaterThanOrEqualTo(0.01));
    }

    @Test
    public void frequencyMonobitTest_Bouncy_Castle() {
        double pValue = getFrequencyMonobitPValue(bouncyCastleRandomBits);

        assertThat(pValue, greaterThanOrEqualTo(0.01));
    }

    /**
     * As "[800-22] 2.1.5", the pValue should be greater than or equal to 0.01 to the randomBits being random
     * @param randomBits to be tested
     * @return pValue to be validated
     */
    private double getFrequencyMonobitPValue(String randomBits) {
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
    public void frequencyTestWithinABlock_NIST_Example() {
        blockFrequency("0110011010", 3);
    }

    private void blockFrequency(String randomBits, int lengthOfEachBlock) {
        // [800-22] 2.2.4 (1)
        int lengthOfTheBitString = randomBits.length();
        int truncatedBlocksLength = lengthOfTheBitString / lengthOfEachBlock;
        ArrayList<String> blocks = new ArrayList<>(truncatedBlocksLength);

        int blockCount = 1;
        StringBuilder currentBlock = new StringBuilder();
        for (int bitIndex = 0; bitIndex < lengthOfTheBitString; bitIndex++) {

            char currentBit = randomBits.charAt(bitIndex);
            currentBlock.append(currentBit);

            if (blockCount == truncatedBlocksLength) {
                blocks.add(String.valueOf(currentBlock));
                blockCount = 1;
                currentBlock = new StringBuilder();
            } else {
                blockCount++;
            }
        }

        System.out.println(blocks);

        // [800-22] 2.2.4 (2)

    }
}