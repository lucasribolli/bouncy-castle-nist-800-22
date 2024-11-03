package br.unicamp.criptografia.hash_drbg;

import org.apache.commons.math3.special.Erf;
import org.apache.commons.math3.special.Gamma;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.ArrayList;

import static br.unicamp.criptografia.hash_drbg.CryptoHelper.generatePersonalizationString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;

// TODO
//  make better logs: title of the method: log(tag, m) -> {2.1.4 (1)}, length: ....
public class BouncyCastleHashDRBGTest {
    private static final Double BASE_P_VALUE = 0.01;
    private static BouncyCastleHashDRBG bouncyCastle;
    private static String bouncyCastleRandomBits;

    @BeforeClass
    public static void before() {
        String nonce = CryptoHelper.generateNonce(128);
        String personalizationString = generatePersonalizationString();
        bouncyCastle = new BouncyCastleHashDRBG(nonce, personalizationString);
        byte[] randomBytes = bouncyCastle.generateRandomBytes();
        bouncyCastleRandomBits = CryptoHelper.bytesToBits(randomBytes);
    }

    @Test
    public void frequencyMonobitTest_NIST_Example() {
        String randomBits = "11001001000011111101101010100010001000010110100011000010001101001" +
                "10001001100011001100010100010111000";
        double pValue = getFrequencyMonobitPValue(randomBits);

        assertThat(pValue, greaterThanOrEqualTo(BASE_P_VALUE));
    }

    @Test
    public void frequencyMonobitTest_Bouncy_Castle() {
        double pValue = getFrequencyMonobitPValue(bouncyCastleRandomBits);

        assertThat(pValue, greaterThanOrEqualTo(BASE_P_VALUE));
    }

    /**
     * As "2.1.5", the pValue should be greater than or equal to P_VALUE to the randomBits being random
     *
     * @param randomBits to be tested
     * @return pValue to be validated
     */
    private double getFrequencyMonobitPValue(String randomBits) {
        String logTag = "2.1.4";
        // 2.1.4 (1)
        int length = randomBits.length();
        log(logTag, 1, "length (n): " + length);

        int absoluteSum = 0;

        for (int i = 0; i < length; i++) {
            int bit = Integer.parseInt(String.valueOf(randomBits.charAt(i)));
            if (bit == 1) {
                absoluteSum++;
            } else {
                absoluteSum--;
            }
        }
        log(logTag, 1, "Absolute sum: " + absoluteSum);


        // 2.1.4 (2)
        double referenceDistribution = Math.abs(absoluteSum) / Math.sqrt(length);
        log(logTag, 2, "Reference Distribution: " + referenceDistribution);


        // 2.1.4 (3)
        double pValue = Erf.erfc(referenceDistribution / Math.sqrt(2));
        log(logTag, 3, "P-value: " + pValue);

        return pValue;
    }

    @Test
    public void frequencyTestWithinABlock_NIST_Example() {
        double pValue = getBlockFrequencyPValue("1100100100001111110110101010001000100001011010" +
                "001100001000110100110001001100011001100010100010111000", 10);
        assertThat(pValue, greaterThanOrEqualTo(BASE_P_VALUE));
    }

    @Test
    public void frequencyTestWithinABlock_Bouncy_Castle() {
        double pValue = getBlockFrequencyPValue(bouncyCastleRandomBits, bouncyCastle.getBlockSize());
        assertThat(pValue, greaterThanOrEqualTo(BASE_P_VALUE));
    }

    private double getBlockFrequencyPValue(String randomBits, int lengthOfEachBlock) {
        String logTag = "2.2.4";

        // 2.2.4 (1)
        int lengthOfTheBitString = randomBits.length();
        int nonOverlappingBlocks = lengthOfTheBitString / lengthOfEachBlock;
        ArrayList<String> blocks = new ArrayList<>(nonOverlappingBlocks);

        int blockCount = 1;
        StringBuilder currentBlock = new StringBuilder();
        for (int bitIndex = 0; bitIndex < lengthOfTheBitString; bitIndex++) {

            char currentBit = randomBits.charAt(bitIndex);
            currentBlock.append(currentBit);

            if (blockCount == nonOverlappingBlocks) {
                blocks.add(String.valueOf(currentBlock));
                blockCount = 1;
                currentBlock = new StringBuilder();
            } else {
                blockCount++;
            }
        }

        log(logTag, 1, "blocks: " + blocks);


        // 2.2.4 (2)
        ArrayList<Double> proportionOfOnes = new ArrayList<>();
        double sum;
        // 1 <= i <= N
        for (int i = 1; i <= nonOverlappingBlocks; i++) {
            sum = 0;
            for (int j = 0; j < lengthOfEachBlock; j++) {
                int positionOfBit = (i - 1) * lengthOfEachBlock + j;
                String bitString = String.valueOf(randomBits.charAt(positionOfBit));
                sum += Integer.parseInt(bitString);
            }

            Double proportionOfOne = (sum / lengthOfEachBlock);
            proportionOfOnes.add(proportionOfOne);
        }

        log(logTag, 2, "proportionOfOnes: " + proportionOfOnes);


        // 2.2.4 (3)
        double chiSquareStatisticObserved = 0.0;
        sum = 0.0;
        for (int i = 0; i < nonOverlappingBlocks; i++) {
            sum += Math.pow(proportionOfOnes.get(i) - 0.5, 2);
        }

        chiSquareStatisticObserved = 4 * lengthOfEachBlock * sum;

        log(logTag, 3, "chiSquareStatisticObserved: " + chiSquareStatisticObserved);


        // 2.2.4 (4)
        // igamc: Complementary Incomplete Gamma Function
        double pValue = Gamma.regularizedGammaQ((double) nonOverlappingBlocks / 2, chiSquareStatisticObserved / 2);
        log(logTag, 4, "pValue: " + pValue);

        return pValue;
    }

    @Test
    public void runsTest_NIST_Example() {
        double pValue = getRunsTestPValue("11001001000011111101101010100010001000010110100011" +
                "00001000110100110001001100011001100010100010111000");
        assertThat(pValue, greaterThanOrEqualTo(BASE_P_VALUE));
    }

    @Test
    public void runsTest_Bouncy_Castle() {
        double pValue = getRunsTestPValue(bouncyCastleRandomBits);
        assertThat(pValue, greaterThanOrEqualTo(BASE_P_VALUE));
    }

    private double getRunsTestPValue(String randomBits) {
        String logTag = "2.3.4";

        // 2.3.4 (1)
        int lengthOfTheBitString = randomBits.length();
        double preTestProportion = 0.0;
        double sum = 0.0;
        for (int j = 0; j < lengthOfTheBitString; j++) {
            int bit = Integer.parseInt(String.valueOf(randomBits.charAt(j)));
            sum += bit;
        }
        preTestProportion = sum / lengthOfTheBitString;
        log(logTag, 1, "preTestProportion: " + preTestProportion);


        // 2.3.4 (2)
        // Frequency monobit test should be successful


        // 2.3.4 (3)
        int testStatisticValue = 0;
        for (int k = 1; k <= lengthOfTheBitString - 1; k++) {
            int r = r(randomBits, k);
            testStatisticValue += r;
        }
        testStatisticValue++;

        log(logTag, 3, "testStatisticValue: " + testStatisticValue);


        // 2.3.4 (4)
        double divisor = Math.abs(testStatisticValue - 2 * lengthOfTheBitString * preTestProportion * (1 - preTestProportion));
        double dividend = 2 * Math.sqrt(2 * lengthOfTheBitString) * preTestProportion * (1 - preTestProportion);
        double pValue = Erf.erfc(divisor / dividend);
        log(logTag, 3, "pValue: " + pValue);

        return pValue;
    }

    private int r(String randomBits, int k) {
        int currentBit = Integer.parseInt(String.valueOf(randomBits.charAt(k)));
        int nextBit = -1;
        int ret;
        try {
            nextBit = Integer.parseInt(String.valueOf(randomBits.charAt(k + 1)));
        } catch (IndexOutOfBoundsException _) {
        }
        if (currentBit == nextBit) {
            ret = 0;
        } else {
            ret = 1;
        }
        return ret;
    }

    private void log(String tag, int part, String message) {
        System.out.println("[" + tag + "] (" + part + ") " + message);
    }
}