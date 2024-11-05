package br.unicamp.criptografia.hash_drbg;

import org.apache.commons.math3.special.Erf;
import org.apache.commons.math3.special.Gamma;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.InvalidParameterException;
import java.util.ArrayList;

import static br.unicamp.criptografia.hash_drbg.CryptoHelper.generatePersonalizationString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;

public class BouncyCastleHashDRBGTest {
    private static final Double BASE_P_VALUE = 0.01;
    private static final String NIST_EXAMPLE_RANDOM_BITS_100_BITS = "11001001000011111101101010100010001000010110100" +
            "01100001000110100110001001100011001100010100010111000";
    private static final String NIST_EXAMPLE_RANDOM_BITS_128_BITS = "11001100000101010110110001001100111000000000001" +
            "001001101010100010001001111010110100000001101011111001100111001101101100010110010";
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
        double pValue = getFrequencyMonobitPValue(NIST_EXAMPLE_RANDOM_BITS_100_BITS);

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
        double pValue = getBlockFrequencyPValue(NIST_EXAMPLE_RANDOM_BITS_100_BITS, 10);
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
        int nonOverlappingBlocks = getNonOverlappingBlocks(lengthOfTheBitString, lengthOfEachBlock);
        ArrayList<String> blocks = getBlocks(randomBits, nonOverlappingBlocks);

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
        double pValue = getRunsTestPValue(NIST_EXAMPLE_RANDOM_BITS_100_BITS);
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

    @Test
    public void testForTheLongestRunOfOnesInABlock_Bouncy_Castle() {
        double pValue = getTestForTheLongestRunOfOnesInABlockPValue(bouncyCastleRandomBits, bouncyCastle.getBlockSize());
        assertThat(pValue, greaterThanOrEqualTo(BASE_P_VALUE));
    }

    @Test
    public void testForTheLongestRunOfOnesInABlock_NIST_Example() {
        double pValue = getTestForTheLongestRunOfOnesInABlockPValue(NIST_EXAMPLE_RANDOM_BITS_128_BITS, 8);
        assertThat(pValue, greaterThanOrEqualTo(BASE_P_VALUE));
    }

    private double getTestForTheLongestRunOfOnesInABlockPValue(String randomBits, int lengthOfEachBlock) {
        int lengthOfBitString = randomBits.length();

        Integer[][] preSetMinimumLengthOfBitStringByLengthOfEachBlock = {
                {128, 8},
                {6272, 128},
                {750000, (int) Math.pow(10, 4)}
        };

        for(Integer[] preSet : preSetMinimumLengthOfBitStringByLengthOfEachBlock) {
            int maxNumberOfBitsSegment = preSet[0];
            if (lengthOfBitString < maxNumberOfBitsSegment) {
                int maxBlockSizeSegment = preSet[1];
                if (lengthOfEachBlock >= maxBlockSizeSegment) {
                    throw new InvalidParameterException("Random bits has a wrong block size: (lengthOfBitString) "
                            + lengthOfBitString + "; (lengthOfEachBlock) " + lengthOfEachBlock);
                }
            }
        }


        // 2.4.4 (1)
        int nonOverlappingBlocks = getNonOverlappingBlocks(lengthOfBitString, lengthOfEachBlock);
        ArrayList<String> blocks = getBlocks(randomBits, nonOverlappingBlocks);

        // 2.4.4 (2)
//        int[][] frequenciesOfTheLongestRunsOfOnes = {
//                {1, 4, 3, 4},
//                {4, 5, 6, 7, 8, 9},
//                {10, 11, 12, 13, 14, 15, 16}
//        };
        Integer[][] frequenciesOfTheLongestRunsOfOnes = {
            //  M=8, M=128, M=10⁴
                {1, 4, 10},
                {2, 5, 11},
                {3, 6, 12},
                {4, 7, 13},
                {null, 8, 14},
                {null, 9, 15},
                {null, null, 16}
        };


        // 2.4.4 (3)
        Integer[][] preSetMKN = {
                {8, 3, 16},
                {128, 5, 49},
                {(int) Math.pow(10, 4), 6, 75}
        };


        return testLongestRunOfOnes(randomBits, lengthOfEachBlock, nonOverlappingBlocks);


//        return 0.0;
    }


    public double testLongestRunOfOnes(String binarySequence, int blockSize, int numberOfBlocks) {
        // Define expected probabilities based on NIST's test
        int[] expectedRuns = {1, 2, 3, 4}; // Adjust as needed for larger blocks
        double[] probabilities = {0.2148, 0.3672, 0.2305, 0.1875};

        // Count occurrences of the longest runs
        int[] observedRuns = new int[expectedRuns.length];
        for (int i = 0; i < numberOfBlocks; i++) {
            String block = binarySequence.substring(i * blockSize, (i + 1) * blockSize);
            int longestRun = longestRunOfOnes(block);

            // Map the longest run to the expected categories
            if (longestRun >= 1 && longestRun <= 4) {
                observedRuns[longestRun - 1]++;
            } else if (longestRun > 4) {
                observedRuns[3]++;
            }
        }

        // Perform chi-squared test
        double chiSquareStatisticObserved = 0.0;
        for (int i = 0; i < expectedRuns.length; i++) {
            double expectedCount = probabilities[i] * numberOfBlocks;
            chiSquareStatisticObserved += Math.pow(observedRuns[i] - expectedCount, 2) / expectedCount;
        }

        return chiSquareStatisticObserved;
    }

    // Function to find the longest run of 1's in a block
    public static int longestRunOfOnes(String block) {
        int maxRun = 0;
        int currentRun = 0;

        for (char bit : block.toCharArray()) {
            if (bit == '1') {
                currentRun++;
                if (currentRun > maxRun) {
                    maxRun = currentRun;
                }
            } else {
                currentRun = 0;
            }
        }
        return maxRun;
    }

    private int getNonOverlappingBlocks(int lengthOfTheBitString, int lengthOfEachBlock) {
        return lengthOfTheBitString / lengthOfEachBlock;
    }

    private ArrayList<String> getBlocks(String randomBits, int nonOverlappingBlocks) {
        int lengthOfTheBitString = randomBits.length();
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
        return blocks;
    }

    private void log(String tag, int part, String message) {
        System.out.println("[" + tag + "] (" + part + ") " + message);
    }
}