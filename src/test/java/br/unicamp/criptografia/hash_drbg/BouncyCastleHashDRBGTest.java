package br.unicamp.criptografia.hash_drbg;

import org.apache.commons.math3.special.Erf;
import org.apache.commons.math3.special.Gamma;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Vector;

import static br.unicamp.criptografia.hash_drbg.CryptoHelper.generatePersonalizationString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.junit.Assert.assertFalse;

public class BouncyCastleHashDRBGTest {
    private static final Double BASE_P_VALUE = 0.01;
    private static final String NIST_EXAMPLE_RANDOM_100_BITS = "11001001000011111101101010100010001000010110100" +
            "01100001000110100110001001100011001100010100010111000";
    private static final String NIST_EXAMPLE_RANDOM_128_BITS = "11001100000101010110110001001100111000000000001" +
            "001001101010100010001001111010110100000001101011111001100111001101101100010110010";
    private static final String NIST_EXAMPLE_RANDOM_20_BITS = "01011001001010101101";
    private static final String NIST_EXAMPLE_RANDOM_10_BITS = "1001101011";
    private static BouncyCastleHashDRBG bouncyCastle;
    private static byte[] randomBytes;
    private static String bouncyCastleRandomBits;

    @BeforeClass
    public static void before() {
        String nonce = CryptoHelper.generateNonce(128);
        String personalizationString = generatePersonalizationString();
        bouncyCastle = new BouncyCastleHashDRBG(nonce, personalizationString);
        randomBytes = bouncyCastle.generateDefaultRandomBytes();
        bouncyCastleRandomBits = CryptoHelper.bytesToBits(randomBytes);
    }

    @Test
    public void frequencyMonobitTest_NIST_Example() {
        double pValue = getFrequencyMonobitPValue(NIST_EXAMPLE_RANDOM_100_BITS);
        nistPValueAssertion(pValue);
    }

    @Test
    public void frequencyMonobitTest_Bouncy_Castle() {
        double pValue = getFrequencyMonobitPValue(bouncyCastleRandomBits);
        nistPValueAssertion(pValue);
    }

    /**
     * As "2.1.5", the pValue should be greater than or equal to P_VALUE to the randomBits being random
     *
     * @param randomBits to be tested
     * @return pValue to be validated
     */
    private double getFrequencyMonobitPValue(String randomBits) {
        int length = randomBits.length();
        int absoluteSum = 0;
        for (int i = 0; i < length; i++) {
            int bit = Integer.parseInt(String.valueOf(randomBits.charAt(i)));
            if (bit == 1) {
                absoluteSum++;
            } else {
                absoluteSum--;
            }
        }
        double referenceDistribution = Math.abs(absoluteSum) / Math.sqrt(length);
        return Erf.erfc(referenceDistribution / Math.sqrt(2));
    }

    @Test
    public void frequencyTestWithinABlock_NIST_Example() {
        double pValue = getBlockFrequencyPValue(NIST_EXAMPLE_RANDOM_100_BITS, 10);
        nistPValueAssertion(pValue);
    }

    @Test
    public void frequencyTestWithinABlock_Bouncy_Castle() {
        double pValue = getBlockFrequencyPValue(bouncyCastleRandomBits, bouncyCastle.getBlockSize());
        nistPValueAssertion(pValue);
    }

    private double getBlockFrequencyPValue(String randomBits, int lengthOfEachBlock) {
        // 2.2.4 (1)
        int lengthOfTheBitString = randomBits.length();
        int nonOverlappingBlocks = getNonOverlappingBlocks(lengthOfTheBitString, lengthOfEachBlock);

        // 2.2.4 (2)
        ArrayList<Double> proportionOfOnes = new ArrayList<>();
        double sum;
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

        // 2.2.4 (3)
        double chiSquareStatisticObserved;
        sum = 0.0;
        for (int i = 0; i < nonOverlappingBlocks; i++) {
            sum += Math.pow(proportionOfOnes.get(i) - 0.5, 2);
        }

        chiSquareStatisticObserved = 4 * lengthOfEachBlock * sum;


        // 2.2.4 (4)
        return Gamma.regularizedGammaQ((double) nonOverlappingBlocks / 2, chiSquareStatisticObserved / 2);
    }

    @Test
    public void runsTest_NIST_Example_10_Bits() {
        double pValue = getRunsTestPValue(NIST_EXAMPLE_RANDOM_10_BITS);
        nistPValueAssertion(pValue);
    }

    @Test
    public void runsTest_NIST_Example_100_Bits() {
        double pValue = getRunsTestPValue(NIST_EXAMPLE_RANDOM_100_BITS);
        nistPValueAssertion(pValue);
    }

    @Test
    public void runsTest_Bouncy_Castle() {
        double pValue = getRunsTestPValue(bouncyCastleRandomBits);
        nistPValueAssertion(pValue);
    }

    private double getRunsTestPValue(String randomBits) {
        // 2.3.4 (1)
        int lengthOfTheBitString = randomBits.length();
        double preTestProportion;
        double sum = 0.0;
        for (int j = 0; j < lengthOfTheBitString; j++) {
            int bit = Integer.parseInt(String.valueOf(randomBits.charAt(j)));
            sum += bit;
        }
        preTestProportion = sum / lengthOfTheBitString;

        // 2.3.4 (2)
        double frequencyTestPrerequisite = 2 / Math.sqrt(lengthOfTheBitString);
        assertThat(frequencyTestPrerequisite, greaterThanOrEqualTo(Math.abs(preTestProportion - 0.5)));

        // 2.3.4 (3)
        int testStatisticValue = 0;
        for (int k = 1; k < lengthOfTheBitString - 1; k++) {
            int r = r(randomBits, k);
            testStatisticValue += r;
        }
        testStatisticValue++;

        // 2.3.4 (4)
        double divisor = Math.abs(testStatisticValue - 2 * lengthOfTheBitString
                * preTestProportion * (1 - preTestProportion));
        double dividend = 2 * Math.sqrt(2 * lengthOfTheBitString) * preTestProportion
                * (1 - preTestProportion);
        return Erf.erfc(divisor / dividend);
    }

    private int r(String randomBits, int k) {
        int currentBit = Integer.parseInt(String.valueOf(randomBits.charAt(k)));
        int nextBit;
        int ret;
        nextBit = Integer.parseInt(String.valueOf(randomBits.charAt(k + 1)));
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
        nistPValueAssertion(pValue);
    }

    @Test
    public void testForTheLongestRunOfOnesInABlock_NIST_Example() {
        double pValue = getTestForTheLongestRunOfOnesInABlockPValue(NIST_EXAMPLE_RANDOM_128_BITS, 8);
        nistPValueAssertion(pValue);
    }

    private double getTestForTheLongestRunOfOnesInABlockPValue(String randomBits, int lengthOfEachBlock) {
        int lengthOfBitString = randomBits.length();

        Integer[][] preSetMinimumLengthOfBitStringByLengthOfEachBlock = {
                {128, 8},
                {6272, 128},
                {750000, (int) Math.pow(10, 4)}
        };

        for (Integer[] preSet : preSetMinimumLengthOfBitStringByLengthOfEachBlock) {
            int maxNumberOfBitsSegment = preSet[0];
            if (lengthOfBitString < maxNumberOfBitsSegment) {
                int maxBlockSizeSegment = preSet[1];
                if (lengthOfEachBlock > maxBlockSizeSegment) {
                    throw new InvalidParameterException("Random bits has a wrong block size: (lengthOfBitString) "
                            + lengthOfBitString + "; (lengthOfEachBlock) " + lengthOfEachBlock);
                }
            }
        }


        // 2.4.4 (1)
        int nonOverlappingBlocks = getNonOverlappingBlocks(lengthOfBitString, lengthOfEachBlock);
        ArrayList<String> blocks = getBlocks(randomBits, nonOverlappingBlocks, lengthOfEachBlock);

        ArrayList<Integer> maxRuns = new ArrayList<>(lengthOfEachBlock);
        for (String block : blocks) {
            int maxRun = 0;
            int currentRun = 0;
            for (int i = 0; i < block.length(); i++) {
                char bit = block.charAt(i);
                if (bit == '1') {
                    currentRun++;
                }
                if (currentRun > maxRun) {
                    maxRun = currentRun;
                }
                if (bit == '0') {
                    currentRun = 0;
                }
            }
            maxRuns.add(maxRun);
        }

        Integer[][] preSetMKN = {
                {8, 3, 16},
                {128, 5, 49},
                {(int) Math.pow(10, 4), 6, 75}
        };

        int sizeOfFrequencies = getColumnFromFirstValue(preSetMKN, lengthOfEachBlock, 1);
        Vector<Integer> frequencies = new Vector<>(sizeOfFrequencies);

        for (int i = 1; i <= sizeOfFrequencies + 1; i++) {
            int finalI = i;
            int currentMaxRun = (int) maxRuns.stream().filter(integer -> integer == finalI).count();
            frequencies.add(currentMaxRun);
        }

        double chiSquareStatisticObserved = 0.0;
        for (int i = 0; i <= sizeOfFrequencies; i++) {
            int currentFrequency = frequencies.get(i);
            int n = getColumnFromFirstValue(preSetMKN, lengthOfEachBlock, 2);
            double[] preSetFrequencyByProbability = getProbabilitiesFromKAndM(sizeOfFrequencies, lengthOfEachBlock);
            double probability = preSetFrequencyByProbability[i];
            double nByProbability = n * probability;
            double divisor = Math.pow(currentFrequency - nByProbability, 2);
            chiSquareStatisticObserved += divisor / nByProbability;
        }

        // 2.4.4 (4)
        return Gamma.regularizedGammaQ((double) sizeOfFrequencies / 2, chiSquareStatisticObserved / 2);
    }

    private Integer getColumnFromFirstValue(Integer[][] matrix, int target, int column) {
        for (Integer[] row : matrix) {
            if (row[0] == target) {
                return row[column];
            }
        }
        throw new InvalidParameterException("Invalid block size");
    }

    /**
     * pre-defined probabilities from NIST 800-22A
     *
     * @param k pre-set
     * @param m block size
     * @return the class by probability, where the first needs to be compared as <= and the last as >=
     */
    private double[] getProbabilitiesFromKAndM(int k, int m) {
        if (k == 3 && m == 8) {
            return new double[]{
                    0.2148,
                    0.3672,
                    0.2305,
                    0.1875
            };
        }
        if (k == 5 && m == 128) {
            return new double[]{
                    0.1174,
                    0.2430,
                    0.2493,
                    0.1752,
                    0.1027,
                    0.1124
            };
        }
        if (k == 5 && m == 512) {
            return new double[]{
                    0.1170,
                    0.2460,
                    0.2523,
                    0.1755,
                    0.1027,
                    0.1124
            };
        }
        if (k == 5 && m == 1000) {
            return new double[]{
                    0.1307,
                    0.2437,
                    0.2452,
                    0.1714,
                    0.1002,
                    0.1088,
            };
        }
        if (k == 6 && m == 10000) {
            return new double[]{
                    0.0882,
                    0.2092,
                    0.2483,
                    0.1933,
                    0.1208,
                    0.0675,
                    0.0727
            };
        }
        return new double[]{};
    }

    @Test
    public void binaryMatrixRankTest_Bouncy_Castle() {
        double pValue = getBinaryMatrixRankTestPValue(bouncyCastleRandomBits, false);
        nistPValueAssertion(pValue);
    }


    @Test
    public void binaryMatrixRankTest_NIST_Example() {
        double pValue = getBinaryMatrixRankTestPValue(NIST_EXAMPLE_RANDOM_20_BITS, true);
        nistPValueAssertion(pValue);
    }

    private double getBinaryMatrixRankTestPValue(String randomBits, boolean isANistExample) {
        int lengthOfTheBitString = randomBits.length();
        int numberOfMatrixRowsM, numberOfMatrixColumnsQ;
        numberOfMatrixRowsM = numberOfMatrixColumnsQ = 32;
        int minimumLength = 38 * numberOfMatrixRowsM * numberOfMatrixColumnsQ;

        if (isANistExample && lengthOfTheBitString < minimumLength) {
            numberOfMatrixRowsM = numberOfMatrixColumnsQ = 3;
        } else if (lengthOfTheBitString < minimumLength) {
            throw new InvalidParameterException("lengthOfTheBitString is less than the minimum recommended: "
                    + minimumLength);
        }

        // 2.5.4 (1)
        int disjointBlocksN = Math.abs(lengthOfTheBitString / (numberOfMatrixRowsM * numberOfMatrixColumnsQ));

        // 2.5.4 (2)
        int[] ranks = getFullDeficientAndLowerRanks(randomBits, numberOfMatrixRowsM,
                numberOfMatrixColumnsQ, disjointBlocksN);
        int fullRank = ranks[0];
        int deficientRankCount = ranks[1];
        int lowerRankCount = ranks[2];

        // 2.5.4 (4)
        double pFullRank = 0.2888;
        double pDeficientRank = 0.5776;
        double pLowerRank = 0.1336;

        double chiSquareStatisticObserved =
                Math.pow(fullRank - disjointBlocksN * pFullRank, 2)
                        / (disjointBlocksN * pFullRank) +
                Math.pow(deficientRankCount - disjointBlocksN * pDeficientRank, 2)
                        / (disjointBlocksN * pDeficientRank) +
                Math.pow(lowerRankCount - disjointBlocksN * pLowerRank, 2)
                        / disjointBlocksN * pLowerRank;

        // 2.5.4 (5)
        return Math.pow(EulerNumber.getWith6Digits(), (chiSquareStatisticObserved / 2) * (-1));
    }

    public static int[] getFullDeficientAndLowerRanks(String sequence, int rowsM, int rowsQ, int disjointBlocksN) {
        int fullRankCount = 0;
        int deficientRankCount = 0;
        int lowerRankCount = 0;

        for (int block = 0; block < disjointBlocksN; block++) {
            int[][] matrix = getSubMatrix(sequence, block, rowsM, rowsQ);
            int rank = calculateBinaryRank(matrix, rowsM, rowsQ);

            if (rank == rowsM) {
                fullRankCount++;
            } else if (rank == rowsM - 1) {
                deficientRankCount++;
            } else {
                lowerRankCount++;
            }
        }
        return new int[]{fullRankCount, deficientRankCount, lowerRankCount};
    }

    public static int[][] getSubMatrix(String sequence, int blockIndex, int rowsM, int columnsQ) {
        int[][] matrix = new int[rowsM][columnsQ];
        int start = blockIndex * rowsM * columnsQ;

        for (int i = 0; i < rowsM; i++) {
            for (int j = 0; j < columnsQ; j++) {
                int index = start + i * columnsQ + j;
                matrix[i][j] = Integer.parseInt(String.valueOf(sequence.charAt(index)));
            }
        }
        return matrix;
    }

    /**
     * It calculates the max number of lines or columns linearly independent of the matrix using Gaussian elimination.
     * The rank is, after the appropriate swaps, the number of 1's on the main diagonal.
     *
     * @param matrix  matrix of boolean values
     * @param rows    number of rows
     * @param columns number of columns
     * @return max rank calculated
     */
    public static int calculateBinaryRank(int[][] matrix, int rows, int columns) {
        int rank = 0;

        for (int row = 0; row < rows; row++) {
            if (matrix[row][row] == 0) {
                // searching for an appropriate true pivot element value
                boolean swapped = false;
                for (int i = row + 1; i < rows; i++) {
                    if (matrix[i][row] == 1) {
                        int[] temp = matrix[row];
                        matrix[row] = matrix[i];
                        matrix[i] = temp;
                        swapped = true;
                        break;
                    }
                }
                if (!swapped) {
                    continue;
                }
            }

            for (int i = row + 1; i < rows; i++) {
                if (matrix[i][row] == 1) {
                    for (int j = row; j < columns; j++) {
                        // XOR operation
                        matrix[i][j] = matrix[i][j] ^ matrix[row][j];
                    }
                }
            }
            rank++;
        }
        return rank;
    }

    private int getNonOverlappingBlocks(int lengthOfTheBitString, int lengthOfEachBlock) {
        return lengthOfTheBitString / lengthOfEachBlock;
    }

    private ArrayList<String> getBlocks(String randomBits, int nonOverlappingBlocks, int blockSize) {
        int lengthOfTheBitString = randomBits.length();
        ArrayList<String> blocks = new ArrayList<>(nonOverlappingBlocks);
        int blockCount = 1;
        StringBuilder currentBlock = new StringBuilder();
        for (int bitIndex = 0; bitIndex < lengthOfTheBitString; bitIndex++) {

            char currentBit = randomBits.charAt(bitIndex);
            currentBlock.append(currentBit);

            if (blockCount == blockSize) {
                blocks.add(String.valueOf(currentBlock));
                blockCount = 1;
                currentBlock = new StringBuilder();
            } else {
                blockCount++;
            }
        }
        return blocks;
    }

    private void nistPValueAssertion(double pValue) {
        assertFalse("pValue is not a number", Double.isNaN(pValue));
        assertThat(pValue, greaterThanOrEqualTo(BASE_P_VALUE));
    }

    private void log(String tag, int part, String message) {
        System.out.println("[" + tag + "] (" + part + ") " + message);
    }
}