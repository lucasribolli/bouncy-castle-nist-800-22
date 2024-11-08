package br.unicamp.criptografia.hash_drbg;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.MathContext;
import java.nio.file.Files;
import java.nio.file.Path;

public class EulerNumber {
    public static double getWith6Digits() {
        BigDecimal e = calculateE(20);
        return e.doubleValue();
    }

    public static BigDecimal getVeryLargeBits() {
        String fileName = "src/main/java/br/unicamp/criptografia/hash_drbg/euler_12500_binry_digits.txt";
        Path path = Path.of(fileName);

        // Lê o conteúdo do arquivo para uma string
        String content = null;
        try {
            content = Files.readString(path);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return new BigDecimal(content);
    }

    private static BigDecimal calculateE(int terms) {
        BigDecimal e = BigDecimal.ONE;
        BigDecimal factorial = BigDecimal.ONE;

        for (int i = 1; i < terms; i++) {
            factorial = factorial.multiply(BigDecimal.valueOf(i)); // Calcula o fatorial
            e = e.add(BigDecimal.ONE.divide(factorial, MathContext.DECIMAL128));
        }

        return e;
    }

    private static void readFileContent(String[] args) {

    }
}

