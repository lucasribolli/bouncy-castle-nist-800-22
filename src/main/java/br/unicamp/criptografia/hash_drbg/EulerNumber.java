package br.unicamp.criptografia.hash_drbg;

import java.math.BigDecimal;
import java.math.MathContext;

public class EulerNumber {
    public static double getWith6Digits() {
        BigDecimal e = calculateE(20);
        return e.doubleValue();
    }

    private static BigDecimal calculateE(int terms) {
        BigDecimal e = BigDecimal.ONE;
        BigDecimal factorial = BigDecimal.ONE;

        for (int i = 1; i < terms; i++) {
            factorial = factorial.multiply(BigDecimal.valueOf(i));
            e = e.add(BigDecimal.ONE.divide(factorial, MathContext.DECIMAL128));
        }

        return e;
    }
}

