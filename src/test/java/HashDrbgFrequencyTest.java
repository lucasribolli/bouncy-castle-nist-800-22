import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.BasicEntropySourceProvider;
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG;

import java.security.SecureRandom;

public class HashDrbgFrequencyTest {

    // Gera uma sequência de bytes aleatórios usando HASH_DRBG
    public static byte[] generateRandomBytes(int numBytes) {
        // Configura a força de segurança para 256 bits e fornece entropia suficiente
        EntropySource entropySource = new BasicEntropySourceProvider(new SecureRandom(), true).get(256);
        HashSP800DRBG drbg = new HashSP800DRBG(new SHA256Digest(), 256, entropySource, null, null);

        byte[] randomBytes = new byte[numBytes];
        drbg.generate(randomBytes, null, false);
        return randomBytes;
    }

    // Converte bytes para uma sequência de bits em String
    public static String bytesToBitString(byte[] bytes) {
        StringBuilder bits = new StringBuilder();
        for (byte b : bytes) {
            bits.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }
        return bits.toString();
    }

    // Implementação do Frequency (Monobit) Test
    public static double frequencyMonobitTest(String bitString) {
        int n = bitString.length();
        int sum = 0;

        // Conta os bits: adiciona 1 para cada '1' e subtrai 1 para cada '0'
        for (char bit : bitString.toCharArray()) {
            sum += (bit == '1') ? 1 : -1;
        }

        // Calcula a estatística de teste s_obs
        double s_obs = Math.abs(sum) / Math.sqrt(n);

        // Calcula o valor-p usando a função de erro complementar (erfc)
        return erfc(s_obs / Math.sqrt(2));
    }

    // Função auxiliar para calcular erfc (função de erro complementar)
    private static double erfc(double x) {
        return 1 - erf(x);
    }

    // Implementação da função de erro (erf)
    private static double erf(double x) {
        double sign = (x < 0) ? -1 : 1;
        x = Math.abs(x);
        double t = 1.0 / (1.0 + 0.5 * x);
        double y = 1 - t * Math.exp(-x * x - 1.26551223 +
                t * (1.00002368 + t * (0.37409196 +
                        t * (0.09678418 + t * (-0.18628806 +
                                t * (0.27886807 + t * (-1.13520398 +
                                        t * (1.48851587 + t * (-0.82215223 +
                                                t * (0.17087277))))))))));
        return sign * y;
    }

    public static void main(String[] args) {
        int numBytes = 1000; // Número de bytes aleatórios a serem gerados
        byte[] randomBytes = generateRandomBytes(numBytes);

        // Converte os bytes gerados para uma sequência de bits
        String bitString = bytesToBitString(randomBytes);

        // Executa o Frequency (Monobit) Test
        double pValue = frequencyMonobitTest(bitString);

        // Exibe o resultado
        System.out.println("Frequency (Monobit) Test p-value: " + pValue);
        if (pValue > 0.01) {
            System.out.println("A sequência provavelmente é aleatória.");
        } else {
            System.out.println("A sequência não parece ser aleatória.");
        }
    }
}
