package br.unicamp.criptografia.hash_drbg;

import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import java.security.SecureRandom;

public class HashDRBGExample {

    public static void run() {
        byte[] randomBytes = getBytes();

        // Converter os bytes em uma sequência de bits para exibição
        StringBuilder bitString = new StringBuilder();
        for (byte b : randomBytes) {
            bitString.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }

        // Imprimir a sequência de bits gerada
        System.out.println("Sequência de bits gerada: " + bitString.toString());
    }

    private static byte[] getBytes() {
        SHA256Digest sha256Digest = new SHA256Digest();
        DigestRandomGenerator hashDrbg = new DigestRandomGenerator(sha256Digest);

        // Inicializar o gerador com uma semente
        SecureRandom secureRandom = new SecureRandom();
        byte[] seed = new byte[32];
        secureRandom.nextBytes(seed);
        hashDrbg.addSeedMaterial(seed);

        // Gerar uma sequência de bytes aleatórios
        byte[] randomBytes = new byte[64]; // Defina o tamanho conforme necessário
        hashDrbg.nextBytes(randomBytes);
        return randomBytes;
    }
}
