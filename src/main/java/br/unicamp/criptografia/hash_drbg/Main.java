package br.unicamp.criptografia.hash_drbg;

import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        byte[] bouncyCastleRandomBytes = new BouncyCastleHashDRBG("nonce", "personalizationString", 256).generateRandomBytes();
        System.out.println("bouncyCastleRandomBytes: " + Arrays.toString(bouncyCastleRandomBytes));
    }
}