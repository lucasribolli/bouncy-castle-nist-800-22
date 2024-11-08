package br.unicamp.criptografia.hash_drbg;

import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        byte[] bouncyCastleRandomBytes = new BouncyCastleHashDRBG("nonce", "personalizationString").generateDefaultRandomBytes();
        System.out.println("bouncyCastleRandomBytes: " + Arrays.toString(bouncyCastleRandomBytes));
    }
}