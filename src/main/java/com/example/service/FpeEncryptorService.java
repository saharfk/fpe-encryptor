package com.example.service;


import com.example.exception.FpeException;
import org.bouncycastle.crypto.AlphabetMapper;
import org.bouncycastle.crypto.util.BasicAlphabetMapper;
import org.bouncycastle.jcajce.spec.FPEParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;

@Service
public class FpeEncryptorService {

    public static final String NUMBER = "0123456789abcdefghijklmnopqrstuvwxyz";
    public static final String AES_FF_1_NO_PADDING = "AES/FF1/NoPadding";
    private final String fpeKey = "fpeKey";
    private final String fpeTweak = "fpeTweak";


    public String FPEEncryption(String documentIdString) {
        try {
            SecretKey key = generateKey(fpeKey);
            byte[] tweak = getTweak(fpeTweak);
            AlphabetMapper alphabetMapper = new BasicAlphabetMapper(NUMBER);
            int radix = alphabetMapper.getRadix();
            char[] plaintext = documentIdString.toCharArray();
            byte[] plain_bytes = alphabetMapper.convertToIndexes(plaintext);
            Cipher cipher = Cipher.getInstance(AES_FF_1_NO_PADDING, new BouncyCastleProvider());
            byte[] cipher_bytes = encrypt(cipher, key, tweak, radix, plain_bytes);
            char[] cipher_chars = alphabetMapper.convertToChars(cipher_bytes);
            return new String(cipher_chars);
        } catch (Exception e) {
            throw new FpeException(e.getMessage());
        }

    }

    public String FPEDecryption(String documentIdEncypted) {
        try {
            AlphabetMapper alphabetMapper = new BasicAlphabetMapper(NUMBER);
            byte[] reversed_cipher_bytes = alphabetMapper.convertToIndexes(documentIdEncypted.toCharArray());
            SecretKey key = generateKey(fpeKey);
            byte[] tweak = getTweak(fpeTweak);
            int radix = alphabetMapper.getRadix();
            Cipher cipher = Cipher.getInstance(AES_FF_1_NO_PADDING, new BouncyCastleProvider());
            byte[] decrypted = decrypt(cipher, key, tweak, radix, reversed_cipher_bytes);
            char[] plain_chars = alphabetMapper.convertToChars(decrypted);
            return new String(plain_chars);
        } catch (Exception e) {
            throw new FpeException(e.getMessage());
        }
    }

    public byte[] encrypt(Cipher cipher, SecretKey key, byte[] tweak, int radix, byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        AlgorithmParameterSpec fpeParameterSpec = new FPEParameterSpec(radix, tweak);
        cipher.init(Cipher.ENCRYPT_MODE, key, fpeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    public byte[] decrypt(Cipher cipher, SecretKey key, byte[] tweak, int radix, byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        AlgorithmParameterSpec fpeParameterSpec = new FPEParameterSpec(radix, tweak);
        cipher.init(Cipher.DECRYPT_MODE, key, fpeParameterSpec);
        return cipher.doFinal(ciphertext);
    }

    private SecretKey generateKey(String secretKeyString) {
        byte[] secretKeyBytes = secretKeyString.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = new byte[32]; // 256 bits key length for AES
        System.arraycopy(secretKeyBytes, 0, keyBytes, 0, Math.min(secretKeyBytes.length, keyBytes.length));

        return new SecretKeySpec(keyBytes, "AES");
    }

    private byte[] getTweak(String tweak) {
        return tweak.getBytes(StandardCharsets.UTF_8);
    }
}

