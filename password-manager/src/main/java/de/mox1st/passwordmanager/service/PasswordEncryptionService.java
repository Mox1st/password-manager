package de.mox1st.passwordmanager.service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordEncryptionService {

    private static final String VERSION_PREFIX = "v1:";
    private static final String KEY_ALGORITHM = "AES";
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int SALT_LENGTH_BYTES = 16;
    private static final int NONCE_LENGTH_BYTES = 12;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int PBKDF2_ITERATIONS = 600_000;

    private final SecureRandom secureRandom = new SecureRandom();

    public byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        secureRandom.nextBytes(salt);
        return salt;
    }

    public SecretKey deriveKey(String masterPassword, byte[] salt)
            throws GeneralSecurityException {
        if (masterPassword == null || masterPassword.isEmpty()) {
            throw new IllegalArgumentException(
                    "Das Masterpasswort darf nicht leer sein."
            );
        }
        if (salt == null || salt.length != SALT_LENGTH_BYTES) {
            throw new IllegalArgumentException("Der Salt ist ungültig.");
        }

        PBEKeySpec keySpec = new PBEKeySpec(
                masterPassword.toCharArray(),
                salt,
                PBKDF2_ITERATIONS,
                KEY_LENGTH_BITS
        );

        try {
            SecretKeyFactory keyFactory =
                    SecretKeyFactory.getInstance(KDF_ALGORITHM);
            byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
            return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        } finally {
            keySpec.clearPassword();
        }
    }

    public String encrypt(String plaintext, SecretKey key)
            throws GeneralSecurityException {
        if (plaintext == null) {
            throw new IllegalArgumentException("Der Klartext darf nicht null sein.");
        }
        validateKey(key);

        byte[] nonce = new byte[NONCE_LENGTH_BYTES];
        secureRandom.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(
                Cipher.ENCRYPT_MODE,
                key,
                new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce)
        );
        byte[] ciphertext = cipher.doFinal(
                plaintext.getBytes(StandardCharsets.UTF_8)
        );

        byte[] payload = ByteBuffer.allocate(nonce.length + ciphertext.length)
                .put(nonce)
                .put(ciphertext)
                .array();

        return VERSION_PREFIX + Base64.getEncoder().encodeToString(payload);
    }

    public String decrypt(String encryptedValue, SecretKey key)
            throws GeneralSecurityException {
        if (encryptedValue == null
                || !encryptedValue.startsWith(VERSION_PREFIX)) {
            throw new IllegalArgumentException(
                    "Der verschlüsselte Wert hat kein unterstütztes Format."
            );
        }
        validateKey(key);

        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(
                    encryptedValue.substring(VERSION_PREFIX.length())
            );
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                    "Der verschlüsselte Wert ist kein gültiges Base64.",
                    exception
            );
        }

        if (payload.length <= NONCE_LENGTH_BYTES) {
            throw new IllegalArgumentException(
                    "Der verschlüsselte Wert ist unvollständig."
            );
        }

        byte[] nonce = new byte[NONCE_LENGTH_BYTES];
        byte[] ciphertext = new byte[payload.length - NONCE_LENGTH_BYTES];
        System.arraycopy(payload, 0, nonce, 0, nonce.length);
        System.arraycopy(
                payload,
                nonce.length,
                ciphertext,
                0,
                ciphertext.length
        );

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce)
        );
        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    private void validateKey(SecretKey key) {
        if (key == null
                || !KEY_ALGORITHM.equalsIgnoreCase(key.getAlgorithm())
                || key.getEncoded() == null
                || key.getEncoded().length != KEY_LENGTH_BITS / 8) {
            throw new IllegalArgumentException("Der AES-Schlüssel ist ungültig.");
        }
    }
}
