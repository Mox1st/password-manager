package de.mox1st.passwordmanager.security;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordHasher {
    private static final String HASH_PREFIX = "pbkdf2-sha256";
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 600_000;
    // Prevents attacker-controlled hashes from forcing excessive login work.
    private static final int MAX_ACCEPTED_ITERATIONS = 2_000_000;
    private static final int SALT_LENGTH_BYTES = 16;
    private static final int HASH_LENGTH_BITS = 256;
    private final SecureRandom secureRandom = new SecureRandom();

    public String hashPassword(String password) {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Das Passwort darf nicht leer sein.");
        }
        try {
            byte[] salt = new byte[SALT_LENGTH_BYTES];
            secureRandom.nextBytes(salt);
            byte[] hash = deriveHash(password, salt);
            return HASH_PREFIX + "$" + ITERATIONS + "$"
                    + Base64.getEncoder().encodeToString(salt) + "$"
                    + Base64.getEncoder().encodeToString(hash);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "Das Passwort konnte nicht gehasht werden.",
                    exception
            );
        }
    }

    public boolean matches(String password, String storedHash) {
        if (password == null || storedHash == null) {
            return false;
        }
        if (isPbkdf2Hash(storedHash)) {
            return matchesPbkdf2(password, storedHash);
        }
        if (isLegacySha256Hash(storedHash)) {
            return matchesLegacySha256(password, storedHash);
        }
        return false;
    }

    public boolean isPbkdf2Hash(String storedHash) {
        if (storedHash == null) {
            return false;
        }
        String[] parts = storedHash.split("\\$", -1);
        return parts.length == 4
                && HASH_PREFIX.equals(parts[0])
                && isPositiveInteger(parts[1])
                && isBase64(parts[2])
                && isBase64(parts[3]);
    }

    public boolean isLegacySha256Hash(String storedHash) {
        if (storedHash == null || storedHash.length() != 64) {
            return false;
        }
        for (int index = 0; index < storedHash.length(); index++) {
            char character = storedHash.charAt(index);
            if (Character.digit(character, 16) < 0) {
                return false;
            }
        }
        return true;
    }

    private boolean matchesPbkdf2(String password, String storedHash) {
        try {
            String[] parts = storedHash.split("\\$", -1);
            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expectedHash = Base64.getDecoder().decode(parts[3]);
            if (iterations < ITERATIONS || iterations > MAX_ACCEPTED_ITERATIONS
                    || salt.length != SALT_LENGTH_BYTES
                    || expectedHash.length != HASH_LENGTH_BITS / 8) {
                return false;
            }
            return MessageDigest.isEqual(expectedHash, deriveHash(
                    password, salt, iterations
            ));
        } catch (IllegalArgumentException | GeneralSecurityException exception) {
            return false;
        }
    }

    private boolean matchesLegacySha256(String password, String storedHash) {
        byte[] actualHash = sha256(password);
        byte[] expectedHash = hexToBytes(storedHash);
        return MessageDigest.isEqual(expectedHash, actualHash);
    }

    private byte[] deriveHash(String password, byte[] salt)
            throws GeneralSecurityException {
        return deriveHash(password, salt, ITERATIONS);
    }

    private byte[] deriveHash(
            String password,
            byte[] salt,
            int iterations) throws GeneralSecurityException {
        PBEKeySpec keySpec = new PBEKeySpec(
                password.toCharArray(),
                salt,
                iterations,
                HASH_LENGTH_BITS
        );
        try {
            return SecretKeyFactory.getInstance(ALGORITHM)
                    .generateSecret(keySpec)
                    .getEncoded();
        } finally {
            keySpec.clearPassword();
        }
    }

    private byte[] sha256(String password) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(password.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "SHA-256 konnte nicht gefunden werden.",
                    exception
            );
        }
    }

    private byte[] hexToBytes(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) Integer.parseInt(
                    value.substring(index * 2, index * 2 + 2),
                    16
            );
        }
        return result;
    }

    private boolean isPositiveInteger(String value) {
        try {
            return Integer.parseInt(value) > 0;
        } catch (NumberFormatException exception) {
            return false;
        }
    }

    private boolean isBase64(String value) {
        try {
            Base64.getDecoder().decode(value);
            return true;
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }
}
