package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.security.PasswordHasher;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PasswordHasherTest {

    @Test
    public void createsAndVerifiesPbkdf2Hash() {
        PasswordHasher hasher = new PasswordHasher();
        String hash = hasher.hashPassword("test-master-value");

        assertTrue(hasher.isPbkdf2Hash(hash));
        assertTrue(hasher.matches("test-master-value", hash));
        assertFalse(hasher.matches("wrong-master-value", hash));
    }

    @Test
    public void rejectsPbkdf2HashWithTooFewIterations() {
        PasswordHasher hasher = new PasswordHasher();
        String validHash = hasher.hashPassword("test-master-value");
        String weakenedHash = validHash.replace("$600000$", "$599999$");

        assertFalse(hasher.matches("test-master-value", weakenedHash));
    }

    @Test
    public void rejectsPbkdf2HashWithExcessiveIterations() {
        PasswordHasher hasher = new PasswordHasher();
        String validHash = hasher.hashPassword("test-master-value");
        String excessiveHash = validHash.replace("$600000$", "$2000001$");

        assertFalse(hasher.matches("test-master-value", excessiveHash));
    }

    @Test
    public void usesDifferentSaltsForEqualPasswords() {
        PasswordHasher hasher = new PasswordHasher();

        assertFalse(hasher.hashPassword("same-test-value")
                .equals(hasher.hashPassword("same-test-value")));
    }

    @Test
    public void verifiesLegacySha256Hash() throws Exception {
        PasswordHasher hasher = new PasswordHasher();
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest("legacy-test-value".getBytes(StandardCharsets.UTF_8));
        StringBuilder legacyHash = new StringBuilder();
        for (byte value : digest) {
            legacyHash.append(String.format("%02x", value));
        }

        assertTrue(hasher.isLegacySha256Hash(legacyHash.toString()));
        assertTrue(hasher.matches("legacy-test-value", legacyHash.toString()));
        assertFalse(hasher.matches("wrong-test-value", legacyHash.toString()));
    }
}
