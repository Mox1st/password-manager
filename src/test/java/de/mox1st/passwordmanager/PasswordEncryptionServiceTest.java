package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.service.PasswordEncryptionService;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.fail;

public class PasswordEncryptionServiceTest {

    private static final String MASTER_PASSWORD = "MasterPasswort123!";
    private static final String PLAINTEXT = "MeinTestPasswort123!";

    @Test
    public void encryptAndDecryptRoundTrip() throws GeneralSecurityException {
        PasswordEncryptionService service = new PasswordEncryptionService();
        byte[] salt = service.generateSalt();
        SecretKey key = service.deriveKey(MASTER_PASSWORD, salt);

        String encrypted = service.encrypt(PLAINTEXT, key);

        assertEquals(PLAINTEXT, service.decrypt(encrypted, key));
    }

    @Test
    public void encryptionsUseDifferentNonces() throws GeneralSecurityException {
        PasswordEncryptionService service = new PasswordEncryptionService();
        SecretKey key = service.deriveKey(
                MASTER_PASSWORD,
                service.generateSalt()
        );

        assertNotEquals(
                service.encrypt(PLAINTEXT, key),
                service.encrypt(PLAINTEXT, key)
        );
    }

    @Test
    public void deriveKeyAcceptsExactly16ByteSalt() throws GeneralSecurityException {
        PasswordEncryptionService service = new PasswordEncryptionService();

        assertNotEquals(
                null,
                service.deriveKey(MASTER_PASSWORD, new byte[16])
        );
    }

    @Test
    public void deriveKeyRejectsNullAndInvalidSaltLengths()
            throws GeneralSecurityException {
        PasswordEncryptionService service = new PasswordEncryptionService();

        assertDeriveKeyFails(service, null);
        assertDeriveKeyFails(service, new byte[15]);
        assertDeriveKeyFails(service, new byte[17]);
    }

    @Test
    public void tamperedCiphertextAndWrongKeyAreRejected()
            throws GeneralSecurityException {
        PasswordEncryptionService service = new PasswordEncryptionService();
        byte[] salt = service.generateSalt();
        SecretKey key = service.deriveKey(MASTER_PASSWORD, salt);
        String encrypted = service.encrypt(PLAINTEXT, key);

        String tampered = encrypted.substring(0, encrypted.length() - 1)
                + (encrypted.endsWith("A") ? "B" : "A");
        assertDecryptionFails(service, tampered, key);

        SecretKey wrongKey = service.deriveKey("FalschesPasswort", salt);
        assertDecryptionFails(service, encrypted, wrongKey);
    }

    private void assertDecryptionFails(
            PasswordEncryptionService service,
            String encrypted,
            SecretKey key) throws GeneralSecurityException {
        try {
            service.decrypt(encrypted, key);
            fail("Die Entschlüsselung hätte fehlschlagen müssen.");
        } catch (GeneralSecurityException | IllegalArgumentException expected) {
            // Expected for tampered data and an incorrect key.
        }
    }

    private void assertDeriveKeyFails(
            PasswordEncryptionService service,
            byte[] salt) throws GeneralSecurityException {
        try {
            service.deriveKey(MASTER_PASSWORD, salt);
            fail("Ein ungültiger Salt hätte abgelehnt werden müssen.");
        } catch (IllegalArgumentException expected) {
            // Expected for null and invalid salt lengths.
        }
    }
}
