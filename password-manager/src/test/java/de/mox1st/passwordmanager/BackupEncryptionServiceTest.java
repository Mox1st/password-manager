package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.model.BackupContainer;
import de.mox1st.passwordmanager.model.BackupEntry;
import de.mox1st.passwordmanager.model.BackupPayload;
import de.mox1st.passwordmanager.service.BackupEncryptionService;
import org.junit.Test;

import java.security.GeneralSecurityException;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

public class BackupEncryptionServiceTest {

    private static final String MASTER_PASSWORD = "backup-master-value";

    @Test
    public void encryptDecryptRoundTripPreservesMultipleEntries() throws Exception {
        BackupPayload payload = payload();
        BackupEncryptionService service = new BackupEncryptionService();

        BackupContainer container = service.encrypt(payload, MASTER_PASSWORD);
        BackupPayload restored = service.decrypt(container, MASTER_PASSWORD);

        assertEquals(payload.getUsername(), restored.getUsername());
        assertEquals(payload.getPasswordHash(), restored.getPasswordHash());
        assertArrayEquals(payload.getKeySalt(), restored.getKeySalt());
        assertEquals(2, restored.getEntries().size());
        assertEquals("first-password", restored.getEntries().get(0).getPassword());
        assertEquals("second-password", restored.getEntries().get(1).getPassword());
    }

    @Test
    public void separateEncryptionsUseDifferentSaltAndNonce() throws Exception {
        BackupEncryptionService service = new BackupEncryptionService();

        BackupContainer first = service.encrypt(payload(), MASTER_PASSWORD);
        BackupContainer second = service.encrypt(payload(), MASTER_PASSWORD);

        assertFalse(java.util.Arrays.equals(
                first.getBackupSalt(), second.getBackupSalt()));
        assertFalse(java.util.Arrays.equals(first.getNonce(), second.getNonce()));
    }

    @Test
    public void rejectsWrongPasswordAndTamperedCiphertext() throws Exception {
        BackupEncryptionService service = new BackupEncryptionService();
        BackupContainer container = service.encrypt(payload(), MASTER_PASSWORD);

        assertDecryptFails(service, container, "wrong-password");
        byte[] tampered = container.getEncryptedPayload();
        tampered[0] ^= 1;
        assertDecryptFails(service, new BackupContainer(
                1, container.getKdfAlgorithm(), container.getKdfIterations(),
                container.getBackupSalt(), container.getEncryptionAlgorithm(),
                container.getNonce(), tampered
        ), MASTER_PASSWORD);

        byte[] tamperedSalt = container.getBackupSalt();
        tamperedSalt[0] ^= 1;
        assertDecryptFails(service, new BackupContainer(
                1, container.getKdfAlgorithm(), container.getKdfIterations(),
                tamperedSalt, container.getEncryptionAlgorithm(),
                container.getNonce(), container.getEncryptedPayload()
        ), MASTER_PASSWORD);

        byte[] tamperedNonce = container.getNonce();
        tamperedNonce[0] ^= 1;
        assertDecryptFails(service, new BackupContainer(
                1, container.getKdfAlgorithm(), container.getKdfIterations(),
                container.getBackupSalt(), container.getEncryptionAlgorithm(),
                tamperedNonce, container.getEncryptedPayload()
        ), MASTER_PASSWORD);
    }

    @Test
    public void rejectsInvalidContainerParameters() throws Exception {
        BackupEncryptionService service = new BackupEncryptionService();
        BackupContainer valid = service.encrypt(payload(), MASTER_PASSWORD);

        assertDecryptFails(service, new BackupContainer(
                1, valid.getKdfAlgorithm(), valid.getKdfIterations(),
                new byte[15], valid.getEncryptionAlgorithm(),
                valid.getNonce(), valid.getEncryptedPayload()
        ), MASTER_PASSWORD);
        assertDecryptFails(service, new BackupContainer(
                1, valid.getKdfAlgorithm(), valid.getKdfIterations(),
                valid.getBackupSalt(), valid.getEncryptionAlgorithm(),
                new byte[11], valid.getEncryptedPayload()
        ), MASTER_PASSWORD);
        assertDecryptFails(service, new BackupContainer(
                1, valid.getKdfAlgorithm(), 599_999,
                valid.getBackupSalt(), valid.getEncryptionAlgorithm(),
                valid.getNonce(), valid.getEncryptedPayload()
        ), MASTER_PASSWORD);
        assertDecryptFails(service, new BackupContainer(
                1, valid.getKdfAlgorithm(), 2_000_001,
                valid.getBackupSalt(), valid.getEncryptionAlgorithm(),
                valid.getNonce(), valid.getEncryptedPayload()
        ), MASTER_PASSWORD);
    }

    @Test
    public void rejectsUnsupportedVersion() throws Exception {
        BackupEncryptionService service = new BackupEncryptionService();
        BackupContainer invalid = new BackupContainer(
                2, "PBKDF2WithHmacSHA256", 600_000,
                new byte[16], "AES-256-GCM", new byte[12], new byte[]{1}
        );

        assertDecryptFails(service, invalid, MASTER_PASSWORD);
    }

    private BackupPayload payload() {
        return new BackupPayload(
                "account-user",
                "pbkdf2-sha256$600000$salt$hash",
                new byte[16],
                List.of(
                        new BackupEntry("one.example", "one-user", "first-password"),
                        new BackupEntry("two.example", "two-user", "second-password")
                )
        );
    }

    private void assertDecryptFails(
            BackupEncryptionService service,
            BackupContainer container,
            String password) throws GeneralSecurityException {
        try {
            service.decrypt(container, password);
            fail("Das Backup hätte abgelehnt werden müssen.");
        } catch (IllegalArgumentException | GeneralSecurityException expected) {
            // Expected for invalid parameters, wrong passwords, and tampering.
        }
    }
}
