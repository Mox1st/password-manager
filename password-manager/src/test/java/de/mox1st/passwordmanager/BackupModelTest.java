package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.model.BackupContainer;
import de.mox1st.passwordmanager.model.BackupEntry;
import de.mox1st.passwordmanager.model.BackupPayload;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class BackupModelTest {

    @Test
    public void createsValidBackupModel() {
        BackupEntry entry = new BackupEntry(
                "example.com",
                "backup-user",
                "backup-password"
        );
        BackupPayload payload = new BackupPayload(
                "account-user",
                "pbkdf2-sha256$600000$salt$hash",
                new byte[]{1, 2, 3},
                List.of(entry)
        );
        BackupContainer container = new BackupContainer(
                BackupContainer.CURRENT_FORMAT_VERSION,
                "PBKDF2WithHmacSHA256",
                600_000,
                new byte[]{4, 5, 6},
                "AES-256-GCM",
                new byte[]{7, 8, 9},
                new byte[]{10, 11, 12}
        );

        assertEquals("example.com", payload.getEntries().get(0).getWebsite());
        assertEquals("account-user", payload.getUsername());
        assertEquals(BackupContainer.CURRENT_FORMAT_VERSION,
                container.getFormatVersion());
        assertEquals(payload.getPasswordHash(),
                "pbkdf2-sha256$600000$salt$hash");
    }

    @Test
    public void storesMultipleBackupEntries() {
        BackupPayload payload = new BackupPayload(
                "account-user",
                "hash",
                new byte[]{1},
                List.of(
                        new BackupEntry("one.example", "one", "one-password"),
                        new BackupEntry("two.example", "two", "two-password")
                )
        );

        assertEquals(2, payload.getEntries().size());
        assertEquals("two.example", payload.getEntries().get(1).getWebsite());
    }

    @Test
    public void associatesHeaderAndPayloadData() {
        byte[] salt = new byte[]{1, 2};
        byte[] nonce = new byte[]{3, 4};
        byte[] encryptedPayload = new byte[]{5, 6};
        BackupContainer container = new BackupContainer(
                1,
                "PBKDF2WithHmacSHA256",
                600_000,
                salt,
                "AES-256-GCM",
                nonce,
                encryptedPayload
        );

        assertEquals("PBKDF2WithHmacSHA256", container.getKdfAlgorithm());
        assertEquals(600_000, container.getKdfIterations());
        assertEquals("AES-256-GCM", container.getEncryptionAlgorithm());
        assertArrayEquals(salt, container.getBackupSalt());
        assertArrayEquals(nonce, container.getNonce());
        assertArrayEquals(encryptedPayload, container.getEncryptedPayload());
        assertTrue(container.getEncryptedPayload() != encryptedPayload);
    }
}
