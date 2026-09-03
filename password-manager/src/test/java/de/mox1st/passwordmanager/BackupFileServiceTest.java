package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.model.BackupContainer;
import de.mox1st.passwordmanager.model.BackupEntry;
import de.mox1st.passwordmanager.model.BackupPayload;
import de.mox1st.passwordmanager.service.BackupEncryptionService;
import de.mox1st.passwordmanager.service.BackupFileService;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

public class BackupFileServiceTest {

    @Test
    public void writesAndReadsContainerWithoutPlaintextSecrets() throws Exception {
        BackupEncryptionService encryptionService = new BackupEncryptionService();
        BackupFileService fileService = new BackupFileService();
        BackupContainer original = encryptionService.encrypt(
                new BackupPayload(
                        "account-user",
                        "pbkdf2-sha256$600000$salt$hash",
                        new byte[16],
                        List.of(
                                new BackupEntry(
                                        "one.example",
                                        "one",
                                        "päss-" + "x".repeat(5000)
                                ),
                                new BackupEntry(
                                        "two.example",
                                        "two",
                                        "second-password"
                                )
                        )
                ),
                "backup-master"
        );

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        fileService.write(original, bytes);
        byte[] serialized = bytes.toByteArray();
        BackupContainer restored = fileService.read(
                new ByteArrayInputStream(serialized)
        );

        assertEquals(original.getFormatVersion(), restored.getFormatVersion());
        assertEquals(original.getKdfAlgorithm(), restored.getKdfAlgorithm());
        assertEquals(original.getKdfIterations(), restored.getKdfIterations());
        assertArrayEquals(original.getBackupSalt(), restored.getBackupSalt());
        assertEquals(
                original.getEncryptionAlgorithm(),
                restored.getEncryptionAlgorithm()
        );
        assertArrayEquals(original.getNonce(), restored.getNonce());
        assertArrayEquals(
                original.getEncryptedPayload(),
                restored.getEncryptedPayload()
        );
        String serializedText = new String(serialized, StandardCharsets.UTF_8);
        assertEquals(-1, serializedText.indexOf("päss-"));
        assertEquals(-1, serializedText.indexOf("backup-master"));
    }

    @Test
    public void writesAndReadsAFile() throws Exception {
        BackupContainer original = new BackupEncryptionService().encrypt(
                new BackupPayload("user", "hash", new byte[16], List.of(
                        new BackupEntry("site", "name", "password")
                )),
                "master"
        );
        Path file = Files.createTempFile("password-manager-backup-", ".bin");
        try {
            BackupFileService service = new BackupFileService();
            service.write(original, file);
            BackupContainer restored = service.read(file);
            assertArrayEquals(
                    original.getEncryptedPayload(),
                    restored.getEncryptedPayload()
            );
        } finally {
            Files.deleteIfExists(file);
        }
    }

    @Test
    public void leavesNoTemporaryFileAfterSuccessfulWrite() throws Exception {
        BackupContainer container = new BackupEncryptionService().encrypt(
                new BackupPayload("user", "hash", new byte[16], List.of(
                        new BackupEntry("site", "name", "password")
                )),
                "master"
        );
        Path directory = Files.createTempDirectory("password-manager-backup-dir-");
        Path file = directory.resolve("backup.pmb");
        try {
            new BackupFileService().write(container, file);
            try (var files = Files.list(directory)) {
                assertFalse(files.anyMatch(path -> path.getFileName().toString().startsWith(".pmb-")));
            }
        } finally {
            Files.deleteIfExists(file);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    public void rejectsCorruptedTruncatedAndInvalidFiles() throws Exception {
        BackupFileService fileService = new BackupFileService();
        BackupContainer valid = new BackupEncryptionService().encrypt(
                new BackupPayload("user", "hash", new byte[16], List.of(
                        new BackupEntry("site", "name", "password")
                )),
                "master"
        );
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        fileService.write(valid, bytes);
        byte[] serialized = bytes.toByteArray();

        byte[] corrupted = serialized.clone();
        corrupted[0] ^= 1;
        assertReadFails(fileService, corrupted);

        byte[] truncated = java.util.Arrays.copyOf(
                serialized,
                serialized.length - 1
        );
        assertReadFails(fileService, truncated);

        byte[] invalidVersion = serialized.clone();
        invalidVersion[7] = 2;
        assertReadFails(fileService, invalidVersion);
    }

    @Test
    public void rejectsNullStreamsAndMissingRequiredFields() throws Exception {
        BackupFileService fileService = new BackupFileService();
        try {
            fileService.read((java.io.InputStream) null);
            fail("Ein null InputStream hätte abgelehnt werden müssen.");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
        try {
            fileService.write(null, new ByteArrayOutputStream());
            fail("Ein null Container hätte abgelehnt werden müssen.");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private void assertReadFails(
            BackupFileService service,
            byte[] data) throws IOException {
        try {
            service.read(new ByteArrayInputStream(data));
            fail("Die beschädigte Backup-Datei hätte abgelehnt werden müssen.");
        } catch (IOException expected) {
            // Expected for corrupted or truncated data.
        }
    }
}
