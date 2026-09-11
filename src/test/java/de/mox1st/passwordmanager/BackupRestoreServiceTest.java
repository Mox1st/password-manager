package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.database.UserRepository;
import de.mox1st.passwordmanager.model.BackupContainer;
import de.mox1st.passwordmanager.model.BackupEntry;
import de.mox1st.passwordmanager.model.BackupPayload;
import de.mox1st.passwordmanager.model.User;
import de.mox1st.passwordmanager.service.BackupEncryptionService;
import de.mox1st.passwordmanager.service.BackupRestoreService;
import de.mox1st.passwordmanager.service.EncryptionSession;
import de.mox1st.passwordmanager.service.PasswordEncryptionService;
import de.mox1st.passwordmanager.security.PasswordHasher;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class BackupRestoreServiceTest {
    @Test
    public void restoresOwnEntriesWithBackupSaltAndKeepsLoginHash() throws Exception {
        Path database = Files.createTempFile("password-manager-restore-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            PasswordHasher hasher = new PasswordHasher();
            String currentPassword = "current-master";
            String loginHash = hasher.hashPassword(currentPassword);
            insertUser(url, 1, "owner", loginHash);
            PasswordEncryptionService encryption = new PasswordEncryptionService();
            byte[] oldSalt = encryption.generateSalt();
            byte[] newSalt = encryption.generateSalt();
            insertSalt(url, 1, oldSalt);
            EncryptionSession oldSession = new EncryptionSession(
                    encryption.deriveKey(currentPassword, oldSalt)
            );
            insertEntry(url, 1, 1, encryption.encrypt(
                    "old-password", oldSession.getKey()));

            BackupEncryptionService backupEncryption = new BackupEncryptionService();
            BackupContainer backup = backupEncryption.encrypt(
                    new BackupPayload(
                            "owner",
                            "backup-only-hash",
                            newSalt,
                            List.of(
                                    new BackupEntry("one.example", "one", "new-one"),
                                    new BackupEntry("two.example", "two", "new-two")
                            )
                    ),
                    "backup-password"
            );

            BackupRestoreService restore = new BackupRestoreService(
                    new UserRepository(() -> connect(url)),
                    new de.mox1st.passwordmanager.database.PasswordEntryRepository(),
                    backupEncryption,
                    encryption,
                    hasher,
                    () -> connect(url)
            );
            EncryptionSession restored = restore.restore(
                    backup,
                    "backup-password",
                    new User(1, "owner", loginHash),
                    currentPassword,
                    oldSession
            );

            assertEquals(2, count(url, "password_entries"));
            assertEquals(1, count(url, "users"));
            assertEquals(loginHash, readUserHash(url, "owner"));
            assertArrayEquals(newSalt, readSalt(url, 1));
            assertEquals(
                    "new-one",
                    encryption.decrypt(readPassword(url, 1), restored.getKey())
            );
            assertEquals(
                    "new-two",
                    encryption.decrypt(readPassword(url, 2), restored.getKey())
            );
            try {
                oldSession.getKey();
                fail("Die alte Session hätte nach erfolgreichem Restore ungültig sein müssen.");
            } catch (IllegalStateException expected) {
                assertTrue(true);
            }
            restored.clear();
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void rejectsWrongUserOrPasswordsWithoutDatabaseChanges() throws Exception {
        Path database = Files.createTempFile("password-manager-restore-reject-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            PasswordHasher hasher = new PasswordHasher();
            String currentPassword = "current-master";
            String loginHash = hasher.hashPassword(currentPassword);
            insertUser(url, 1, "owner", loginHash);
            PasswordEncryptionService encryption = new PasswordEncryptionService();
            byte[] salt = encryption.generateSalt();
            insertSalt(url, 1, salt);
            EncryptionSession session = new EncryptionSession(
                    encryption.deriveKey(currentPassword, salt));
            insertEntry(url, 1, 1, encryption.encrypt("unchanged", session.getKey()));
            BackupEncryptionService backupEncryption = new BackupEncryptionService();
            BackupContainer backup = backupEncryption.encrypt(
                    new BackupPayload("other", "hash", encryption.generateSalt(), List.of()),
                    "backup-password"
            );
            BackupRestoreService restore = newRestore(url, encryption, hasher, backupEncryption);

            assertRestoreRejected(restore, backup, "backup-password",
                    new User(1, "owner", loginHash), currentPassword, session);
            assertRestoreRejected(restore, backup, "wrong-backup-password",
                    new User(1, "owner", loginHash), currentPassword, session);
            assertEquals(1, count(url, "password_entries"));
            assertEquals("unchanged", encryption.decrypt(
                    readPassword(url, 1), session.getKey()));
        } finally {
            Files.deleteIfExists(database);
        }

    }

    @Test
    public void rejectsManipulatedUserIdWithoutChangingForeignEntries() throws Exception {
        Path database = Files.createTempFile("password-manager-restore-user-id-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            PasswordHasher hasher = new PasswordHasher();
            String currentPassword = "current-master";
            String loginHash = hasher.hashPassword(currentPassword);
            insertUser(url, 1, "owner", loginHash);
            insertUser(url, 2, "other", "other-hash");
            PasswordEncryptionService encryption = new PasswordEncryptionService();
            byte[] ownerSalt = encryption.generateSalt();
            byte[] otherSalt = encryption.generateSalt();
            insertSalt(url, 1, ownerSalt);
            insertSalt(url, 2, otherSalt);
            EncryptionSession session = new EncryptionSession(
                    encryption.deriveKey(currentPassword, ownerSalt));
            insertEntry(url, 1, 2, encryption.encrypt("foreign", session.getKey()));
            BackupEncryptionService backupEncryption = new BackupEncryptionService();
            BackupContainer backup = backupEncryption.encrypt(
                    new BackupPayload(
                            "owner", "ignored", encryption.generateSalt(),
                            List.of(new BackupEntry("new", "user", "secret"))
                    ),
                    "backup-password"
            );

            try {
                newRestore(url, encryption, hasher, backupEncryption).restore(
                        backup,
                        "backup-password",
                        new User(2, "owner", loginHash),
                        currentPassword,
                        session
                );
                fail("Ein manipulierter Benutzerkontext hätte abgelehnt werden müssen.");
            } catch (IllegalStateException expected) {
                assertEquals(1, count(url, "password_entries"));
                assertEquals("foreign", encryption.decrypt(
                        readPassword(url, 1), session.getKey()));
                assertArrayEquals(otherSalt, readSalt(url, 2));
            } finally {
                session.clear();
            }
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void rollsBackDeletedEntriesAndSaltWhenImportFails() throws Exception {
        Path database = Files.createTempFile("password-manager-restore-rollback-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            execute(url, """
                    CREATE TRIGGER fail_second_restore_entry
                    BEFORE INSERT ON password_entries
                    WHEN (SELECT COUNT(*) FROM password_entries) >= 1
                    BEGIN SELECT RAISE(ABORT, 'forced restore failure'); END
                    """);
            PasswordHasher hasher = new PasswordHasher();
            String currentPassword = "current-master";
            String loginHash = hasher.hashPassword(currentPassword);
            insertUser(url, 1, "owner", loginHash);
            PasswordEncryptionService encryption = new PasswordEncryptionService();
            byte[] oldSalt = encryption.generateSalt();
            byte[] newSalt = encryption.generateSalt();
            insertSalt(url, 1, oldSalt);
            EncryptionSession oldSession = new EncryptionSession(
                    encryption.deriveKey(currentPassword, oldSalt));
            insertEntry(url, 1, 1, encryption.encrypt("old", oldSession.getKey()));
            BackupEncryptionService backupEncryption = new BackupEncryptionService();
            BackupContainer backup = backupEncryption.encrypt(
                    new BackupPayload(
                            "owner", "ignored", newSalt,
                            List.of(
                                    new BackupEntry("first", "one", "first"),
                                    new BackupEntry("second", "two", "second")
                            )
                    ),
                    "backup-password"
            );

            try {
                newRestore(url, encryption, hasher, backupEncryption).restore(
                        backup,
                        "backup-password",
                        new User(1, "owner", loginHash),
                        currentPassword,
                        oldSession
                );
                fail("Der Restore hätte fehlschlagen müssen.");
            } catch (RuntimeException expected) {
                assertEquals(1, count(url, "password_entries"));
                assertEquals("old", encryption.decrypt(
                        readPassword(url, 1), oldSession.getKey()));
                assertArrayEquals(oldSalt, readSalt(url, 1));
                assertEquals(loginHash, readUserHash(url, "owner"));
            }
        } finally {
            Files.deleteIfExists(database);
        }
    }

    private BackupRestoreService newRestore(
            String url,
            PasswordEncryptionService encryption,
            PasswordHasher hasher,
            BackupEncryptionService backupEncryption) {
        return new BackupRestoreService(
                new UserRepository(() -> connect(url)),
                new de.mox1st.passwordmanager.database.PasswordEntryRepository(),
                backupEncryption,
                encryption,
                hasher,
                () -> connect(url)
        );
    }

    private void assertRestoreRejected(
            BackupRestoreService restore,
            BackupContainer backup,
            String backupPassword,
            User user,
            String currentPassword,
            EncryptionSession session) {
        try {
            restore.restore(backup, backupPassword, user, currentPassword, session);
            fail("Der Restore hätte abgelehnt werden müssen.");
        } catch (RuntimeException | java.security.GeneralSecurityException expected) {
            // Expected rejection before database modification.
        }
    }

    private void setupSchema(String url) throws Exception {
        try (Connection connection = connect(url); Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)");
            statement.execute("CREATE TABLE user_security (user_id INTEGER PRIMARY KEY, key_salt BLOB)");
            statement.execute("CREATE TABLE password_entries (id INTEGER PRIMARY KEY, user_id INTEGER, website TEXT, username TEXT, password TEXT)");
        }
    }

    private void insertUser(String url, int id, String username, String hash) throws Exception {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement("INSERT INTO users VALUES (?, ?, ?)")) {
            statement.setInt(1, id);
            statement.setString(2, username);
            statement.setString(3, hash);
            statement.executeUpdate();
        }
    }

    private void insertSalt(String url, int userId, byte[] salt) throws Exception {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement("INSERT INTO user_security VALUES (?, ?)")) {
            statement.setInt(1, userId);
            statement.setBytes(2, salt);
            statement.executeUpdate();
        }
    }

    private void insertEntry(String url, int id, int userId, String password) throws Exception {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement("INSERT INTO password_entries VALUES (?, ?, 'site', 'user', ?)")) {
            statement.setInt(1, id);
            statement.setInt(2, userId);
            statement.setString(3, password);
            statement.executeUpdate();
        }
    }

    private String readPassword(String url, int id) throws Exception {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement("SELECT password FROM password_entries WHERE id = ?")) {
            statement.setInt(1, id);
            try (var result = statement.executeQuery()) {
                result.next();
                return result.getString(1);
            }
        }
    }

    private String readUserHash(String url, String username) throws Exception {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement("SELECT password FROM users WHERE username = ?")) {
            statement.setString(1, username);
            try (var result = statement.executeQuery()) {
                result.next();
                return result.getString(1);
            }
        }
    }

    private byte[] readSalt(String url, int userId) throws Exception {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement("SELECT key_salt FROM user_security WHERE user_id = ?")) {
            statement.setInt(1, userId);
            try (var result = statement.executeQuery()) {
                result.next();
                return result.getBytes(1);
            }
        }
    }

    private int count(String url, String table) throws Exception {
        try (Connection connection = connect(url);
             var statement = connection.createStatement();
             var result = statement.executeQuery("SELECT COUNT(*) FROM " + table)) {
            result.next();
            return result.getInt(1);
        }
    }

    private void execute(String url, String sql) throws Exception {
        try (Connection connection = connect(url);
             Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private Connection connect(String url) {
        try {
            return DriverManager.getConnection(url);
        } catch (java.sql.SQLException exception) {
            throw new IllegalStateException("Testdatenbank konnte nicht geöffnet werden.", exception);
        }
    }

    private void assertArrayEquals(byte[] expected, byte[] actual) {
        org.junit.Assert.assertArrayEquals(expected, actual);
    }
}
