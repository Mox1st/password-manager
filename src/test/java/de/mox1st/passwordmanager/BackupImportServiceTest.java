package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.database.UserRepository;
import de.mox1st.passwordmanager.model.BackupContainer;
import de.mox1st.passwordmanager.model.BackupEntry;
import de.mox1st.passwordmanager.model.BackupPayload;
import de.mox1st.passwordmanager.service.BackupEncryptionService;
import de.mox1st.passwordmanager.service.BackupImportService;
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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.fail;

public class BackupImportServiceTest {
    @Test
    public void importsNewUserAndEncryptedEntriesAtomically() throws Exception {
        Path database = Files.createTempFile("password-manager-import-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            PasswordEncryptionService encryption = new PasswordEncryptionService();
            byte[] salt = encryption.generateSalt();
            BackupPayload payload = new BackupPayload(
                    "imported-user",
                    "pbkdf2-sha256$600000$salt$hash",
                    salt,
                    List.of(
                            new BackupEntry("one.example", "one", "secret-one"),
                            new BackupEntry("two.example", "two", "secret-two")
                    )
            );
            BackupEncryptionService backupEncryption = new BackupEncryptionService();
            BackupContainer container = backupEncryption.encrypt(payload, "master");
            UserRepository users = new UserRepository(() -> connect(url));
            BackupImportService service = new BackupImportService(
                    users, encryption, backupEncryption, () -> connect(url));

            EncryptionSession session = service.importBackup(
                    container, "master", "new-master");
            assertEquals(1, count(url, "users"));
            assertEquals(2, count(url, "password_entries"));
            String importedHash = users.findUser("imported-user").getPassword();
            PasswordHasher hasher = new PasswordHasher();
            org.junit.Assert.assertTrue(hasher.matches("new-master", importedHash));
            org.junit.Assert.assertFalse(hasher.matches("master", importedHash));
            assertNotEquals("secret-one", readPassword(url, 1));
            assertEquals(
                    "secret-one",
                    encryption.decrypt(readPassword(url, 1), session.getKey())
            );
            session.clear();
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void rejectsExistingUsernameWithoutChanges() throws Exception {
        Path database = Files.createTempFile("password-manager-import-existing-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            execute(url, "INSERT INTO users(username,password) VALUES ('same','hash')");
            PasswordEncryptionService encryption = new PasswordEncryptionService();
            BackupEncryptionService backupEncryption = new BackupEncryptionService();
            BackupContainer container = backupEncryption.encrypt(
                    new BackupPayload("same", "new-hash", encryption.generateSalt(), List.of()),
                    "master"
            );
            BackupImportService service = new BackupImportService(
                    new UserRepository(() -> connect(url)),
                    encryption,
                    backupEncryption,
                    () -> connect(url)
            );
            try {
                service.importBackup(container, "master", "new-master");
                fail("Ein vorhandener Benutzername hätte abgelehnt werden müssen.");
            } catch (IllegalStateException expected) {
                assertEquals(1, count(url, "users"));
                assertEquals(0, count(url, "password_entries"));
            }

        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void rollsBackUserAndEarlierEntriesWhenLaterEntryFails() throws Exception {
        Path database = Files.createTempFile("password-manager-import-rollback-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            execute(url, """
                    CREATE TRIGGER reject_second_entry
                    BEFORE INSERT ON password_entries
                    WHEN (SELECT COUNT(*) FROM password_entries) >= 1
                    BEGIN SELECT RAISE(ABORT, 'forced test failure'); END
                    """);
            PasswordEncryptionService encryption = new PasswordEncryptionService();
            BackupEncryptionService backupEncryption = new BackupEncryptionService();
            BackupContainer container = backupEncryption.encrypt(
                    new BackupPayload(
                            "rollback-user",
                            "hash",
                            encryption.generateSalt(),
                            List.of(
                                    new BackupEntry("first.example", "one", "first"),
                                    new BackupEntry("second.example", "two", "second")
                            )
                    ),
                    "master"
            );
            BackupImportService service = new BackupImportService(
                    new UserRepository(() -> connect(url)),
                    encryption,
                    backupEncryption,
                    () -> connect(url)
            );
            try {
                service.importBackup(container, "master", "new-master");
                fail("Der absichtlich ausgelöste Importfehler hätte weitergegeben werden müssen.");
            } catch (IllegalStateException expected) {
                assertEquals(0, count(url, "users"));
                assertEquals(0, count(url, "password_entries"));
                assertEquals(0, count(url, "user_security"));
            }
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void leavesExistingOtherUserAndEntriesUnchanged() throws Exception {
        Path database = Files.createTempFile("password-manager-import-isolation-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            execute(url, "INSERT INTO users(username,password) VALUES ('other','other-hash')");
            execute(url, """
                    INSERT INTO password_entries(user_id,website,username,password)
                    VALUES (1,'other.example','other-user','existing-ciphertext')
                    """);
            PasswordEncryptionService encryption = new PasswordEncryptionService();
            BackupEncryptionService backupEncryption = new BackupEncryptionService();
            BackupContainer container = backupEncryption.encrypt(
                    new BackupPayload(
                            "new-user",
                            "new-hash",
                            encryption.generateSalt(),
                            List.of(new BackupEntry("new.example", "new", "new-secret"))
                    ),
                    "master"
            );
            new BackupImportService(
                    new UserRepository(() -> connect(url)),
                    encryption,
                    backupEncryption,
                    () -> connect(url)
            ).importBackup(container, "master", "new-master").clear();

            assertEquals(2, count(url, "users"));
            assertEquals(2, count(url, "password_entries"));
            assertEquals("existing-ciphertext", readPassword(url, 1));
        } finally {
            Files.deleteIfExists(database);
        }
    }

    private void setupSchema(String url) throws Exception {
        try (Connection connection = connect(url); Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL)");
            statement.execute("CREATE TABLE user_security (user_id INTEGER PRIMARY KEY, key_salt BLOB NOT NULL)");
            statement.execute("CREATE TABLE password_entries (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, website TEXT NOT NULL, username TEXT NOT NULL, password TEXT NOT NULL)");
        }
    }

    private Connection connect(String url) {
        try {
            return DriverManager.getConnection(url);
        } catch (java.sql.SQLException exception) {
            throw new IllegalStateException("Testdatenbank konnte nicht geöffnet werden.", exception);
        }
    }

    private void execute(String url, String sql) throws Exception {
        try (Connection connection = connect(url); Statement statement = connection.createStatement()) {
            statement.execute(sql);
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
}
