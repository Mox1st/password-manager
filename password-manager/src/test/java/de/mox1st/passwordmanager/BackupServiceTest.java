package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.database.PasswordEntryRepository;
import de.mox1st.passwordmanager.database.UserRepository;
import de.mox1st.passwordmanager.model.BackupPayload;
import de.mox1st.passwordmanager.model.User;
import de.mox1st.passwordmanager.service.BackupEncryptionService;
import de.mox1st.passwordmanager.service.BackupService;
import de.mox1st.passwordmanager.service.EncryptionSession;
import de.mox1st.passwordmanager.service.PasswordEncryptionService;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.lang.reflect.Field;
import java.util.function.Supplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class BackupServiceTest {

    @Test
    public void exportsOnlyUsersEntriesAndRoundTripsPayload() throws Exception {
        Path database = Files.createTempFile("password-manager-export-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            PasswordEncryptionService encryption = new PasswordEncryptionService();
            String masterPassword = "export-master";
            User user = new User(
                    1, "account-user", "pbkdf2-sha256$600000$salt$hash");
            insertUser(url, user);
            insertUser(url, new User(2, "other-user", "other-hash"));
            byte[] keySalt = encryption.generateSalt();
            insertSalt(url, 1, keySalt);
            insertSalt(url, 2, encryption.generateSalt());
            EncryptionSession session = new EncryptionSession(
                    encryption.deriveKey(masterPassword, keySalt));
            insertEntry(url, 1, 1, encryption.encrypt(
                    "pässword-" + "x".repeat(5000), session.getKey()));
            insertEntry(url, 2, 1, encryption.encrypt(
                    "second-password", session.getKey()));
            insertEntry(url, 3, 2, encryption.encrypt(
                    "foreign-password", session.getKey()));

            UserRepository users = new UserRepository(() -> connectUnchecked(url));
            PasswordEntryRepository entries = new PasswordEntryRepository(
                    session, () -> connectUnchecked(url));
            BackupEncryptionService backupEncryption = new BackupEncryptionService();
            BackupService backupService = new BackupService(
                    users, entries, backupEncryption);

            BackupPayload exported = backupEncryption.decrypt(
                    backupService.exportUser(user, masterPassword, session),
                    masterPassword
            );

            assertEquals("account-user", exported.getUsername());
            assertEquals(user.getPassword(), exported.getPasswordHash());
            assertArrayEquals(keySalt, exported.getKeySalt());
            assertEquals(2, exported.getEntries().size());
            assertEquals("pässword-" + "x".repeat(5000),
                    exported.getEntries().get(0).getPassword());
            assertEquals("second-password",
                    exported.getEntries().get(1).getPassword());
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void rejectsClearedSessionWithoutDatabaseExport() throws Exception {
        Path database = Files.createTempFile("password-manager-export-session-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            User user = new User(1, "account-user", "hash");
            insertUser(url, user);
            PasswordEncryptionService encryption = new PasswordEncryptionService();
            byte[] keySalt = encryption.generateSalt();
            insertSalt(url, 1, keySalt);
            EncryptionSession session = new EncryptionSession(
                    encryption.deriveKey("master", keySalt));
            session.clear();

            BackupService backupService = new BackupService(
                    new UserRepository(() -> connectUnchecked(url)),
                    new PasswordEntryRepository(session, () -> connectUnchecked(url)),
                    new BackupEncryptionService()
            );

            try {
                backupService.exportUser(user, "master", session);
                fail("Eine beendete Session hätte abgelehnt werden müssen.");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains(
                        "Verschlüsselungssitzung ist beendet"
                ));
            }
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void rejectsUserIdOnlyExportWithoutAuthenticatedContext() {
        BackupService backupService = new BackupService();

        try {
            backupService.exportUser(2, "master", null);
            fail("Ein Export nur anhand einer Benutzer-ID hätte abgelehnt werden müssen.");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains(
                    "authentifizierten Benutzerkontext"
            ));
        }
    }

    @Test
    public void rejectsForeignUserWithCurrentUsersSession() throws Exception {
        Path database = Files.createTempFile("password-manager-export-foreign-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            PasswordEncryptionService encryption = new PasswordEncryptionService();
            String masterPassword = "export-master";
            User owner = new User(1, "owner", "owner-hash");
            User foreign = new User(2, "foreign", "foreign-hash");
            insertUser(url, owner);
            insertUser(url, foreign);
            byte[] ownerSalt = encryption.generateSalt();
            insertSalt(url, 1, ownerSalt);
            insertSalt(url, 2, encryption.generateSalt());
            EncryptionSession ownerSession = new EncryptionSession(
                    encryption.deriveKey(masterPassword, ownerSalt));

            BackupService backupService = new BackupService(
                    new UserRepository(() -> connectUnchecked(url)),
                    new PasswordEntryRepository(
                            ownerSession,
                            () -> connectUnchecked(url)),
                    new BackupEncryptionService()
            );

            try {
                backupService.exportUser(foreign, masterPassword, ownerSession);
                fail("Ein fremder Benutzer hätte abgelehnt werden müssen.");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("nicht zum Benutzer"));
            } finally {
                ownerSession.clear();
            }
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void defaultRepositoryHasApplicationConnectionSupplier() throws Exception {
        BackupService backupService = new BackupService();
        Field repositoryField = BackupService.class.getDeclaredField(
                "passwordEntryRepository"
        );
        repositoryField.setAccessible(true);
        PasswordEntryRepository repository =
                (PasswordEntryRepository) repositoryField.get(backupService);
        Field supplierField = PasswordEntryRepository.class.getDeclaredField(
                "connectionSupplier"
        );
        supplierField.setAccessible(true);
        assertTrue(supplierField.get(repository) instanceof Supplier<?>);
    }

    private void setupSchema(String url) throws SQLException {
        try (Connection connection = connect(url);
             Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
            statement.execute("CREATE TABLE user_security (user_id INTEGER PRIMARY KEY, key_salt BLOB)");
            statement.execute("""
                    CREATE TABLE password_entries (
                        id INTEGER PRIMARY KEY, user_id INTEGER,
                        website TEXT, username TEXT, password TEXT
                    )
                    """);
        }
    }

    private void insertUser(String url, User user) throws SQLException {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement(
                     "INSERT INTO users VALUES (?, ?, ?)")) {
            statement.setInt(1, user.getId());
            statement.setString(2, user.getUsername());
            statement.setString(3, user.getPassword());
            statement.executeUpdate();
        }
    }

    private void insertSalt(String url, int userId, byte[] salt) throws SQLException {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement(
                     "INSERT INTO user_security VALUES (?, ?)")) {
            statement.setInt(1, userId);
            statement.setBytes(2, salt);
            statement.executeUpdate();
        }
    }

    private void insertEntry(String url, int id, int userId, String password)
            throws SQLException {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement(
                     "INSERT INTO password_entries VALUES (?, ?, 'site', 'user', ?)")) {
            statement.setInt(1, id);
            statement.setInt(2, userId);
            statement.setString(3, password);
            statement.executeUpdate();
        }
    }

    private void assertArrayEquals(byte[] expected, byte[] actual) {
        org.junit.Assert.assertArrayEquals(expected, actual);
    }

    private Connection connect(String url) throws SQLException {
        return DriverManager.getConnection(url);
    }

    private Connection connectUnchecked(String url) {
        try {
            return connect(url);
        } catch (SQLException exception) {
            throw new IllegalStateException("Testdatenbank konnte nicht geöffnet werden.", exception);
        }
    }
}
