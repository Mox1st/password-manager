package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.database.PasswordEntryRepository;
import de.mox1st.passwordmanager.model.PasswordEntry;
import de.mox1st.passwordmanager.service.EncryptionSession;
import de.mox1st.passwordmanager.service.PasswordEncryptionService;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.ResultSet;
import java.sql.Statement;
import java.security.GeneralSecurityException;
import javax.crypto.SecretKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class PasswordEntryRepositoryMigrationTest {

    @Test
    public void migratesOnlyLegacyEntriesForUserAndIsIdempotent()
            throws Exception {
        Path database = Files.createTempFile("password-manager-migration-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);

            PasswordEncryptionService service = new PasswordEncryptionService();
            EncryptionSession session = createSession(service);
            PasswordEntryRepository repository =
                    new PasswordEntryRepository(session,
                            () -> connectUnchecked(url));

            String existingEncrypted = service.encrypt(
                    "already-encrypted-test-value",
                    session.getKey()
            );
            insert(url, 1, 1, "legacy.example", "user-a", "legacy-test-value");
            insert(url, 2, 1, "encrypted.example", "user-a", existingEncrypted);
            insert(url, 3, 2, "other.example", "user-b", "other-test-value");

            repository.migrateLegacyEntriesForUser(1, session);

            String migrated = passwordValue(url, 1);
            assertTrue(migrated.startsWith("v1:"));
            assertNotEquals("legacy-test-value", migrated);
            assertEquals(existingEncrypted, passwordValue(url, 2));
            assertEquals("other-test-value", passwordValue(url, 3));
            assertEquals(
                    "legacy-test-value",
                    repository.findEntriesByUserId(1).get(0).getPassword()
            );

            repository.migrateLegacyEntriesForUser(1, session);
            assertEquals(migrated, passwordValue(url, 1));
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void rollsBackAllUpdatesWhenOneUpdateFails() throws Exception {
        Path database = Files.createTempFile("password-manager-rollback-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            try (Connection connection = connect(url);
                 Statement statement = connection.createStatement()) {
                statement.execute("""
                        CREATE TRIGGER fail_second_migration
                        BEFORE UPDATE OF password ON password_entries
                        WHEN OLD.id = 2
                        BEGIN
                            SELECT RAISE(ABORT, 'test rollback');
                        END
                        """);
            }

            PasswordEncryptionService service = new PasswordEncryptionService();
            EncryptionSession session = createSession(service);
            PasswordEntryRepository repository =
                    new PasswordEntryRepository(session,
                            () -> connectUnchecked(url));
            insert(url, 1, 1, "first.example", "user-a", "first-test-value");
            insert(url, 2, 1, "second.example", "user-a", "second-test-value");

            try {
                repository.migrateLegacyEntriesForUser(1, session);
                fail("Die Migration hätte fehlschlagen müssen.");
            } catch (RuntimeException expected) {
                // The repository must roll back and propagate the failure.
            }

            assertEquals("first-test-value", passwordValue(url, 1));
            assertEquals("second-test-value", passwordValue(url, 2));
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void loadsV1EntriesAndRejectsLegacyValues() throws Exception {
        Path database = Files.createTempFile("password-manager-format-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            PasswordEncryptionService service = new PasswordEncryptionService();
            EncryptionSession session = createSession(service);
            PasswordEntryRepository repository =
                    new PasswordEntryRepository(session,
                            () -> connectUnchecked(url));

            String encrypted = service.encrypt(
                    "v1-test-value",
                    session.getKey()
            );
            insert(url, 1, 1, "encrypted.example", "user-a", encrypted);
            assertEquals(
                    "v1-test-value",
                    repository.findEntriesByUserId(1).get(0).getPassword()
            );

            insert(url, 2, 1, "legacy.example", "user-a", "legacy-test-value");
            try {
                repository.findEntriesByUserId(1);
                fail("Ein Legacy-Wert darf nicht geladen werden.");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains("unbekanntes Format"));
            }
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void saveAndUpdateStoreV1Values() throws Exception {
        Path database = Files.createTempFile("password-manager-write-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            PasswordEncryptionService service = new PasswordEncryptionService();
            EncryptionSession session = createSession(service);
            PasswordEntryRepository repository =
                    new PasswordEntryRepository(session,
                            () -> connectUnchecked(url));

            repository.saveEntry(new PasswordEntry(
                    1, "save.example", "user-a", "save-test-value"
            ));
            String saved = passwordValue(url, 1);
            assertTrue(saved.startsWith("v1:"));

            assertTrue(repository.updateEntry(new PasswordEntry(
                    1, 1, "update.example", "user-a", "update-test-value"
            ), 1));
            String updated = passwordValue(url, 1);
            assertTrue(updated.startsWith("v1:"));
            assertEquals(
                    "update-test-value",
                    repository.findEntriesByUserId(1).get(0).getPassword()
            );
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void updateAndDeleteRequireMatchingUserId() throws Exception {
        Path database = Files.createTempFile("password-manager-auth-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            PasswordEncryptionService service = new PasswordEncryptionService();
            EncryptionSession session = createSession(service);
            PasswordEntryRepository repository =
                    new PasswordEntryRepository(session,
                            () -> connectUnchecked(url));

            insert(url, 1, 1, "user-a.example", "user-a", service.encrypt(
                    "user-a-password", session.getKey()));
            insert(url, 2, 2, "user-b.example", "user-b", service.encrypt(
                    "user-b-password", session.getKey()));

            assertTrue(repository.updateEntry(new PasswordEntry(
                    1, 1, "updated.example", "user-a", "updated-password"
            ), 1));
            assertFalse(repository.updateEntry(new PasswordEntry(
                    2, 2, "not-updated.example", "user-b", "not-updated-password"
            ), 1));
            assertEquals("user-b.example", entryValue(url, 2, "website"));
            assertEquals(
                    "user-b-password",
                    repository.findEntriesByUserId(2).get(0).getPassword()
            );

            assertFalse(repository.deleteEntry(2, 1));
            assertTrue(repository.deleteEntry(1, 1));
            assertEquals("user-b.example", entryValue(url, 2, "website"));
            assertEquals(null, entryValue(url, 1, "website"));
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void rekeysOnlySelectedUsersAndRequiresTransactionRollbackOnFailure()
            throws Exception {
        Path database = Files.createTempFile("password-manager-rekey-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            PasswordEncryptionService service = new PasswordEncryptionService();
            EncryptionSession oldSession = createSession(service);
            EncryptionSession newSession = new EncryptionSession(
                    service.deriveKey("new-test-master-value", service.generateSalt())
            );
            PasswordEntryRepository repository =
                    new PasswordEntryRepository(oldSession, () -> connectUnchecked(url));

            insert(url, 1, 1, "first.example", "user-a",
                    service.encrypt("first-password", oldSession.getKey()));
            insert(url, 2, 1, "second.example", "user-a",
                    service.encrypt("second-password", oldSession.getKey()));
            insert(url, 3, 2, "other.example", "user-b",
                    service.encrypt("other-password", oldSession.getKey()));

            try (Connection connection = connect(url)) {
                connection.setAutoCommit(false);
                repository.rekeyEntriesForUser(1, oldSession, newSession, connection);
                connection.commit();
            }

            String firstRekeyed = passwordValue(url, 1);
            String secondRekeyed = passwordValue(url, 2);
            assertEquals("first-password", service.decrypt(
                    firstRekeyed, newSession.getKey()));
            assertEquals("second-password", service.decrypt(
                    secondRekeyed, newSession.getKey()));
            assertDecryptionFails(service, firstRekeyed, oldSession.getKey());
            assertEquals(
                    "other-password",
                    service.decrypt(passwordValue(url, 3), oldSession.getKey())
            );

            try (Connection connection = connect(url);
                 Statement statement = connection.createStatement()) {
                statement.execute("""
                        CREATE TRIGGER fail_rekey
                        BEFORE UPDATE OF password ON password_entries
                        WHEN OLD.id = 2
                        BEGIN
                            SELECT RAISE(ABORT, 'test rollback');
                        END
                        """);
                connection.setAutoCommit(false);
                try {
                    repository.rekeyEntriesForUser(1, newSession, oldSession, connection);
                    fail("Das Re-Keying hätte fehlschlagen müssen.");
                } catch (RuntimeException expected) {
                    connection.rollback();
                }
            }

            assertEquals(firstRekeyed, passwordValue(url, 1));
            assertEquals(secondRekeyed, passwordValue(url, 2));
        } finally {
            Files.deleteIfExists(database);
        }
    }

    private void assertDecryptionFails(
            PasswordEncryptionService service,
            String encrypted,
            SecretKey key) throws Exception {
        try {
            service.decrypt(encrypted, key);
            fail("Die Entschlüsselung hätte fehlschlagen müssen.");
        } catch (GeneralSecurityException | IllegalArgumentException expected) {
            // Expected when using the old key.
        }
    }

    private EncryptionSession createSession(PasswordEncryptionService service)
            throws Exception {
        SecretKey key = service.deriveKey(
                "test-master-value",
                service.generateSalt()
        );
        return new EncryptionSession(key);
    }

    private void setupSchema(String url) throws Exception {
        try (Connection connection = connect(url);
             Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE password_entries (
                        id INTEGER PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        website TEXT NOT NULL,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL
                    )
                    """);
        }
    }

    private void insert(
            String url,
            int id,
            int userId,
            String website,
            String username,
            String password) throws Exception {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement("""
                     INSERT INTO password_entries
                         (id, user_id, website, username, password)
                     VALUES (?, ?, ?, ?, ?)
                     """)) {
            statement.setInt(1, id);
            statement.setInt(2, userId);
            statement.setString(3, website);
            statement.setString(4, username);
            statement.setString(5, password);
            statement.executeUpdate();
        }
    }

    private String passwordValue(String url, int id) throws Exception {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement(
                     "SELECT password FROM password_entries WHERE id = ?")) {
            statement.setInt(1, id);
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                return resultSet.getString(1);
            }
        }
    }

    private String entryValue(String url, int id, String column) throws Exception {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement(
                     "SELECT " + column + " FROM password_entries WHERE id = ?")) {
            statement.setInt(1, id);
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next() ? resultSet.getString(1) : null;
            }
        }
    }

    private Connection connect(String url) throws SQLException {
        return DriverManager.getConnection(url);
    }

    private Connection connectUnchecked(String url) {
        try {
            return connect(url);
        } catch (SQLException exception) {
            throw new IllegalStateException(
                    "Testdatenbank konnte nicht geöffnet werden.",
                    exception
            );
        }
    }
}
