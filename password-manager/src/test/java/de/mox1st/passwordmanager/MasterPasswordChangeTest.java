package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.database.UserRepository;
import de.mox1st.passwordmanager.model.User;
import de.mox1st.passwordmanager.security.PasswordHasher;
import de.mox1st.passwordmanager.service.EncryptionSession;
import de.mox1st.passwordmanager.service.LoginService;
import de.mox1st.passwordmanager.service.PasswordEncryptionService;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class MasterPasswordChangeTest {

    @Test
    public void changesHashAndRekeysOnlyCurrentUsersEntries() throws Exception {
        Path database = Files.createTempFile("password-manager-password-change-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            PasswordHasher hasher = new PasswordHasher();
            PasswordEncryptionService encryptionService = new PasswordEncryptionService();
            String oldPassword = "old-master-value";
            String newPassword = "new-master-value";
            User user = new User(1, "user-a", hasher.hashPassword(oldPassword));
            insertUser(url, user);
            insertUser(url, new User(2, "user-b", hasher.hashPassword("other-master")));
            byte[] salt = encryptionService.generateSalt();
            insertSalt(url, 1, salt);
            insertSalt(url, 2, encryptionService.generateSalt());
            EncryptionSession oldSession = session(encryptionService, oldPassword, salt);
            String ownCiphertext = encryptionService.encrypt(
                    "own-password", oldSession.getKey());
            String otherCiphertext = encryptionService.encrypt(
                    "other-password", oldSession.getKey());
            insertEntry(url, 1, 1, ownCiphertext);
            insertEntry(url, 2, 2, otherCiphertext);

            LoginService loginService = new LoginService(
                    new UserRepository(),
                    () -> connectUnchecked(url)
            );
            EncryptionSession newSession = loginService.changeMasterPassword(
                    user, oldPassword, newPassword, oldSession);

            assertTrue(hasher.matches(newPassword, passwordHash(url, 1)));
            assertFalse(hasher.matches(oldPassword, passwordHash(url, 1)));
            assertEquals(
                    "own-password",
                    encryptionService.decrypt(passwordValue(url, 1), newSession.getKey())
            );
            assertEquals(
                    otherCiphertext,
                    passwordValue(url, 2)
            );
            try {
                oldSession.getKey();
                fail("Die alte EncryptionSession hätte invalidiert werden müssen.");
            } catch (IllegalStateException expected) {
                // The old session must be unusable after a successful commit.
            }
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void wrongCurrentPasswordLeavesDataAndSessionUnchanged() throws Exception {
        Path database = Files.createTempFile("password-manager-password-change-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            PasswordHasher hasher = new PasswordHasher();
            User user = new User(1, "user-a", hasher.hashPassword("old-master-value"));
            insertUser(url, user);
            PasswordEncryptionService encryptionService = new PasswordEncryptionService();
            byte[] salt = encryptionService.generateSalt();
            insertSalt(url, 1, salt);
            EncryptionSession session = session(
                    encryptionService, "old-master-value", salt);
            String ciphertext = encryptionService.encrypt("password", session.getKey());
            insertEntry(url, 1, 1, ciphertext);

            LoginService loginService = new LoginService(
                    new UserRepository(), () -> connectUnchecked(url));
            try {
                loginService.changeMasterPassword(
                        user, "wrong-master-value", "new-master-value", session);
                fail("Ein falsches aktuelles Passwort hätte abgelehnt werden müssen.");
            } catch (IllegalArgumentException expected) {
                assertEquals(ciphertext, passwordValue(url, 1));
                assertTrue(hasher.matches("old-master-value", passwordHash(url, 1)));
                assertEquals("password", encryptionService.decrypt(
                        passwordValue(url, 1), session.getKey()));
            }
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void hashUpdateFailureRollsBackRekeying() throws Exception {
        Path database = Files.createTempFile("password-manager-password-change-rollback-", ".db");
        try {
            String url = "jdbc:sqlite:" + database;
            setupSchema(url);
            PasswordHasher hasher = new PasswordHasher();
            User user = new User(1, "user-a", hasher.hashPassword("old-master-value"));
            insertUser(url, user);
            PasswordEncryptionService encryptionService = new PasswordEncryptionService();
            byte[] salt = encryptionService.generateSalt();
            insertSalt(url, 1, salt);
            EncryptionSession oldSession = session(
                    encryptionService, "old-master-value", salt);
            String ciphertext = encryptionService.encrypt("password", oldSession.getKey());
            insertEntry(url, 1, 1, ciphertext);
            try (Connection connection = connect(url);
                 Statement statement = connection.createStatement()) {
                statement.execute("""
                        CREATE TRIGGER fail_password_change
                        BEFORE UPDATE OF password ON users
                        BEGIN
                            SELECT RAISE(ABORT, 'test rollback');
                        END
                        """);
            }

            LoginService loginService = new LoginService(
                    new UserRepository(), () -> connectUnchecked(url));
            try {
                loginService.changeMasterPassword(
                        user, "old-master-value", "new-master-value", oldSession);
                fail("Das Passwort-Ändern hätte fehlschlagen müssen.");
            } catch (IllegalStateException expected) {
                assertEquals(ciphertext, passwordValue(url, 1));
                assertTrue(hasher.matches("old-master-value", passwordHash(url, 1)));
                assertEquals("password", encryptionService.decrypt(
                        passwordValue(url, 1), oldSession.getKey()));
            }
        } finally {
            Files.deleteIfExists(database);
        }
    }

    private EncryptionSession session(
            PasswordEncryptionService service,
            String password,
            byte[] salt) throws Exception {
        return new EncryptionSession(service.deriveKey(password, salt));
    }

    private void setupSchema(String url) throws SQLException {
        try (Connection connection = connect(url);
             Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL
                    )
                    """);
            statement.execute("""
                    CREATE TABLE user_security (
                        user_id INTEGER PRIMARY KEY,
                        key_salt BLOB NOT NULL
                    )
                    """);
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

    private void insertUser(String url, User user) throws SQLException {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement(
                     "INSERT INTO users (id, username, password) VALUES (?, ?, ?)")) {
            statement.setInt(1, user.getId());
            statement.setString(2, user.getUsername());
            statement.setString(3, user.getPassword());
            statement.executeUpdate();
        }
    }

    private void insertSalt(String url, int userId, byte[] salt) throws SQLException {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement(
                     "INSERT INTO user_security (user_id, key_salt) VALUES (?, ?)")) {
            statement.setInt(1, userId);
            statement.setBytes(2, salt);
            statement.executeUpdate();
        }
    }

    private void insertEntry(
            String url,
            int id,
            int userId,
            String password) throws SQLException {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement("""
                     INSERT INTO password_entries
                         (id, user_id, website, username, password)
                     VALUES (?, ?, 'example', 'user', ?)
                     """)) {
            statement.setInt(1, id);
            statement.setInt(2, userId);
            statement.setString(3, password);
            statement.executeUpdate();
        }
    }

    private String passwordValue(String url, int id) throws SQLException {
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

    private String passwordHash(String url, int userId) throws SQLException {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement(
                     "SELECT password FROM users WHERE id = ?")) {
            statement.setInt(1, userId);
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                return resultSet.getString(1);
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
                    "Testdatenbank konnte nicht geöffnet werden.", exception);
        }
    }
}
