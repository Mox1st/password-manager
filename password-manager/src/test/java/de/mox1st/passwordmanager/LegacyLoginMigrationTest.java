package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.database.UserRepository;
import de.mox1st.passwordmanager.security.PasswordHasher;
import de.mox1st.passwordmanager.service.LoginService;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class LegacyLoginMigrationTest {
    @Test
    public void successfulLegacyLoginMigratesHashAndAllowsSubsequentLogin()
            throws Exception {
        Path database = Files.createTempFile("password-manager-legacy-login-", ".db");
        try {
            String url = database.toString();
            setupSchema(url);
            String password = "TEST_ONLY_LEGACY_MASTER_PASSWORD";
            String legacyHash = legacyHash(password);
            insertUser(url, legacyHash);
            LoginService login = loginService(url);

            assertTrue(login.checkLogin("legacy-user", password));
            String migratedHash = readHash(url);
            PasswordHasher hasher = new PasswordHasher();
            assertFalse(hasher.isLegacySha256Hash(migratedHash));
            assertTrue(hasher.isPbkdf2Hash(migratedHash));
            assertTrue(login.checkLogin("legacy-user", password));
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void wrongPasswordDoesNotMigrateLegacyHash() throws Exception {
        Path database = Files.createTempFile("password-manager-legacy-wrong-", ".db");
        try {
            String url = database.toString();
            setupSchema(url);
            String legacyHash = legacyHash("legacy-master-value");
            insertUser(url, legacyHash);
            LoginService login = loginService(url);

            assertFalse(login.checkLogin("legacy-user", "wrong-password"));
            assertTrue(readHash(url).equals(legacyHash));
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void failedHashUpdateDoesNotReportSuccessfulLogin() throws Exception {
        Path database = Files.createTempFile("password-manager-legacy-update-failure-", ".db");
        try {
            String url = database.toString();
            setupSchema(url);
            String password = "TEST_ONLY_LEGACY_MASTER_PASSWORD";
            String legacyHash = legacyHash(password);
            insertUser(url, legacyHash);
            try (Connection connection = connect(url);
                 Statement statement = connection.createStatement()) {
                statement.execute("""
                        CREATE TRIGGER fail_legacy_hash_migration
                        BEFORE UPDATE OF password ON users
                        BEGIN SELECT RAISE(ABORT, 'migration failure'); END
                        """);
            }

            try {
                loginService(url).checkLogin("legacy-user", password);
                fail("Ein fehlgeschlagenes Hash-Update darf keinen erfolgreichen Login liefern.");
            } catch (IllegalStateException expected) {
                assertTrue(readHash(url).equals(legacyHash));
            }
        } finally {
            Files.deleteIfExists(database);
        }
    }

    private LoginService loginService(String url) {
        UserRepository users = new UserRepository(() -> connectUnchecked(url));
        return new LoginService(users, () -> connectUnchecked(url));
    }

    private void setupSchema(String url) throws Exception {
        try (Connection connection = connect(url);
             Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                    )
                    """);
        }
    }

    private void insertUser(String url, String hash) throws Exception {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement(
                     "INSERT INTO users(username, password) VALUES (?, ?)")) {
            statement.setString(1, "legacy-user");
            statement.setString(2, hash);
            statement.executeUpdate();
        }
    }

    private String readHash(String url) throws Exception {
        try (Connection connection = connect(url);
             var statement = connection.prepareStatement(
                     "SELECT password FROM users WHERE username = ?")) {
            statement.setString(1, "legacy-user");
            try (var result = statement.executeQuery()) {
                result.next();
                return result.getString(1);
            }
        }
    }

    private String legacyHash(String password) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(password.getBytes(StandardCharsets.UTF_8));
        StringBuilder hash = new StringBuilder();
        for (byte value : digest) {
            hash.append(String.format("%02x", value));
        }
        return hash.toString();
    }

    private Connection connect(String url) throws Exception {
        return DriverManager.getConnection("jdbc:sqlite:" + url);
    }

    private Connection connectUnchecked(String url) {
        try {
            return connect(url);
        } catch (Exception exception) {
            throw new IllegalStateException("Testdatenbank konnte nicht geöffnet werden.", exception);
        }
    }
}
