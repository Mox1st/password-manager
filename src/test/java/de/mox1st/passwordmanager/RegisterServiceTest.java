package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.database.UserRepository;
import de.mox1st.passwordmanager.service.RegisterService;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RegisterServiceTest {
    @Test
    public void rejectsWeakOrShortMasterPasswordWithoutCreatingUser() throws Exception {
        Path database = Files.createTempFile("password-manager-register-weak-", ".db");
        try {
            String url = database.toString();
            createUsersTable(url);
            RegisterService service = service(url);

            assertFalse(service.register("weak-user", "Ab1!"));
            assertFalse(service.register("short-user", "Ab1!xyz"));
            assertTrue(countUsers(url) == 0);
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void acceptsStrongMasterPasswordAndExistingRegistrationStillWorks() throws Exception {
        Path database = Files.createTempFile("password-manager-register-valid-", ".db");
        try {
            String url = database.toString();
            createUsersTable(url);
            RegisterService service = service(url);

            assertTrue(service.register("valid-user", "Strong1!"));
            assertFalse(service.register("valid-user", "Another1!"));
            assertTrue(countUsers(url) == 1);
        } finally {
            Files.deleteIfExists(database);
        }
    }

    @Test
    public void handlesUsernameConstraintRaceAsDuplicate() {
        UserRepository repository = new UserRepository(() -> {
            throw new IllegalStateException("Nicht verwendet");
        }) {
            @Override
            public boolean userExists(String username) {
                return false;
            }

            @Override
            public void saveUser(de.mox1st.passwordmanager.model.User user) {
                throw new IllegalStateException(
                        "Der Benutzer konnte nicht gespeichert werden.",
                        new SQLException("UNIQUE constraint failed: users.username")
                );
            }
        };

        assertFalse(new RegisterService(repository).register(
                "racing-user",
                "Strong1!"
        ));
    }

    private RegisterService service(String url) {
        return new RegisterService(new UserRepository(() -> connectUnchecked(url)));
    }

    private void createUsersTable(String url) throws Exception {
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

    private int countUsers(String url) throws Exception {
        try (Connection connection = connect(url);
             Statement statement = connection.createStatement();
             var result = statement.executeQuery("SELECT COUNT(*) FROM users")) {
            result.next();
            return result.getInt(1);
        }
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
