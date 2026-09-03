package de.mox1st.passwordmanager.database;

import de.mox1st.passwordmanager.model.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.security.SecureRandom;
import java.util.function.Supplier;

public class UserRepository {
  private static final int KEY_SALT_LENGTH_BYTES = 16;
  private final SecureRandom secureRandom = new SecureRandom();
  private final Supplier<Connection> connectionSupplier;

  public UserRepository() {
    this(DatabaseConnection::connect);
  }

  public UserRepository(Supplier<Connection> connectionSupplier) {
    this.connectionSupplier = connectionSupplier;
  }

  public User findUser(String username) {       //Benutzer aus SQLite lesen.

    String sql = """
            SELECT id, username, password
            FROM users
            WHERE username = ?
            """;

    try (Connection connection = connectionSupplier.get();
         PreparedStatement statement = connection.prepareStatement(sql)) {

        statement.setString(1, username);

        try (var resultSet = statement.executeQuery()) {
            if (resultSet.next()) {
                int foundId = resultSet.getInt("id");
                String foundUsername = resultSet.getString("username");
                String foundPassword = resultSet.getString("password");
                return new User(foundId, foundUsername, foundPassword);
            }
        }

    } catch (SQLException e) {
        throw new IllegalStateException(
                "Der Benutzer konnte nicht geladen werden.",
                e
        );
    }

    return null;
}

    public User findUser(Connection connection, String username) {
        String sql = """
                SELECT id, username, password
                FROM users
                WHERE username = ?
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, username);
            try (var resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return new User(
                            resultSet.getInt("id"),
                            resultSet.getString("username"),
                            resultSet.getString("password")
                    );
                }
                return null;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException(
                    "Der Benutzer konnte nicht geprüft werden.",
                    exception
            );
        }
    }

    public int saveUser(Connection connection, User user) {
        if (connection == null || user == null
                || user.getUsername() == null || user.getUsername().isEmpty()
                || user.getPassword() == null || user.getPassword().isEmpty()) {
            throw new IllegalArgumentException("Die Benutzerdaten sind ungültig.");
        }
        String sql = """
                INSERT INTO users (username, password)
                VALUES (?, ?)
                """;
        try (PreparedStatement statement = connection.prepareStatement(
                sql, Statement.RETURN_GENERATED_KEYS)) {
            statement.setString(1, user.getUsername());
            statement.setString(2, user.getPassword());
            if (statement.executeUpdate() != 1) {
                throw new IllegalStateException("Der Benutzer konnte nicht gespeichert werden.");
            }
            try (var keys = statement.getGeneratedKeys()) {
                if (keys.next()) {
                    return keys.getInt(1);
                }
            }
            throw new IllegalStateException("Die Benutzer-ID konnte nicht ermittelt werden.");
        } catch (SQLException exception) {
            throw new IllegalStateException(
                    "Der Benutzer konnte nicht gespeichert werden.",
                    exception
            );
        }
    }

    public User findUserById(int userId) {
        String sql = """
                SELECT id, username, password
                FROM users
                WHERE id = ?
                """;
        try (Connection connection = connectionSupplier.get();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, userId);
            try (var resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return new User(
                            resultSet.getInt("id"),
                            resultSet.getString("username"),
                            resultSet.getString("password")
                    );
                }
            }

            return null;
        } catch (SQLException exception) {
            throw new IllegalStateException(
                    "Der Benutzer konnte nicht geladen werden.",
                    exception
            );
        }
    }

    public User findUserByIdWithinConnection(Connection connection, int userId) {
        String sql = """
                SELECT id, username, password
                FROM users
                WHERE id = ?
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, userId);
            try (var resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return new User(
                            resultSet.getInt("id"),
                            resultSet.getString("username"),
                            resultSet.getString("password")
                    );
                }
                return null;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException(
                    "Der Benutzer konnte nicht geladen werden.",
                    exception
            );
        }
    }

    public void saveUser(User user){        //Benutzer in SQLite speichern.

        String sql = """
                INSERT INTO users (username, password)
                VALUES (?, ?)
                """;

        try(Connection connection = connectionSupplier.get();
            PreparedStatement statement = connection.prepareStatement(sql)){
                statement.setString(1, user.getUsername());
                statement.setString(2, user.getPassword());

                statement.executeUpdate();

            } catch (SQLException e){
                throw new IllegalStateException(
                        "Der Benutzer konnte nicht gespeichert werden.",
                        e
                );
            }
    }

            public boolean updatePasswordHash(int userId, String newHash) {
                try (Connection connection = connectionSupplier.get()) {
                    return updatePasswordHash(connection, userId, newHash);
                } catch (SQLException exception) {
                    throw new IllegalStateException(
                            "Der Passwort-Hash konnte nicht aktualisiert werden.",
                            exception
                    );
                }
            }

            public boolean updatePasswordHash(
                    Connection connection,
                    int userId,
                    String newHash) {
                if (newHash == null || newHash.isEmpty()) {
                    throw new IllegalArgumentException("Der Passwort-Hash ist ungültig.");
                }

                String sql = """
                        UPDATE users
                        SET password = ?
                        WHERE id = ?
                        """;
                try (PreparedStatement statement = connection.prepareStatement(sql)) {
                    statement.setString(1, newHash);
                    statement.setInt(2, userId);
                    return statement.executeUpdate() == 1;
                } catch (SQLException exception) {
                    throw new IllegalStateException(
                            "Der Passwort-Hash konnte nicht aktualisiert werden.",
                            exception
                    );
                }
            }

    public boolean userExists(String username) {        //prüfen, ob bentuzer bereits existiert.

        String sql = """
                SELECT 1
                FROM users
                WHERE username = ? 
                """;

        try (Connection connection = connectionSupplier.get();
            PreparedStatement statement = connection.prepareStatement(sql)){

                statement.setString(1, username);

                try (var resultSet = statement.executeQuery()) {
                    return resultSet.next();
                }

            } catch (SQLException e){
                throw new IllegalStateException(
                        "Der Benutzer konnte nicht geprüft werden.",
                        e
                );
            }
    }

    public byte[] generateKeySalt() {
            byte[] salt = new byte[KEY_SALT_LENGTH_BYTES];
            secureRandom.nextBytes(salt);
            return salt;
    }

    public boolean saveKeySalt(int userId, byte[] salt) {
            if (salt == null || salt.length != KEY_SALT_LENGTH_BYTES) {
              throw new IllegalArgumentException("Der Salt muss 16 Byte lang sein.");
            }

            String sql = """
                    INSERT OR IGNORE INTO user_security (user_id, key_salt)
                    VALUES (?, ?)
                    """;

            try (Connection connection = connectionSupplier.get();
                 PreparedStatement statement = connection.prepareStatement(sql)) {
              statement.setInt(1, userId);
              statement.setBytes(2, salt);
              return statement.executeUpdate() == 1;
            } catch (SQLException e) {
              throw new IllegalStateException(
                      "Der Encryption-Salt konnte nicht gespeichert werden.",
                      e
              );
            }

    }

    public boolean saveKeySalt(Connection connection, int userId, byte[] salt) {
        if (connection == null) {
            throw new IllegalArgumentException("Die Datenbankverbindung darf nicht null sein.");
        }

        if (salt == null || salt.length != KEY_SALT_LENGTH_BYTES) {
            throw new IllegalArgumentException("Der Salt muss 16 Byte lang sein.");
        }

        String sql = """
                INSERT INTO user_security (user_id, key_salt)
                VALUES (?, ?)
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, userId);
            statement.setBytes(2, salt);
            return statement.executeUpdate() == 1;
        } catch (SQLException exception) {
            throw new IllegalStateException(
                    "Der Encryption-Salt konnte nicht gespeichert werden.",
                    exception
            );
        }

    }

    public boolean updateKeySalt(Connection connection, int userId, byte[] salt) {
        if (connection == null) {
            throw new IllegalArgumentException("Die Datenbankverbindung darf nicht null sein.");
        }
        if (salt == null || salt.length != KEY_SALT_LENGTH_BYTES) {
            throw new IllegalArgumentException("Der Salt muss 16 Byte lang sein.");
        }
        String sql = """
                UPDATE user_security
                SET key_salt = ?
                WHERE user_id = ?
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setBytes(1, salt);
            statement.setInt(2, userId);
            return statement.executeUpdate() == 1;
        } catch (SQLException exception) {
            throw new IllegalStateException(
                    "Der Encryption-Salt konnte nicht aktualisiert werden.",
                    exception
            );
        }
    }

    public byte[] findKeySalt(int userId) {
            try (Connection connection = connectionSupplier.get()) {
              return findKeySalt(connection, userId);
            } catch (SQLException exception) {
              throw new IllegalStateException(
                      "Der Encryption-Salt konnte nicht geladen werden.",
                      exception
              );
            }
    }

    public byte[] findKeySalt(Connection connection, int userId) {
            String sql = """
                    SELECT key_salt
                    FROM user_security
                    WHERE user_id = ?
                    """;

            try (PreparedStatement statement = connection.prepareStatement(sql)) {
              statement.setInt(1, userId);
              try (var resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                  byte[] salt = resultSet.getBytes("key_salt");
                  if (salt == null || salt.length != KEY_SALT_LENGTH_BYTES) {
                    throw new IllegalStateException("Der gespeicherte Salt ist ungültig.");
                  }
                  return salt;
                }
              }
            } catch (SQLException e) {
              throw new IllegalStateException(
                      "Der Encryption-Salt konnte nicht geladen werden.",
                      e
              );
            }

            return null;
    }
}
