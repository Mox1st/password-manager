package de.mox1st.passwordmanager.database;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseConnection {

    private static final Path DATABASE_PATH = getDatabasePath();
    private static final String URL = "jdbc:sqlite:" + DATABASE_PATH;

    private static Path getDatabasePath() {
        Path appDataDirectory = Paths.get(
                System.getProperty("user.home"),
                "Library",
                "Application Support",
                "Password Manager"
        );

        try {
            Files.createDirectories(appDataDirectory);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Der Anwendungsordner konnte nicht erstellt werden.",
                    e
            );
        }

        return appDataDirectory.resolve("passwordmanager.db");
    }

    public static Connection connect() {
        Connection connection = null;

        try {
            connection = DriverManager.getConnection(URL);

            try (var statement = connection.createStatement()) {
                statement.execute("PRAGMA foreign_keys = ON");
            }

            return connection;

        } catch (SQLException e) {
            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException closeException) {
                    e.addSuppressed(closeException);
                }
            }

            throw new IllegalStateException(
                    "Die Datenbankverbindung konnte nicht hergestellt werden.",
                    e
            );
        }
    }

    public static void createTables() {

        String sql = """
                CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
                );
                """;

        String passwordEntrysql = """
                CREATE TABLE IF NOT EXISTS password_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
                );
                """;

        String userSecuritySql = """
                CREATE TABLE IF NOT EXISTS user_security (
                user_id INTEGER PRIMARY KEY,
                key_salt BLOB NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
                );
                """;

        try (Connection connection = connect();
             var statement = connection.createStatement()) {

            statement.execute(sql);
            statement.execute(passwordEntrysql);
            statement.execute(userSecuritySql);

        } catch (SQLException e) {
            throw new IllegalStateException(
                    "Die Datenbanktabellen konnten nicht erstellt werden.",
                    e
            );
        }
    }
}