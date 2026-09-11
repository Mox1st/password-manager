package de.mox1st.passwordmanager.database;

import de.mox1st.passwordmanager.model.PasswordEntry;
import de.mox1st.passwordmanager.service.EncryptionSession;
import de.mox1st.passwordmanager.service.PasswordEncryptionService;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;
import java.util.ArrayList;
import java.security.GeneralSecurityException;
import java.util.function.Supplier;
import java.sql.ResultSet;
import javax.crypto.SecretKey;

public class PasswordEntryRepository {
    private final EncryptionSession encryptionSession;
    private final Supplier<Connection> connectionSupplier;
    private final PasswordEncryptionService encryptionService =
            new PasswordEncryptionService();

    public PasswordEntryRepository() {
        this(null);
    }

    public PasswordEntryRepository(EncryptionSession encryptionSession) {
        this(encryptionSession, DatabaseConnection::connect);
    }

    public PasswordEntryRepository(
            EncryptionSession encryptionSession,
            Supplier<Connection> connectionSupplier) {
        this.encryptionSession = encryptionSession;
        this.connectionSupplier = connectionSupplier;
    }
    
    public void saveEntry(PasswordEntry entry){

       String sql="""
               INSERT INTO password_entries (user_id, website, username, password)
               VALUES (?, ?, ?, ?)
               """; 

        try (Connection connection = connectionSupplier.get();
            PreparedStatement statement = connection.prepareStatement(sql)){

                statement.setInt(1, entry.getUserId());
                statement.setString(2, entry.getWebsite());
                statement.setString(3, entry.getUser());
                statement.setString(4, encryptPassword(entry.getPassword()));

                statement.executeUpdate();

            } catch (SQLException e){
                throw new IllegalStateException(
                        "Der Passwort-Eintrag konnte nicht gespeichert werden.",
                        e
                );
            }

        }

        public void saveEntry(Connection connection, PasswordEntry entry) {
            if (connection == null || entry == null) {
                throw new IllegalArgumentException(
                        "Verbindung und Passwort-Eintrag dürfen nicht null sein."
                );
            }

            String sql = """
                    INSERT INTO password_entries (user_id, website, username, password)
                    VALUES (?, ?, ?, ?)
                    """;
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setInt(1, entry.getUserId());
                statement.setString(2, entry.getWebsite());
                statement.setString(3, entry.getUser());
                statement.setString(4, encryptPassword(entry.getPassword()));
                if (statement.executeUpdate() != 1) {
                    throw new IllegalStateException(
                            "Der Passwort-Eintrag konnte nicht gespeichert werden."
                    );
                }

            } catch (SQLException exception) {
                throw new IllegalStateException(
                        "Der Passwort-Eintrag konnte nicht gespeichert werden.",
                        exception
                );
            }

        }

        public int deleteEntriesForUser(Connection connection, int userId) {
            if (connection == null) {
                throw new IllegalArgumentException(
                        "Die Datenbankverbindung darf nicht null sein."
                );
            }
            String sql = """
                    DELETE FROM password_entries
                    WHERE user_id = ?
                    """;
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setInt(1, userId);
                return statement.executeUpdate();
            } catch (SQLException exception) {
                throw new IllegalStateException(
                        "Die Passwort-Einträge konnten nicht gelöscht werden.",
                        exception
                );
            }
        }
        public List<PasswordEntry> findEntriesByUserId(int userId){
            if (encryptionSession == null) {
                throw new IllegalStateException(
                        "Zum Entschlüsseln ist eine aktive Sitzung erforderlich."
                );
            }
            return findEntriesByUserId(userId, encryptionSession);
        }

        public List<PasswordEntry> findEntriesByUserId(
                int userId,
                EncryptionSession session) {
            if (session == null) {
                throw new IllegalStateException(
                        "Zum Entschlüsseln ist eine aktive Sitzung erforderlich."
                );
            }
            List<PasswordEntry> entries = new ArrayList<>();

            String sql="""
                    SELECT id, user_id, website, username, password
                    FROM password_entries
                    WHERE user_id = ?
                    """;
            try (Connection connection = connectionSupplier.get();
                PreparedStatement statement = connection.prepareStatement(sql)){

                    statement.setInt(1, userId);
                    try (var resultSet = statement.executeQuery()) {
                        while (resultSet.next()){
                            int id = resultSet.getInt("id");
                            int foundUserId = resultSet.getInt("user_id");
                            String website = resultSet.getString("website");
                            String username = resultSet.getString("username");
                            String storedPassword = resultSet.getString("password");
                            if (storedPassword == null
                                    || !storedPassword.startsWith("v1:")) {
                                throw new IllegalStateException(
                                        "Ein Passwort-Eintrag hat ein unbekanntes Format."
                                );
                            }
                            String password = decryptPassword(storedPassword, session);
                            PasswordEntry entry = new PasswordEntry(
                                id,
                                foundUserId,
                                website,
                                username,
                                password
                            );

                            entries.add(entry);
                        }
                    }



                } catch (SQLException e){
                    throw new IllegalStateException(
                            "Die Passwort-Einträge konnten nicht geladen werden.",
                            e
                    );
                }
            return entries;


        }

        public boolean deleteEntry(int id, int userId){

            //SQL-Anfrage
            String sql="""
                    DELETE FROM password_entries
                    WHERE id = ?
                    AND user_id = ?
                    """;

            try(Connection connection = connectionSupplier.get();
                PreparedStatement statement = connection.prepareStatement(sql)){

                    statement.setInt(1, id);
                    statement.setInt(2, userId);

                    return statement.executeUpdate() == 1;
                
                } catch (SQLException e) {
                    throw new IllegalStateException(
                            "Der Passwort-Eintrag konnte nicht gelöscht werden.",
                            e
                    );
                }
        }
        
        public boolean updateEntry(PasswordEntry entry, int userId){

            String sql ="""
                    UPDATE password_entries
                    SET website = ?, username = ?, password = ?
                    WHERE id = ?
                    AND user_id = ?
                    """;

        try (Connection connection = connectionSupplier.get();
            PreparedStatement statement = connection.prepareStatement(sql)){

                statement.setString (1, entry.getWebsite());
                statement.setString(2, entry.getUser());
                statement.setString(3, encryptPassword(entry.getPassword()));
                statement.setInt(4, entry.getId());
                statement.setInt(5, userId);

                return statement.executeUpdate() == 1;

            } catch (SQLException e){
                throw new IllegalStateException(
                        "Der Passwort-Eintrag konnte nicht aktualisiert werden.",
                        e
                );
            }
        }

        public void migrateLegacyEntriesForUser(
                int userId,
                EncryptionSession encryptionSession) {
            if (encryptionSession == null) {
                throw new IllegalStateException(
                        "Für die Migration ist eine aktive Sitzung erforderlich."
                );
            }

            String selectSql = """
                    SELECT id, password
                    FROM password_entries
                    WHERE user_id = ?
                    """;
            String updateSql = """
                    UPDATE password_entries
                    SET password = ?
                    WHERE id = ?
                      AND user_id = ?
                      AND password NOT LIKE 'v1:%'
                    """;

            try (Connection connection = connectionSupplier.get()) {
                if (connection == null) {
                    throw new IllegalStateException(
                            "Die Datenbankverbindung konnte nicht hergestellt werden."
                    );
                }

                boolean originalAutoCommit = connection.getAutoCommit();
                connection.setAutoCommit(false);
                try {
                    try (PreparedStatement select =
                                 connection.prepareStatement(selectSql);
                         PreparedStatement update =
                                 connection.prepareStatement(updateSql)) {
                        select.setInt(1, userId);

                        try (ResultSet resultSet = select.executeQuery()) {
                            while (resultSet.next()) {
                                int entryId = resultSet.getInt("id");
                                String storedPassword =
                                        resultSet.getString("password");

                                if (storedPassword.startsWith("v1:")) {
                                    continue;
                                }

                                String encryptedPassword =
                                        encryptionService.encrypt(
                                                storedPassword,
                                                encryptionSession.getKey()
                                        );
                                update.setString(1, encryptedPassword);
                                update.setInt(2, entryId);
                                update.setInt(3, userId);
                                update.executeUpdate();
                            }
                        }
                    }
                    connection.commit();
                } catch (GeneralSecurityException | SQLException | RuntimeException exception) {
                    try {
                        connection.rollback();
                    } catch (SQLException rollbackException) {
                        exception.addSuppressed(rollbackException);
                    }
                    throw exception instanceof RuntimeException runtimeException
                            ? runtimeException
                            : new IllegalStateException(
                                    "Die Legacy-Passwörter konnten nicht migriert werden.",
                                    exception
                            );
                } finally {
                    connection.setAutoCommit(originalAutoCommit);
                }
            } catch (SQLException exception) {
                throw new IllegalStateException(
                        "Die Legacy-Passwörter konnten nicht migriert werden.",
                        exception
                );
            }
        }

        public void rekeyEntriesForUser(
                int userId,
                EncryptionSession oldEncryptionSession,
                EncryptionSession newEncryptionSession,
                Connection connection) {
            if (oldEncryptionSession == null || newEncryptionSession == null) {
                throw new IllegalStateException(
                        "Für das Re-Keying sind aktive Sitzungen erforderlich."
                );
            }
            if (connection == null) {
                throw new IllegalStateException(
                        "Für das Re-Keying ist eine Datenbankverbindung erforderlich."
                );
            }

            String selectSql = """
                    SELECT id, password
                    FROM password_entries
                    WHERE user_id = ?
                    """;
            String updateSql = """
                    UPDATE password_entries
                    SET password = ?
                    WHERE id = ?
                      AND user_id = ?
                    """;

            try {
                SecretKey oldKey = oldEncryptionSession.getKey();
                SecretKey newKey = newEncryptionSession.getKey();
                try (PreparedStatement select = connection.prepareStatement(selectSql);
                     PreparedStatement update = connection.prepareStatement(updateSql)) {
                    select.setInt(1, userId);
                    try (ResultSet resultSet = select.executeQuery()) {
                        while (resultSet.next()) {
                            String storedPassword = resultSet.getString("password");
                            if (storedPassword == null
                                    || !storedPassword.startsWith("v1:")) {
                                continue;
                            }

                            String plaintext = encryptionService.decrypt(
                                    storedPassword,
                                    oldKey
                            );
                            String rekeyedPassword = encryptionService.encrypt(
                                    plaintext,
                                    newKey
                            );
                            update.setString(1, rekeyedPassword);
                            update.setInt(2, resultSet.getInt("id"));
                            update.setInt(3, userId);
                            if (update.executeUpdate() != 1) {
                                throw new IllegalStateException(
                                        "Ein Passwort-Eintrag konnte nicht neu verschlüsselt werden."
                                );
                            }
                        }
                    }
                }
            } catch (GeneralSecurityException | SQLException exception) {
                throw new IllegalStateException(
                        "Die Passwort-Einträge konnten nicht neu verschlüsselt werden.",
                        exception
                );
            }
        }

        private String encryptPassword(String password) {
            if (encryptionSession == null) {
                throw new IllegalStateException(
                        "Zum Verschlüsseln ist eine aktive Sitzung erforderlich."
                );
            }

            try {
                return encryptionService.encrypt(
                        password,
                        encryptionSession.getKey()
                );
            } catch (GeneralSecurityException exception) {
                throw new IllegalStateException(
                        "Das Passwort konnte nicht verschlüsselt werden.",
                        exception
                );
            }
        }

        private String decryptPassword(
                String encryptedPassword,
                EncryptionSession session) {
            try {
                return encryptionService.decrypt(
                        encryptedPassword,
                        session.getKey()
                );
            } catch (GeneralSecurityException | IllegalArgumentException exception) {
                throw new IllegalStateException(
                        "Ein Passwort-Eintrag konnte nicht entschlüsselt werden.",
                        exception
                );
            }
        }
    }
    
