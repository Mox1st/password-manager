package de.mox1st.passwordmanager.service;

import de.mox1st.passwordmanager.model.User;
import de.mox1st.passwordmanager.database.UserRepository;
import de.mox1st.passwordmanager.security.PasswordHasher;
import java.security.GeneralSecurityException;
import de.mox1st.passwordmanager.database.PasswordEntryRepository;
import de.mox1st.passwordmanager.database.DatabaseConnection;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.function.Supplier;


public class LoginService {

    private UserRepository userRepository;
    private PasswordHasher passwordHasher;
    private final Supplier<Connection> connectionSupplier;

//übernimmt den Benutzer von außen. 
    public LoginService(UserRepository userRepository){
        this.userRepository = userRepository;

        passwordHasher = new PasswordHasher();
        connectionSupplier = DatabaseConnection::connect;
    }

    public LoginService(
            UserRepository userRepository,
            Supplier<Connection> connectionSupplier) {
        this.userRepository = userRepository;
        passwordHasher = new PasswordHasher();
        this.connectionSupplier = connectionSupplier;
    }
    //Methode
    public boolean checkLogin(String username, String password){

        User user = userRepository.findUser(username);

        if (user == null){
            return false;
        }

        if (!passwordHasher.matches(password, user.getPassword())) {
            return false;
        }

        if (passwordHasher.isLegacySha256Hash(user.getPassword())) {
            if (!userRepository.updatePasswordHash(
                    user.getId(),
                    passwordHasher.hashPassword(password))) {
                throw new IllegalStateException(
                        "Der Passwort-Hash konnte nicht aktualisiert werden."
                );
            }
        }
        return true;
    }

    public boolean userExists(String username){

        return userRepository.userExists(username);
    }

    public User getUser(String username){
        return userRepository.findUser(username);
    }

    public EncryptionSession createEncryptionSession(
            User user,
            String masterPassword) throws GeneralSecurityException {
        byte[] salt = userRepository.findKeySalt(user.getId());

        if (salt == null) {
            salt = userRepository.generateKeySalt();
            if (!userRepository.saveKeySalt(user.getId(), salt)) {
                throw new IllegalStateException(
                        "Der Encryption-Salt konnte nicht gespeichert werden."
                );
            }
        }

        PasswordEncryptionService encryptionService =
                new PasswordEncryptionService();
        return new EncryptionSession(
                encryptionService.deriveKey(masterPassword, salt)
        );
    }

    public EncryptionSession changeMasterPassword(
            User user,
            String currentMasterPassword,
            String newMasterPassword,
            EncryptionSession currentEncryptionSession) {
        if (user == null || currentEncryptionSession == null) {
            throw new IllegalArgumentException(
                    "Benutzer und aktuelle Verschlüsselungssitzung sind erforderlich."
            );
        }
        if (!passwordHasher.matches(
                currentMasterPassword,
                user.getPassword())) {
            throw new IllegalArgumentException(
                    "Das aktuelle Masterpasswort ist falsch."
            );
        }
        if (newMasterPassword == null || newMasterPassword.isEmpty()) {
            throw new IllegalArgumentException(
                    "Das neue Masterpasswort darf nicht leer sein."
            );
        }

        EncryptionSession newEncryptionSession = null;
        boolean committed = false;
        try (Connection connection = connectionSupplier.get()) {
            if (connection == null) {
                throw new IllegalStateException(
                        "Die Datenbankverbindung konnte nicht hergestellt werden."
                );
            }

            byte[] salt = userRepository.findKeySalt(connection, user.getId());
            if (salt == null) {
                throw new IllegalStateException(
                        "Für den Benutzer ist kein Encryption-Salt vorhanden."
                );
            }

            PasswordEncryptionService encryptionService =
                    new PasswordEncryptionService();
            newEncryptionSession = new EncryptionSession(
                    encryptionService.deriveKey(newMasterPassword, salt)
            );
            String newPasswordHash = passwordHasher.hashPassword(newMasterPassword);

            boolean originalAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try {
                new PasswordEntryRepository(currentEncryptionSession)
                        .rekeyEntriesForUser(
                                user.getId(),
                                currentEncryptionSession,
                                newEncryptionSession,
                                connection
                        );
                if (!userRepository.updatePasswordHash(
                        connection,
                        user.getId(),
                        newPasswordHash)) {
                    throw new IllegalStateException(
                            "Der Passwort-Hash konnte nicht aktualisiert werden."
                    );
                }
                connection.commit();
                committed = true;
                currentEncryptionSession.clear();
            } catch (SQLException | RuntimeException exception) {
                if (!committed) {
                    try {
                        connection.rollback();
                    } catch (SQLException rollbackException) {
                        exception.addSuppressed(rollbackException);
                    }
                }
                throw exception;
            } finally {
                try {
                    connection.setAutoCommit(originalAutoCommit);
                } catch (SQLException exception) {
                    throw new IllegalStateException(
                            "Die Datenbanktransaktion konnte nicht abgeschlossen werden.",
                            exception
                    );
                }
            }
            return newEncryptionSession;
        } catch (GeneralSecurityException | SQLException exception) {
            if (!committed && newEncryptionSession != null) {
                newEncryptionSession.clear();
            }
            throw new IllegalStateException(
                    "Das Masterpasswort konnte nicht geändert werden.",
                    exception
            );
        } catch (RuntimeException exception) {
            if (!committed && newEncryptionSession != null) {
                newEncryptionSession.clear();
            }
            throw exception;
        }
    }

}
