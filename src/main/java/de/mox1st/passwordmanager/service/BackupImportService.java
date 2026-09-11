package de.mox1st.passwordmanager.service;

import de.mox1st.passwordmanager.database.DatabaseConnection;
import de.mox1st.passwordmanager.database.PasswordEntryRepository;
import de.mox1st.passwordmanager.database.UserRepository;
import de.mox1st.passwordmanager.model.BackupContainer;
import de.mox1st.passwordmanager.model.BackupEntry;
import de.mox1st.passwordmanager.model.BackupPayload;
import de.mox1st.passwordmanager.model.PasswordEntry;
import de.mox1st.passwordmanager.model.User;
import de.mox1st.passwordmanager.security.PasswordHasher;

import java.security.GeneralSecurityException;
import java.sql.Connection;

public class BackupImportService {
    private static final int KEY_SALT_LENGTH_BYTES = 16;

    private final UserRepository userRepository;
    private final PasswordEncryptionService passwordEncryptionService;
    private final BackupEncryptionService backupEncryptionService;
    private final PasswordHasher passwordHasher;
    private final java.util.function.Supplier<Connection> connectionSupplier;

    public BackupImportService() {
        this(
                new UserRepository(),
                new PasswordEncryptionService(),
                new BackupEncryptionService(),
                new PasswordHasher(),
                DatabaseConnection::connect
        );
    }

    public BackupImportService(
            UserRepository userRepository,
            PasswordEncryptionService passwordEncryptionService,
            BackupEncryptionService backupEncryptionService,
            PasswordHasher passwordHasher,
            java.util.function.Supplier<Connection> connectionSupplier) {
        this.userRepository = userRepository;
        this.passwordEncryptionService = passwordEncryptionService;
        this.backupEncryptionService = backupEncryptionService;
        this.passwordHasher = passwordHasher;
        this.connectionSupplier = connectionSupplier;
    }

    public BackupImportService(
            UserRepository userRepository,
            PasswordEncryptionService passwordEncryptionService,
            BackupEncryptionService backupEncryptionService,
            java.util.function.Supplier<Connection> connectionSupplier) {
        this(
                userRepository,
                passwordEncryptionService,
                backupEncryptionService,
                new PasswordHasher(),
                connectionSupplier
        );
    }

    public EncryptionSession importBackup(
            BackupContainer container,
            String backupPassword,
            String newMasterPassword) throws GeneralSecurityException {
        BackupPayload payload = backupEncryptionService.decrypt(
                container,
                backupPassword
        );
        validatePayload(payload);
        if (newMasterPassword == null || newMasterPassword.isEmpty()) {
            throw new IllegalArgumentException(
                    "Das neue Masterpasswort darf nicht leer sein."
            );
        }

        EncryptionSession importedSession = new EncryptionSession(
                passwordEncryptionService.deriveKey(
                        newMasterPassword,
                        payload.getKeySalt()
                )
        );
        String newPasswordHash = passwordHasher.hashPassword(newMasterPassword);

        try (Connection connection = connectionSupplier.get()) {
            if (connection == null) {
                importedSession.clear();
                throw new IllegalStateException(
                        "Die Datenbankverbindung konnte nicht hergestellt werden."
                );
            }
            boolean originalAutoCommit = connection.getAutoCommit();
            boolean transactionStarted = false;
            boolean committed = false;
            try {
                connection.setAutoCommit(false);
                transactionStarted = true;
                if (userRepository.findUser(connection, payload.getUsername()) != null) {
                    throw new IllegalStateException(
                            "Der Benutzername existiert bereits."
                    );
                }

                int userId = userRepository.saveUser(
                        connection,
                        new User(payload.getUsername(), newPasswordHash)
                );
                if (!userRepository.saveKeySalt(
                        connection,
                        userId,
                        payload.getKeySalt()
                )) {
                    throw new IllegalStateException(
                            "Der Encryption-Salt konnte nicht gespeichert werden."
                    );
                }

                PasswordEntryRepository entryRepository =
                        new PasswordEntryRepository(
                                importedSession,
                                connectionSupplier
                        );
                for (BackupEntry entry : payload.getEntries()) {
                    entryRepository.saveEntry(
                            connection,
                            new PasswordEntry(
                                    0,
                                    userId,
                                    entry.getWebsite(),
                                    entry.getUsername(),
                                    entry.getPassword()
                            )
                    );
                }
                connection.commit();
                committed = true;
                return importedSession;
            } catch (RuntimeException | java.sql.SQLException exception) {
                if (transactionStarted) {
                    try {
                        connection.rollback();
                    } catch (java.sql.SQLException rollbackException) {
                        exception.addSuppressed(rollbackException);
                    }
                }
                importedSession.clear();
                throw exception instanceof RuntimeException runtimeException
                        ? runtimeException
                        : new IllegalStateException(
                                "Der Backup-Import ist fehlgeschlagen.",
                                exception
                        );
            } finally {
                if (!committed
                        && !connection.isClosed()
                        && connection.getAutoCommit() != originalAutoCommit) {
                    connection.setAutoCommit(originalAutoCommit);
                }
            }
        } catch (java.sql.SQLException exception) {
            importedSession.clear();
            throw new IllegalStateException(
                    "Der Backup-Import ist fehlgeschlagen.",
                    exception
            );
        }
    }

    private void validatePayload(BackupPayload payload) {
        if (payload == null
                || payload.getUsername() == null
                || payload.getUsername().isEmpty()
                || payload.getPasswordHash() == null
                || payload.getPasswordHash().isEmpty()
                || payload.getKeySalt() == null
                || payload.getKeySalt().length != KEY_SALT_LENGTH_BYTES
                || payload.getEntries() == null) {
            throw new IllegalArgumentException("Der Backup-Payload ist ungültig.");
        }
        for (BackupEntry entry : payload.getEntries()) {
            if (entry == null
                    || entry.getWebsite() == null
                    || entry.getWebsite().isEmpty()
                    || entry.getUsername() == null
                    || entry.getUsername().isEmpty()
                    || entry.getPassword() == null
                    || entry.getPassword().isEmpty()) {
                throw new IllegalArgumentException(
                        "Ein Backup-Eintrag ist ungültig."
                );
            }
        }
    }
}
