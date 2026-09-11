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
import java.util.function.Supplier;

public class BackupRestoreService {
    private static final int KEY_SALT_LENGTH_BYTES = 16;

    private final UserRepository userRepository;
    private final PasswordEntryRepository passwordEntryRepository;
    private final BackupEncryptionService backupEncryptionService;
    private final PasswordEncryptionService passwordEncryptionService;
    private final PasswordHasher passwordHasher;
    private final Supplier<Connection> connectionSupplier;

    public BackupRestoreService() {
        this(
                new UserRepository(),
                new PasswordEntryRepository(),
                new BackupEncryptionService(),
                new PasswordEncryptionService(),
                new PasswordHasher(),
                DatabaseConnection::connect
        );
    }

    public BackupRestoreService(
            UserRepository userRepository,
            PasswordEntryRepository passwordEntryRepository,
            BackupEncryptionService backupEncryptionService,
            PasswordEncryptionService passwordEncryptionService,
            PasswordHasher passwordHasher,
            Supplier<Connection> connectionSupplier) {
        this.userRepository = userRepository;
        this.passwordEntryRepository = passwordEntryRepository;
        this.backupEncryptionService = backupEncryptionService;
        this.passwordEncryptionService = passwordEncryptionService;
        this.passwordHasher = passwordHasher;
        this.connectionSupplier = connectionSupplier;
    }

    public EncryptionSession restore(
            BackupContainer container,
            String backupPassword,
            User currentUser,
            String currentMasterPassword,
            EncryptionSession currentEncryptionSession)
            throws GeneralSecurityException {
        if (currentUser == null || currentEncryptionSession == null) {
            throw new IllegalArgumentException(
                    "Benutzer und aktuelle Verschlüsselungssitzung sind erforderlich."
            );
        }
        currentEncryptionSession.getKey();

        BackupPayload payload = backupEncryptionService.decrypt(
                container,
                backupPassword
        );
        validatePayload(payload);

        if (!currentUser.getUsername().equals(payload.getUsername())) {
            throw new IllegalArgumentException(
                    "Das Backup gehört zu einem anderen Benutzer."
            );
        }
        if (!passwordHasher.matches(
                currentMasterPassword,
                currentUser.getPassword())) {
            throw new IllegalArgumentException(
                    "Das aktuelle Masterpasswort ist falsch."
            );
        }

        EncryptionSession restoredSession = new EncryptionSession(
                passwordEncryptionService.deriveKey(
                        currentMasterPassword,
                        payload.getKeySalt()
                )
        );

        try (Connection connection = connectionSupplier.get()) {
            if (connection == null) {
                restoredSession.clear();
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

                User databaseUser = userRepository.findUserByIdWithinConnection(
                        connection,
                        currentUser.getId()
                );
                if (databaseUser == null
                        || databaseUser.getId() != currentUser.getId()
                        || !databaseUser.getUsername().equals(
                                currentUser.getUsername())
                        || !databaseUser.getPassword().equals(
                                currentUser.getPassword())) {
                    throw new IllegalStateException(
                            "Der authentifizierte Benutzer ist ungültig."
                    );
                }
                if (!userRepository.updateKeySalt(
                        connection,
                        currentUser.getId(),
                        payload.getKeySalt())) {
                    throw new IllegalStateException(
                            "Der Encryption-Salt konnte nicht aktualisiert werden."
                    );
                }

                passwordEntryRepository.deleteEntriesForUser(
                        connection,
                        currentUser.getId()
                );
                PasswordEntryRepository restoredEntries =
                        new PasswordEntryRepository(
                                restoredSession,
                                connectionSupplier
                        );
                for (BackupEntry entry : payload.getEntries()) {
                    restoredEntries.saveEntry(
                            connection,
                            new PasswordEntry(
                                    currentUser.getId(),
                                    entry.getWebsite(),
                                    entry.getUsername(),
                                    entry.getPassword()
                            )
                    );
                }

                connection.commit();
                committed = true;
                currentEncryptionSession.clear();
                return restoredSession;
            } catch (RuntimeException | java.sql.SQLException exception) {
                if (transactionStarted) {
                    try {
                        connection.rollback();
                    } catch (java.sql.SQLException rollbackException) {
                        exception.addSuppressed(rollbackException);
                    }
                }
                restoredSession.clear();
                throw exception instanceof RuntimeException runtimeException
                        ? runtimeException
                        : new IllegalStateException(
                                "Der Restore konnte nicht abgeschlossen werden.",
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
            restoredSession.clear();
            throw new IllegalStateException(
                    "Der Restore konnte nicht abgeschlossen werden.",
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
