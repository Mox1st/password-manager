package de.mox1st.passwordmanager.service;

import de.mox1st.passwordmanager.database.PasswordEntryRepository;
import de.mox1st.passwordmanager.database.UserRepository;
import de.mox1st.passwordmanager.database.DatabaseConnection;
import de.mox1st.passwordmanager.model.BackupContainer;
import de.mox1st.passwordmanager.model.BackupEntry;
import de.mox1st.passwordmanager.model.BackupPayload;
import de.mox1st.passwordmanager.model.PasswordEntry;
import de.mox1st.passwordmanager.model.User;

import java.util.ArrayList;
import java.util.List;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public class BackupService {

    private final UserRepository userRepository;
    private final PasswordEntryRepository passwordEntryRepository;
    private final BackupEncryptionService backupEncryptionService;

    public BackupService() {
        this(
                new UserRepository(),
                new PasswordEntryRepository(null, DatabaseConnection::connect),
                new BackupEncryptionService()
        );
    }

    public BackupService(
            UserRepository userRepository,
            PasswordEntryRepository passwordEntryRepository,
            BackupEncryptionService backupEncryptionService) {
        this.userRepository = userRepository;
        this.passwordEntryRepository = passwordEntryRepository;
        this.backupEncryptionService = backupEncryptionService;
    }

    public BackupContainer exportUser(
            User authenticatedUser,
            String masterPassword,
            EncryptionSession encryptionSession) {
        if (authenticatedUser == null) {
            throw new IllegalArgumentException(
                    "Für den Export ist ein authentifizierter Benutzer erforderlich."
            );
        }
        int userId = authenticatedUser.getId();
        if (encryptionSession == null) {
            throw new IllegalStateException(
                    "Für den Export ist eine aktive Sitzung erforderlich."
            );
        }
        encryptionSession.getKey();

        User user = userRepository.findUserById(userId);
        if (user == null) {
            throw new IllegalArgumentException("Der Benutzer wurde nicht gefunden.");
        }
        if (user.getId() != authenticatedUser.getId()
                || !user.getUsername().equals(authenticatedUser.getUsername())) {
            throw new IllegalStateException(
                    "Der authentifizierte Benutzer ist ungültig."
            );
        }

        byte[] keySalt = userRepository.findKeySalt(userId);
        if (keySalt == null) {
            throw new IllegalStateException(
                    "Für den Benutzer ist kein Encryption-Salt vorhanden."
            );
        }
        try {
            byte[] expectedKey = new PasswordEncryptionService()
                    .deriveKey(masterPassword, keySalt)
                    .getEncoded();
            if (!MessageDigest.isEqual(
                    expectedKey,
                    encryptionSession.getKey().getEncoded())) {
                throw new IllegalArgumentException(
                        "Die Verschlüsselungssitzung gehört nicht zum Benutzer."
                );
            }
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "Die Verschlüsselungssitzung konnte nicht geprüft werden.",
                    exception
            );
        }

        List<BackupEntry> backupEntries = new ArrayList<>();
        for (PasswordEntry entry :
                passwordEntryRepository.findEntriesByUserId(userId, encryptionSession)) {
            if (entry.getUserId() != userId) {
                throw new IllegalStateException(
                        "Ein Passwort-Eintrag gehört zu einem anderen Benutzer."
                );
            }
            backupEntries.add(new BackupEntry(
                    entry.getWebsite(),
                    entry.getUser(),
                    entry.getPassword()
            ));
        }

        BackupPayload payload = new BackupPayload(
                user.getUsername(),
                user.getPassword(),
                keySalt,
                backupEntries
        );
        try {
            return backupEncryptionService.encrypt(payload, masterPassword);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "Das Backup konnte nicht verschlüsselt werden.",
                    exception
            );
        }
    }

    /**
     * User IDs alone do not establish authentication and cannot authorize an export.
     */
    public BackupContainer exportUser(
            int userId,
            String masterPassword,
            EncryptionSession encryptionSession) {
        throw new IllegalArgumentException(
                "Der Export benötigt einen authentifizierten Benutzerkontext."
        );
    }
}
