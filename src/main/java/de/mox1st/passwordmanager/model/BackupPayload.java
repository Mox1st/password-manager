package de.mox1st.passwordmanager.model;

import java.util.ArrayList;
import java.util.List;

public final class BackupPayload {

    private final String username;
    private final String passwordHash;
    private final byte[] keySalt;
    private final List<BackupEntry> entries;

    public BackupPayload(
            String username,
            String passwordHash,
            byte[] keySalt,
            List<BackupEntry> entries) {
        this.username = requireValue(username, "Der Benutzername darf nicht leer sein.");
        this.passwordHash = requireValue(
                passwordHash,
                "Der Passwort-Hash darf nicht leer sein."
        );
        if (keySalt == null) {
            throw new IllegalArgumentException("Der Key-Salt darf nicht null sein.");
        }
        if (entries == null) {
            throw new IllegalArgumentException("Die Eintragsliste darf nicht null sein.");
        }
        this.keySalt = keySalt.clone();
        this.entries = List.copyOf(new ArrayList<>(entries));
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public byte[] getKeySalt() {
        return keySalt.clone();
    }

    public List<BackupEntry> getEntries() {
        return entries;
    }

    private String requireValue(String value, String message) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(message);
        }
        return value;
    }
}
