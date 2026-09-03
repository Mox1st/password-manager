package de.mox1st.passwordmanager.model;

public final class BackupEntry {

    private final String website;
    private final String username;
    private final String password;

    public BackupEntry(String website, String username, String password) {
        this.website = requireValue(website, "Die Website darf nicht leer sein.");
        this.username = requireValue(username, "Der Benutzername darf nicht leer sein.");
        this.password = requireValue(password, "Das Passwort darf nicht leer sein.");
    }

    public String getWebsite() {
        return website;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    private String requireValue(String value, String message) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(message);
        }
        return value;
    }
}
