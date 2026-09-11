package de.mox1st.passwordmanager.model;

public final class BackupContainer {

    public static final int CURRENT_FORMAT_VERSION = 1;

    private final int formatVersion;
    private final String kdfAlgorithm;
    private final int kdfIterations;
    private final byte[] backupSalt;
    private final String encryptionAlgorithm;
    private final byte[] nonce;
    private final byte[] encryptedPayload;

    public BackupContainer(
            int formatVersion,
            String kdfAlgorithm,
            int kdfIterations,
            byte[] backupSalt,
            String encryptionAlgorithm,
            byte[] nonce,
            byte[] encryptedPayload) {
        this.formatVersion = formatVersion;
        this.kdfAlgorithm = requireValue(
                kdfAlgorithm,
                "Der KDF-Algorithmus darf nicht leer sein."
        );
        if (kdfIterations <= 0) {
            throw new IllegalArgumentException(
                    "Die KDF-Iterationszahl muss positiv sein."
            );
        }
        this.kdfIterations = kdfIterations;
        this.backupSalt = requireBytes(backupSalt, "Der Backup-Salt darf nicht null sein.");
        this.encryptionAlgorithm = requireValue(
                encryptionAlgorithm,
                "Der Verschlüsselungsalgorithmus darf nicht leer sein."
        );
        this.nonce = requireBytes(nonce, "Die Nonce darf nicht null sein.");
        this.encryptedPayload = requireBytes(
                encryptedPayload,
                "Der verschlüsselte Payload darf nicht null sein."
        );
    }

    public int getFormatVersion() {
        return formatVersion;
    }

    public String getKdfAlgorithm() {
        return kdfAlgorithm;
    }

    public int getKdfIterations() {
        return kdfIterations;
    }

    public byte[] getBackupSalt() {
        return backupSalt.clone();
    }

    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public byte[] getNonce() {
        return nonce.clone();
    }

    public byte[] getEncryptedPayload() {
        return encryptedPayload.clone();
    }

    private String requireValue(String value, String message) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(message);
        }
        return value;
    }

    private byte[] requireBytes(byte[] value, String message) {
        if (value == null) {
            throw new IllegalArgumentException(message);
        }
        return value.clone();
    }
}
