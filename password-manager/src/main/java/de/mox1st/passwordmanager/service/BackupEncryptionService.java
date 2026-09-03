package de.mox1st.passwordmanager.service;

import de.mox1st.passwordmanager.model.BackupContainer;
import de.mox1st.passwordmanager.model.BackupEntry;
import de.mox1st.passwordmanager.model.BackupPayload;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class BackupEncryptionService {

    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String ENCRYPTION_ALGORITHM = "AES-256-GCM";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KDF_ITERATIONS = 600_000;
    private static final int MAX_ACCEPTED_ITERATIONS = 2_000_000;
    private static final int SALT_LENGTH_BYTES = 16;
    private static final int NONCE_LENGTH_BYTES = 12;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int PAYLOAD_VERSION = 1;
    private static final int MAX_PAYLOAD_ENTRIES = 1_000_000;
    private static final int MAX_FIELD_BYTES = 16 * 1024 * 1024;

    private final SecureRandom secureRandom = new SecureRandom();

    public BackupContainer encrypt(
            BackupPayload payload,
            String masterPassword) throws GeneralSecurityException {
        if (payload == null) {
            throw new IllegalArgumentException("Der Backup-Payload darf nicht null sein.");
        }
        validateMasterPassword(masterPassword);

        byte[] salt = new byte[SALT_LENGTH_BYTES];
        byte[] nonce = new byte[NONCE_LENGTH_BYTES];
        secureRandom.nextBytes(salt);
        secureRandom.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(
                Cipher.ENCRYPT_MODE,
                deriveKey(masterPassword, salt, KDF_ITERATIONS),
                new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce)
        );

        return new BackupContainer(
                BackupContainer.CURRENT_FORMAT_VERSION,
                KDF_ALGORITHM,
                KDF_ITERATIONS,
                salt,
                ENCRYPTION_ALGORITHM,
                nonce,
                cipher.doFinal(serialize(payload))
        );
    }

    public BackupPayload decrypt(
            BackupContainer container,
            String masterPassword) throws GeneralSecurityException {
        if (container == null) {
            throw new IllegalArgumentException("Der Backup-Container darf nicht null sein.");
        }
        validateMasterPassword(masterPassword);
        validateContainer(container);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(
                Cipher.DECRYPT_MODE,
                deriveKey(masterPassword, container.getBackupSalt(),
                        container.getKdfIterations()),
                new GCMParameterSpec(GCM_TAG_LENGTH_BITS, container.getNonce())
        );

        return deserialize(cipher.doFinal(container.getEncryptedPayload()));
    }

    private void validateContainer(BackupContainer container) {
        if (container.getFormatVersion() != BackupContainer.CURRENT_FORMAT_VERSION) {
            throw new IllegalArgumentException("Die Backup-Version wird nicht unterstützt.");
        }
        if (!KDF_ALGORITHM.equals(container.getKdfAlgorithm())) {
            throw new IllegalArgumentException("Der KDF-Algorithmus ist ungültig.");
        }
        int iterations = container.getKdfIterations();
        if (iterations < KDF_ITERATIONS || iterations > MAX_ACCEPTED_ITERATIONS) {
            throw new IllegalArgumentException("Die KDF-Iterationszahl ist ungültig.");
        }
        if (container.getBackupSalt().length != SALT_LENGTH_BYTES) {
            throw new IllegalArgumentException("Der Backup-Salt ist ungültig.");
        }
        if (!ENCRYPTION_ALGORITHM.equals(container.getEncryptionAlgorithm())) {
            throw new IllegalArgumentException(
                    "Der Verschlüsselungsalgorithmus ist ungültig."
            );
        }
        if (container.getNonce().length != NONCE_LENGTH_BYTES) {
            throw new IllegalArgumentException("Die Nonce ist ungültig.");
        }
        if (container.getEncryptedPayload().length == 0) {
            throw new IllegalArgumentException("Der verschlüsselte Payload ist leer.");
        }
    }

    private SecretKeySpec deriveKey(
            String masterPassword,
            byte[] salt,
            int iterations) throws GeneralSecurityException {
        PBEKeySpec keySpec = new PBEKeySpec(
                masterPassword.toCharArray(),
                salt,
                iterations,
                KEY_LENGTH_BITS
        );
        try {
            byte[] keyBytes = SecretKeyFactory.getInstance(KDF_ALGORITHM)
                    .generateSecret(keySpec)
                    .getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            keySpec.clearPassword();
        }
    }

    private byte[] serialize(BackupPayload payload) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.writeInt(PAYLOAD_VERSION);
            writeString(output, payload.getUsername());
            writeString(output, payload.getPasswordHash());
            writeBytes(output, payload.getKeySalt());
            List<BackupEntry> entries = payload.getEntries();
            output.writeInt(entries.size());
            for (BackupEntry entry : entries) {
                writeString(output, entry.getWebsite());
                writeString(output, entry.getUsername());
                writeString(output, entry.getPassword());
            }
            output.flush();
            return bytes.toByteArray();
        } catch (IOException exception) {
            throw new IllegalStateException("Der Backup-Payload konnte nicht serialisiert werden.", exception);
        }
    }

    private BackupPayload deserialize(byte[] serializedPayload) {
        try {
            DataInputStream input = new DataInputStream(
                    new ByteArrayInputStream(serializedPayload)
            );
            if (input.readInt() != PAYLOAD_VERSION) {
                throw new IllegalArgumentException("Die Payload-Version wird nicht unterstützt.");
            }
            String username = readString(input);
            String passwordHash = readString(input);
            byte[] keySalt = readBytes(input);
            int entryCount = input.readInt();
            if (entryCount < 0 || entryCount > MAX_PAYLOAD_ENTRIES) {
                throw new IllegalArgumentException("Die Anzahl der Backup-Einträge ist ungültig.");
            }

            List<BackupEntry> entries = new ArrayList<>(entryCount);
            for (int index = 0; index < entryCount; index++) {
                entries.add(new BackupEntry(
                        readString(input),
                        readString(input),
                        readString(input)
                ));
            }
            if (input.available() != 0) {
                throw new IllegalArgumentException("Der Backup-Payload enthält zusätzliche Daten.");
            }
            return new BackupPayload(username, passwordHash, keySalt, entries);
        } catch (EOFException exception) {
            throw new IllegalArgumentException("Der Backup-Payload ist unvollständig.", exception);
        } catch (IOException exception) {
            throw new IllegalArgumentException("Der Backup-Payload ist ungültig.", exception);
        }
    }

    private void writeString(DataOutputStream output, String value) throws IOException {
        writeBytes(output, value.getBytes(StandardCharsets.UTF_8));
    }

    private String readString(DataInputStream input) throws IOException {
        return new String(readBytes(input), StandardCharsets.UTF_8);
    }

    private void writeBytes(DataOutputStream output, byte[] value) throws IOException {
        if (value.length > MAX_FIELD_BYTES) {
            throw new IllegalArgumentException("Ein Backup-Feld ist zu groß.");
        }
        output.writeInt(value.length);
        output.write(value);
    }

    private byte[] readBytes(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > MAX_FIELD_BYTES) {
            throw new IllegalArgumentException("Die Größe eines Backup-Feldes ist ungültig.");
        }
        byte[] value = input.readNBytes(length);
        if (value.length != length) {
            throw new EOFException();
        }
        return value;
    }

    private void validateMasterPassword(String masterPassword) {
        if (masterPassword == null || masterPassword.isEmpty()) {
            throw new IllegalArgumentException(
                    "Das Masterpasswort darf nicht leer sein."
            );
        }
    }
}
