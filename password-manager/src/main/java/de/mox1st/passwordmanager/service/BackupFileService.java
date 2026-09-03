package de.mox1st.passwordmanager.service;

import de.mox1st.passwordmanager.model.BackupContainer;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.StandardCopyOption;

public class BackupFileService {

    private static final int FILE_MAGIC = 0x504D424B;
    private static final int SALT_LENGTH_BYTES = 16;
    private static final int NONCE_LENGTH_BYTES = 12;
    private static final int MAX_TEXT_BYTES = 1024;
    private static final int MAX_PAYLOAD_BYTES = 256 * 1024 * 1024;

    public void write(BackupContainer container, Path path) throws IOException {
        if (path == null) {
            throw new IllegalArgumentException("Der Dateipfad darf nicht null sein.");
        }
        Path absolutePath = path.toAbsolutePath();
        Path parent = absolutePath.getParent();
        if (parent == null) {
            throw new IOException("Der Backup-Dateipfad hat kein gültiges Verzeichnis.");
        }
        Path temporaryPath = Files.createTempFile(parent, ".pmb-", ".tmp");
        boolean moved = false;
        try {
            try (OutputStream outputStream = Files.newOutputStream(temporaryPath)) {
                write(container, outputStream);
            }
            try {
                Files.move(
                        temporaryPath,
                        absolutePath,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING
                );
            } catch (AtomicMoveNotSupportedException exception) {
                Files.move(
                        temporaryPath,
                        absolutePath,
                        StandardCopyOption.REPLACE_EXISTING
                );
            }
            moved = true;
        } finally {
            if (!moved) {
                Files.deleteIfExists(temporaryPath);
            }
        }
    }

    public BackupContainer read(Path path) throws IOException {
        if (path == null) {
            throw new IllegalArgumentException("Der Dateipfad darf nicht null sein.");
        }
        try (InputStream inputStream = Files.newInputStream(path)) {
            return read(inputStream);
        }
    }

    public void write(BackupContainer container, OutputStream outputStream)
            throws IOException {
        if (container == null || outputStream == null) {
            throw new IllegalArgumentException(
                    "Backup-Container und Ausgabestream dürfen nicht null sein."
            );
        }
        validateContainer(container);

        DataOutputStream output = new DataOutputStream(outputStream);
        output.writeInt(FILE_MAGIC);
        output.writeInt(container.getFormatVersion());
        writeString(output, container.getKdfAlgorithm());
        output.writeInt(container.getKdfIterations());
        writeBytes(output, container.getBackupSalt(), SALT_LENGTH_BYTES);
        writeString(output, container.getEncryptionAlgorithm());
        writeBytes(output, container.getNonce(), NONCE_LENGTH_BYTES);
        writeBytes(output, container.getEncryptedPayload(), MAX_PAYLOAD_BYTES);
        output.flush();
    }

    public BackupContainer read(InputStream inputStream) throws IOException {
        if (inputStream == null) {
            throw new IllegalArgumentException("Der Eingabestream darf nicht null sein.");
        }

        try {
            DataInputStream input = new DataInputStream(inputStream);
            if (input.readInt() != FILE_MAGIC) {
                throw new IOException("Das Backup-Dateiformat ist ungültig.");
            }

            int version = input.readInt();
            String kdfAlgorithm = readString(input);
            int kdfIterations = input.readInt();
            byte[] salt = readBytes(input, SALT_LENGTH_BYTES);
            String encryptionAlgorithm = readString(input);
            byte[] nonce = readBytes(input, NONCE_LENGTH_BYTES);
            byte[] encryptedPayload = readBytes(input, MAX_PAYLOAD_BYTES);

            if (input.read() != -1) {
                throw new IOException("Die Backup-Datei enthält zusätzliche Daten.");
            }

            BackupContainer container = new BackupContainer(
                    version,
                    kdfAlgorithm,
                    kdfIterations,
                    salt,
                    encryptionAlgorithm,
                    nonce,
                    encryptedPayload
            );
            validateContainer(container);
            return container;
        } catch (EOFException exception) {
            throw new IOException("Die Backup-Datei ist unvollständig.", exception);
        } catch (IllegalArgumentException exception) {
            throw new IOException("Die Backup-Datei enthält ungültige Daten.", exception);
        }
    }

    private void validateContainer(BackupContainer container) {
        if (container.getFormatVersion()
                != BackupContainer.CURRENT_FORMAT_VERSION) {
            throw new IllegalArgumentException(
                    "Die Backup-Version wird nicht unterstützt."
            );
        }
        if (container.getKdfAlgorithm() == null
                || container.getKdfAlgorithm().isEmpty()
                || container.getEncryptionAlgorithm() == null
                || container.getEncryptionAlgorithm().isEmpty()) {
            throw new IllegalArgumentException(
                    "Pflichtfelder des Backup-Headers fehlen."
            );
        }
        if (container.getBackupSalt().length != SALT_LENGTH_BYTES) {
            throw new IllegalArgumentException("Der Backup-Salt ist ungültig.");
        }
        if (container.getNonce().length != NONCE_LENGTH_BYTES) {
            throw new IllegalArgumentException("Die Nonce ist ungültig.");
        }
        if (container.getEncryptedPayload().length == 0) {
            throw new IllegalArgumentException(
                    "Der verschlüsselte Payload ist leer."
            );
        }
    }

    private void writeString(DataOutputStream output, String value)
            throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_TEXT_BYTES) {
            throw new IllegalArgumentException("Ein Header-Feld ist zu groß.");
        }
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private String readString(DataInputStream input) throws IOException {
        byte[] bytes = readBytes(input, MAX_TEXT_BYTES);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private void writeBytes(
            DataOutputStream output,
            byte[] value,
            int expectedLength) throws IOException {
        if (value.length != expectedLength && expectedLength != MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("Ein Backup-Feld hat eine ungültige Länge.");
        }
        if (value.length > expectedLength) {
            throw new IllegalArgumentException("Der Backup-Payload ist zu groß.");
        }
        output.writeInt(value.length);
        output.write(value);
    }

    private byte[] readBytes(DataInputStream input, int maximumLength)
            throws IOException {
        int length = input.readInt();
        if (length < 0 || length > maximumLength) {
            throw new IOException("Die Länge eines Backup-Feldes ist ungültig.");
        }
        byte[] value = input.readNBytes(length);
        if (value.length != length) {
            throw new EOFException();
        }
        return value;
    }
}
