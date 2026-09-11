package de.mox1st.passwordmanager.service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class EncryptionSession {

    private byte[] keyBytes;

    public EncryptionSession(SecretKey key) {
        if (key == null || key.getEncoded() == null) {
            throw new IllegalArgumentException("Der Sitzungsschlüssel ist ungültig.");
        }
        this.keyBytes = key.getEncoded().clone();
    }

    public SecretKey getKey() {
        if (keyBytes == null) {
            throw new IllegalStateException("Die Verschlüsselungssitzung ist beendet.");
        }
        return new SecretKeySpec(keyBytes.clone(), "AES");
    }

    public void clear() {
        if (keyBytes != null) {
            Arrays.fill(keyBytes, (byte) 0);
            keyBytes = null;
        }
    }
}
