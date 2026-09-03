package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.service.EncryptionSession;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotEquals;

public class EncryptionSessionTest {

    @Test
    public void sessionProvidesKeyAndClearsItOnLogout() {
        byte[] keyBytes = new byte[32];
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        EncryptionSession session = new EncryptionSession(key);

        assertArrayEquals(keyBytes, session.getKey().getEncoded());

        session.clear();
        session.clear();

        try {
            session.getKey();
        } catch (IllegalStateException expected) {
            assertNotEquals(null, expected);
            return;
        }
        throw new AssertionError("Der Sitzungsschlüssel wurde nicht verworfen.");
    }
}
