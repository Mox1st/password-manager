package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.database.UserRepository;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class UserRepositorySaltTest {

    @Test
    public void generatedSaltsHaveExpectedLengthAndAreUnique() {
        UserRepository repository = new UserRepository();

        byte[] firstSalt = repository.generateKeySalt();
        byte[] secondSalt = repository.generateKeySalt();

        assertEquals(16, firstSalt.length);
        assertEquals(16, secondSalt.length);
        assertFalse(java.util.Arrays.equals(firstSalt, secondSalt));
    }
}
