package de.mox1st.passwordmanager.service;

import java.security.SecureRandom;

public class PasswordGenerator {

    private static final int DEFAULT_LENGTH = 20;
    private static final String LOWERCASE = "abcdefghijkmnopqrstuvwxyz";
    private static final String UPPERCASE = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private static final String DIGITS = "23456789";
    private static final String SYMBOLS = "!@#$%^&*()-_=+[]{}";
    private static final String ALL_CHARACTERS =
            LOWERCASE + UPPERCASE + DIGITS + SYMBOLS;

    private final SecureRandom secureRandom = new SecureRandom();

    public String generatePassword() {
        return generatePassword(DEFAULT_LENGTH);
    }

    public String generatePassword(int length) {
        if (length < 4) {
            throw new IllegalArgumentException(
                    "Die Passwortlänge muss mindestens 4 Zeichen betragen.");
        }

        char[] password = new char[length];
        password[0] = randomCharacter(LOWERCASE);
        password[1] = randomCharacter(UPPERCASE);
        password[2] = randomCharacter(DIGITS);
        password[3] = randomCharacter(SYMBOLS);

        for (int i = 4; i < length; i++) {
            password[i] = randomCharacter(ALL_CHARACTERS);
        }

        for (int i = password.length - 1; i > 0; i--) {
            int swapIndex = secureRandom.nextInt(i + 1);
            char temporary = password[i];
            password[i] = password[swapIndex];
            password[swapIndex] = temporary;
        }

        return new String(password);
    }

    private char randomCharacter(String characters) {
        return characters.charAt(secureRandom.nextInt(characters.length()));
    }
}
