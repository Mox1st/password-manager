package de.mox1st.passwordmanager.service;

public class PasswordStrengthEvaluator {

    public String evaluate(String password) {
        if (password == null || password.isEmpty()) {
            return "Sehr schwach";
        }

        int score = 0;

        if (password.length() >= 8) {
            score++;
        }
        if (password.length() >= 12) {
            score++;
        }
        if (containsLowercase(password)) {
            score++;
        }
        if (containsUppercase(password)) {
            score++;
        }
        if (containsDigit(password)) {
            score++;
        }
        if (containsSpecialCharacter(password)) {
            score++;
        }

        return switch (score) {
            case 0 -> "Sehr schwach";
            case 1 -> "Schwach";
            case 2 -> "Mittel";
            case 3, 4 -> "Stark";
            default -> "Sehr stark";
        };
    }

    public boolean isAcceptableMasterPassword(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }

        String strength = evaluate(password);
        return "Stark".equals(strength) || "Sehr stark".equals(strength);
    }

    private boolean containsLowercase(String password) {
        return password.chars().anyMatch(Character::isLowerCase);
    }

    private boolean containsUppercase(String password) {
        return password.chars().anyMatch(Character::isUpperCase);
    }

    private boolean containsDigit(String password) {
        return password.chars().anyMatch(Character::isDigit);
    }

    private boolean containsSpecialCharacter(String password) {
        return password.chars().anyMatch(
                character -> !Character.isLetterOrDigit(character)
        );
    }
}
