package de.mox1st.passwordmanager.service;

import de.mox1st.passwordmanager.database.UserRepository;
import de.mox1st.passwordmanager.model.User;
import de.mox1st.passwordmanager.security.PasswordHasher;

import java.sql.SQLException;

public class RegisterService {

    private UserRepository userRepository;
    private PasswordHasher passwordHasher;
    private PasswordStrengthEvaluator passwordStrengthEvaluator;

    public RegisterService(UserRepository userRepository){
        this.userRepository = userRepository;

        passwordHasher = new PasswordHasher();
        passwordStrengthEvaluator = new PasswordStrengthEvaluator();
    }

    public boolean register(String username, String password){

        if (!passwordStrengthEvaluator.isAcceptableMasterPassword(password)) {
            return false;
        }

        if (userRepository.userExists(username)){
            return false;
        }

        String passwordHash = passwordHasher.hashPassword(password);
        User user = new User(username, passwordHash);

        try {
            userRepository.saveUser(user);
        } catch (IllegalStateException exception) {
            if (isUniqueConstraintViolation(exception)) {
                return false;
            }
            throw exception;
        }

        return true;
    }

    private boolean isUniqueConstraintViolation(Throwable exception) {
        for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
            if (cause instanceof SQLException
                    && cause.getMessage() != null
                    && cause.getMessage().toLowerCase().contains("unique")) {
                return true;
            }
        }
        return false;
    }

    public boolean isAcceptableMasterPassword(String password) {
        return passwordStrengthEvaluator.isAcceptableMasterPassword(password);
    }
}
