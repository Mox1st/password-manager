package de.mox1st.passwordmanager.controller;   //Diese Klasse gehört zum Package controller.

import javafx.scene.control.Button;         //Damit kann der Controller mit unserem Login-Button arbeiten.
import javafx.scene.control.Label;         //Damit kann er die Fehlermeldung bzw. Erfolgsmeldung verändern.
import javafx.scene.control.PasswordField; //Damit kann er auf das Passwortfeld zugreifen.
import javafx.scene.control.TextField;      //Damit kann er auf das Benutzername-Feld zugreifen.
import de.mox1st.passwordmanager.model.User;
import de.mox1st.passwordmanager.database.UserRepository;
import de.mox1st.passwordmanager.database.PasswordEntryRepository;
import de.mox1st.passwordmanager.service.LoginService;
import de.mox1st.passwordmanager.service.RegisterService;
import de.mox1st.passwordmanager.service.EncryptionSession;
import de.mox1st.passwordmanager.service.LoginAttemptLimiter;
import java.security.GeneralSecurityException;
import javafx.stage.Stage;

public class LoginController {

private TextField usernameField;
private PasswordField passwordField;
private Button loginButton;
private Label errorLabel;
private Button registerButton;

private LoginService loginService;
private RegisterService registerService;
private DashboardController dashboardController;
private Stage loginStage;
private final LoginAttemptLimiter loginAttemptLimiter = new LoginAttemptLimiter();

//Konstruktor 
public LoginController(
    TextField usernameField,
    PasswordField passwordField, 
    Button loginButton,
    Button registerButton,
    Label errorLabel,
    Stage loginStage) {

    this.usernameField = usernameField;
    this.passwordField = passwordField;
    this.loginButton = loginButton;
    this.registerButton = registerButton;
    this.errorLabel = errorLabel;
    this.loginStage = loginStage;

    UserRepository userRepository = new UserRepository();

    this.loginService = new LoginService(userRepository);
    this.registerService = new RegisterService(userRepository);
    this.dashboardController = new DashboardController();
    this.dashboardController.setLoginPasswordField(passwordField);
}

//Methode
public void initialize(){

    //Legt fest, dass beim Klicken auf den Login-Button die Login-Methode ausgeführt wird.
    loginButton.setOnAction(event -> handleLogin());

    registerButton.setOnAction(event -> handleRegister());
}

// Verarbeitet den Login-Vorgang.
private void handleLogin(){

    if (loginAttemptLimiter.isBlocked()) {
        errorLabel.setText("Zu viele Fehlversuche. Bitte warten Sie 30 Sekunden.");
        return;
    }

    String username = usernameField.getText();  //Liest den eingegebenen Benutzername aus.
    String password = passwordField.getText();  //Liest das eingegebene Passwort aus.

    if (username.isEmpty()){
        errorLabel.setText("Benutzername fehlt!");
        return;
    }

    else if (password.isEmpty()){
        errorLabel.setText("Passwort fehlt!");
        return;
    }

    try {
      if (!loginService.checkLogin(username, password)) {
        loginAttemptLimiter.recordFailedAttempt();
        errorLabel.setText("Benutzername oder Passwort falsch!");
        return;
      }
      loginAttemptLimiter.reset();

      User user = loginService.getUser(username);
      EncryptionSession encryptionSession = null;
      try {
        encryptionSession =
                loginService.createEncryptionSession(user, password);
        new PasswordEntryRepository(encryptionSession)
                .migrateLegacyEntriesForUser(user.getId(), encryptionSession);
        dashboardController.showDashboard(user, encryptionSession, loginStage);
        clearLoginPassword();
        loginStage.hide();
      } catch (GeneralSecurityException | IllegalStateException exception) {
        clearLoginPassword();
        if (encryptionSession != null) {
          encryptionSession.clear();
        }
        errorLabel.setText("Verschlüsselung konnte nicht initialisiert werden.");
      }
    } catch (IllegalStateException exception) {
      clearLoginPassword();
      errorLabel.setText("Anmeldung konnte nicht abgeschlossen werden.");
    }

}

private void clearLoginPassword() {
    passwordField.clear();
}

private void handleRegister(){

    String username = usernameField.getText();
    String password = passwordField.getText();

    if (username.isEmpty()){
        errorLabel.setText("Benutzername fehlt!");
    }
    else if (password.isEmpty()){
        errorLabel.setText("Passwort fehlt!");
    }
    else if (!registerService.isAcceptableMasterPassword(password)) {
        errorLabel.setText("Das Master-Passwort muss mindestens 8 Zeichen lang sein und ausreichend stark sein.");
    }
    else if (registerService.register(username, password)){
        errorLabel.setText("Registrierung erfolgreich!");
    }
    else {
        errorLabel.setText("Benutzername bereits vergeben!");
    }
}
}
