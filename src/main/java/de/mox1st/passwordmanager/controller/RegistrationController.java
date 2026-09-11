package de.mox1st.passwordmanager.controller;

import de.mox1st.passwordmanager.database.UserRepository;
import de.mox1st.passwordmanager.service.RegisterService;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.Window;

public class RegistrationController {

    private final RegisterService registerService;
    private final Stage registrationStage;

    private final TextField usernameField;
    private final PasswordField passwordField;
    private final PasswordField repeatPasswordField;
    private final Label strengthLabel;
    private final Label errorLabel;

    public RegistrationController(Window owner) {
        this.registerService = new RegisterService(new UserRepository());

        this.registrationStage = new Stage();
        this.registrationStage.initOwner(owner);
        this.registrationStage.initModality(Modality.WINDOW_MODAL);
        this.registrationStage.setTitle("Neues Konto erstellen");
        this.registrationStage.setResizable(false);

        Label title = new Label("Neues Konto erstellen");
        title.getStyleClass().add("auth-title");

        Label subtitle = new Label("Erstelle deinen persönlichen Password-Manager-Account.");
        subtitle.getStyleClass().add("auth-subtitle");
        subtitle.setWrapText(true);

        usernameField = new TextField();
        usernameField.setPromptText("Benutzername");
        usernameField.setPrefWidth(300);
        usernameField.getStyleClass().add("input-field");

        passwordField = new PasswordField();
        passwordField.setPromptText("Master-Passwort");
        passwordField.setPrefWidth(300);
        passwordField.getStyleClass().add("input-field");

        strengthLabel = new Label("Passwortstärke: –");
        strengthLabel.getStyleClass().add("status-label");

        repeatPasswordField = new PasswordField();
        repeatPasswordField.setPromptText("Master-Passwort wiederholen");
        repeatPasswordField.setPrefWidth(300);
        repeatPasswordField.getStyleClass().add("input-field");

        Button registerButton = new Button("Konto erstellen");
        registerButton.setPrefWidth(300);
        registerButton.getStyleClass().add("login-button");

        Button backButton = new Button("Zurück zum Login");
        backButton.setPrefWidth(300);
        backButton.getStyleClass().add("register-button");

        errorLabel = new Label();
        errorLabel.setWrapText(true);
        errorLabel.getStyleClass().add("error-label");

        passwordField.textProperty().addListener((observable, oldValue, newValue) ->
                updatePasswordStrength(newValue)
        );

        registerButton.setOnAction(event -> handleRegister());

        backButton.setOnAction(event -> {
            clearFields();
            registrationStage.close();
        });

        registrationStage.setOnCloseRequest(event -> clearFields());

        VBox root = new VBox(14);
        root.setAlignment(Pos.CENTER);
        root.setPadding(new Insets(40));
        root.getStyleClass().add("auth-card");

        root.getChildren().addAll(
                title,
                subtitle,
                usernameField,
                passwordField,
                strengthLabel,
                repeatPasswordField,
                registerButton,
                backButton,
                errorLabel
        );

        Scene scene = new Scene(root, 500, 620);

        var stylesheet = getClass().getResource("/style.css");
        if (stylesheet == null) {
            throw new IllegalStateException("Das UI-Stylesheet konnte nicht geladen werden.");
        }

        scene.getStylesheets().add(stylesheet.toExternalForm());

        registrationStage.setScene(scene);
    }

    public void show() {
        registrationStage.show();
        registrationStage.centerOnScreen();
        usernameField.requestFocus();
    }

    private void handleRegister() {
        String username = usernameField.getText().trim();
        String password = passwordField.getText();
        String repeatPassword = repeatPasswordField.getText();

        errorLabel.setText("");

        if (username.isEmpty()) {
            errorLabel.setText("Benutzername fehlt!");
            return;
        }

        if (password.isEmpty()) {
            errorLabel.setText("Master-Passwort fehlt!");
            return;
        }

        if (repeatPassword.isEmpty()) {
            errorLabel.setText("Bitte wiederhole das Master-Passwort.");
            return;
        }

        if (!password.equals(repeatPassword)) {
            errorLabel.setText("Die Passwörter stimmen nicht überein.");
            return;
        }

        if (!registerService.isAcceptableMasterPassword(password)) {
            errorLabel.setText(
                    "Das Master-Passwort muss mindestens 8 Zeichen lang sein und ausreichend stark sein."
            );
            return;
        }

        if (!registerService.register(username, password)) {
            errorLabel.setText("Benutzername bereits vergeben.");
            return;
        }

        clearFields();
        registrationStage.close();
    }

    private void updatePasswordStrength(String password) {
        if (password == null || password.isEmpty()) {
            strengthLabel.setText("Passwortstärke: –");
            return;
        }

        if (registerService.isAcceptableMasterPassword(password)) {
            strengthLabel.setText("Passwortstärke: Stark");
        } else if (password.length() < 8) {
            strengthLabel.setText("Passwortstärke: Zu kurz");
        } else {
            strengthLabel.setText("Passwortstärke: Zu schwach");
        }
    }

    private void clearFields() {
        usernameField.clear();
        passwordField.clear();
        repeatPasswordField.clear();
        errorLabel.setText("");
        strengthLabel.setText("Passwortstärke: –");
    }
}