package de.mox1st.passwordmanager.controller;   //Diese Klasse gehört zum Package controller.

import javafx.scene.control.Button;         //Damit kann der Controller mit unserem Login-Button arbeiten.
import javafx.scene.control.Label;         //Damit kann er die Fehlermeldung bzw. Erfolgsmeldung verändern.
import javafx.scene.control.PasswordField; //Damit kann er auf das Passwortfeld zugreifen.
import javafx.scene.control.TextField;      //Damit kann er auf das Benutzername-Feld zugreifen.


public class LoginController {

private TextField usernameField;
private PasswordField passwordField;
private Button loginButton;
private Label errorLabel;

//Konstruktor 
public LoginController(
    TextField usernameField,
    PasswordField passwordField, 
    Button loginButton,
    Label errorLabel) {

    this.usernameField = usernameField;
    this.passwordField = passwordField;
    this.loginButton = loginButton;
    this.errorLabel = errorLabel;
}

//Methode
public void initialize(){

    //Legt fest, dass beim Klicken auf den Login-Button die Login-Methode ausgeführt wird.
    loginButton.setOnAction(event -> handleLogin());
}

// Verarbeitet den Login-Vorgang.
private void handleLogin(){


    String username = usernameField.getText();  //Liest den eingegebenen Benutzername aus.
    String password = passwordField.getText();  //Liest das eingegebene Passwort aus.

    if (username.isEmpty()){
        errorLabel.setText("Benutzername fehlt!");
    }

    else if (password.isEmpty()){
        errorLabel.setText("Passwort fehlt!");
    }

    else if (username.equals("admin")
        && password.equals("1234")) {
            errorLabel.setText("Login erfolgreich!");
        } 
        else {
            errorLabel.setText("Benutzername oder passwort falsch!");
        }



}
}
