package de.mox1st.passwordmanager.app;  //Diese Klasse gehört zum Paket de.mox1st.passwordmanager.app

import javafx.application.Application;
import javafx.scene.Scene;              //Ein Scene enthält den gesammten sichtbaren Inhatl des Fensters.
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;    
import javafx.scene.control.Label;      //Damit können wir die JavaFX-Klasse Label verwenden.
import javafx.scene.control.TextField;  //TextFiled ist ein JavaFX-Eingabefeld, in das der Benutzer normalen Text schreiben.
import javafx.scene.control.PasswordField;
import javafx.scene.control.Button;     //Button ist die JavaFX-Komponente für einen anklickbaren Button.
import javafx.geometry.Pos;
import javafx.geometry.Insets;
import javafx.stage.Stage;              //Dadurch kann ich die Klasse Stage verwenden.
import de.mox1st.passwordmanager.controller.LoginController;
import de.mox1st.passwordmanager.database.DatabaseConnection;


public class Main extends Application {
     
    //Methoden
    @Override                           //Ich überschreibe jetzt die Methode start() aus der Oberklasse Application.
    public void start(Stage stage){     //Stage=Datentyp :: stage=Varibalenname
        DatabaseConnection.createTables();

        //start() startet die grafische Oberfläche
        stage.setTitle("Password Manager");
        //Jetzt soll das Fenster eine Größe bekommen.:
        stage.setWidth(800); 
        stage.setHeight(600);

        VBox root= new VBox();
        root.getStyleClass().add("auth-card");

        root.setSpacing (10);   //Legt einen Absand von 10 Pixeln zwischen den Elementen des VBox fest.
       
        root.setAlignment(Pos.CENTER);  //Zentriert die Elemente desVBox innerhalb dre verfügbaren Fläche.

        Label errorLabel = new Label(); //Erstellt ein Label, das später Fehlermeldungen für den Benutzer anzeigt.

        Label title= new Label("Password Manager");
        //Label=Datentyp für eine Textanzeige.
        //title=Variblenname.
        //new Label(..)=ersellt ein neues Label-Objekt.
        //"Password Manager"=Text, der angezeigt werden soll.
        VBox.setMargin(title, new Insets(0,0,20,0)); //Fügt dem Titel einen Abstand von 20 Pixeln nach unten hinzu.
        title.getStyleClass().add("title"); //Fügt dem Titel die CSS-Klasse "title" hinzu.
        Label subtitle = new Label("Deine Passwörter. Sicher verwaltet.");
        subtitle.getStyleClass().add("subtitle");
        root.getChildren().add(title);
        root.getChildren().add(subtitle);
        // getChildren() holt die Liste der Elemente, die sich im VBox befinden.
        // add(title) fügt unser Label zu dieser Liste hinzu.

        TextField usernameField = new TextField();
        //TextField =Datentyp für ein Texteingabefeld.
        //usernameField=Variablenname.
        //new TextField()=erstellt ein neues Eingabefeld.
        usernameField.setPromptText("Benutzername oder E-Mail");    //Zeigt einen Hinweis im leeren Eingabefled.
        usernameField.setPrefWidth(300);    //Legt die bevorzugte Breite des Benutzernamenfeldes auf 300 Pixel fest.
        usernameField.getStyleClass().add("input-field"); //Fügt dem Benutzernamenfeld die CSS-Klasse "input-field" hinzu.

        
        PasswordField passwordField = new PasswordField();
        
        passwordField.setPromptText("Passwort");
        passwordField.setPrefWidth(300);    //Legt die bevorzugte Breitedes. Passwortfeldes auf 300 Pixel fest.
        passwordField.getStyleClass().add("input-field");   //Fügt dem Passwortfeld die CSS-Klasse "input-field" hinzu.

        Button loginButton = new Button("Login");
        loginButton.setPrefWidth(300);  //Ledt die bevorzugte Breite des Login-Buttons auf 300 Pixel fest.
        VBox.setMargin(loginButton, new Insets(10,0,0,0));  //Fügt dem Login-Button einen Abstand von 10 Pixeln nach oben hinzu.
        loginButton.getStyleClass().add("login-button");    //Fügt dem Login-Button die CSS-Klasse "login-button" hinzu.
        
        Button registerButton = new Button ("Registrieren");
        registerButton.setPrefWidth(300);
        registerButton.getStyleClass().add("register-button");

        LoginController loginController = new LoginController(
            usernameField,
            passwordField,
            loginButton,
            registerButton,
            errorLabel,
            stage
        );
        //Initialisiert den Controller und richtet den Login-Button ein.
        loginController.initialize();


        root.getChildren().add(usernameField);  //Fügt das Eingabefeld zum VBox hinzu.

        root.getChildren().add(passwordField);

        root.getChildren().add(loginButton);    //Damit wird der Button in unser VBox eingefügt.

        root.getChildren().add(registerButton);

        root.getChildren().add(errorLabel);     //Fügt das Fehlermeldungs-Label zur Benutzeroberfläche hinzu.

        

        StackPane sceneRoot = new StackPane(root);
        sceneRoot.getStyleClass().add("auth-root");
        Scene sc= new Scene(sceneRoot);      //Erstellt eine Scene und setzt root als Wurzelelement.
        
        var stylesheet = getClass().getResource("/style.css");
        if (stylesheet == null) {
            throw new IllegalStateException("Das UI-Stylesheet konnte nicht geladen werden.");
        }
        sc.getStylesheets().add(stylesheet.toExternalForm());

        stage.setScene(sc);             //Setzt die Scene in das Fenster (Stage).
        
        stage.show();                   //Macht das Fenster sichtbar.
        
    }


//Hauptprogramm ::Diese Methode startet später die Anwendung
public static void main(String[] args){
    launch(args);                       //Diese Methode startet JavaFX.Sie übernimmt den gesamten Startvorgang.
}
}