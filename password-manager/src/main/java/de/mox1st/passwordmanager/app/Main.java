package de.mox1st.passwordmanager.app;  //Diese Klasse gehört zum Paket de.mox1st.passwordmanager.app

import javafx.application.Application;
import javafx.scene.Scene;              //Ein Scene enthält den gesammten sichtbaren Inhatl des Fensters.
import javafx.scene.layout.StackPane;   //StackPane ist ein Layout-Container und ordnet Elemente übereinander an.
import javafx.scene.layout.VBox;    
import javafx.scene.control.Label;      //Damit können wir die JavaFX-Klasse Label verwenden.
import javafx.scene.control.TextField;  //TextFiled ist ein JavaFX-Eingabefeld, in das der Benutzer normalen Text schreiben.
import javafx.scene.control.PasswordField;
import javafx.scene.control.Button;     //Button ist die JavaFX-Komponente für einen anklickbaren Button.
import javafx.geometry.Pos;
import javafx.scene.text.Font;
import javafx.geometry.Insets;
import javafx.stage.Stage;              //Dadurch kann ich die Klasse Stage verwenden.
import de.mox1st.passwordmanager.controller.LoginController;


public class Main extends Application {
     
    //Methoden
    @Override                           //Ich überschreibe jetzt die Methode start() aus der Oberklasse Application.
    public void start(Stage stage){     //Stage=Datentyp :: stage=Varibalenname
                                        //start() startet die grafische Oberfläche
        stage.setTitle("Password Manager");
        //Jetzt soll das Fenster eine Größe bekommen.:
        stage.setWidth(800); 
        stage.setHeight(600);

        VBox root= new VBox();   

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
        root.getChildren().add(title); 
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
        
        LoginController loginController = new LoginController(
            usernameField,
            passwordField,
            loginButton,
            errorLabel
        );
        //Initialisiert den Controller und richtet den Login-Button ein.
        loginController.initialize();


        root.getChildren().add(usernameField);  //Fügt das Eingabefeld zum VBox hinzu.

        root.getChildren().add(passwordField);

        root.getChildren().add(loginButton);    //Damit wird der Button in unser VBox eingefügt.

        root.getChildren().add(errorLabel);     //Fügt das Fehlermeldungs-Label zur Benutzeroberfläche hinzu.

        

        Scene sc= new Scene(root);      //Erstellt eine Scene und setzt root als Wurzelelement.
        
        sc.getStylesheets().add(                                            //Lädet die CSS-Datei und wendet ihre Gestaltung auf die Scene an.
            getClass().getResource("/style.css").toExternalForm()
        );

        stage.setScene(sc);             //Setzt die Scene in das Fenster (Stage).
        
        stage.show();                   //Macht das Fenster sichtbar.
        
    }


//Hauptprogramm ::Diese Methode startet später die Anwendung
public static void main(String[] args){
    launch(args);                       //Diese Methode startet JavaFX.Sie übernimmt den gesamten Startvorgang.
}
}