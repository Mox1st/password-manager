package de.mox1st.passwordmanager.model;    //Diese Klasse gehört zum Package model.

public class User {

    private int id;
    private String username;
    private String password;


    //1. Konstruktor zum Erstellen eines Benutzers.
    public User (String username, String password){

        this.username = username;
        this.password = password;
    }

    //2. Konstruktor: Benutzer wird aus der Datenbank geladen. 
    public User(int id, String username, String password){

        this.id = id;
        this.username = username;
        this.password = password;

    }
    
    //Getter
    //Gibt den gespeicherten Benutzername zurück.
    public int getId(){
        return id;
    }
    public String getUsername(){
        return username;
    }
    //Gibt das gespeicherte Passwort zurück.
    public String getPassword(){
        return password;
    }
}
