//PasswordEntry repräsentiert einen gespeicherten Zugang.

package de.mox1st.passwordmanager.model; 

public class PasswordEntry {
    
    private int id;
    private int userId;
    private String website;
    private String user;
    private String password;

    //Konstruktor 
    public PasswordEntry(int userId, String website, String user, String password){
        this.userId = userId;
        this.website = website;
        this.user = user; 
        this.password = password;
    }

    //Konstruktor für einen vorhandenen Passwort-Eintrag aus der Datenbank
    public PasswordEntry (int id, int userId, String website, String user, String password){
        this.id = id;
        this.userId = userId;
        this.website = website;
        this.user = user;
        this.password = password;
    }

    //Getter
    public int getId(){
        return id;
    }

    public int getUserId(){
        return userId;
    }

    public String getWebsite(){
        return website;
    }

    public String getUser(){
        return user;
    }

    public String getPassword(){
        return password;
    }


}
