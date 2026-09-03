package de.mox1st.passwordmanager.controller;

import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ScrollPane;
import javafx.scene.layout.VBox;
import javafx.scene.layout.HBox;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;
import javafx.stage.FileChooser;
import java.io.File;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.animation.PauseTransition;
import javafx.util.Duration;

import de.mox1st.passwordmanager.model.User;
import de.mox1st.passwordmanager.model.PasswordEntry;
import de.mox1st.passwordmanager.database.PasswordEntryRepository;
import de.mox1st.passwordmanager.database.UserRepository;
import de.mox1st.passwordmanager.service.PasswordGenerator;
import de.mox1st.passwordmanager.service.PasswordStrengthEvaluator;
import de.mox1st.passwordmanager.service.EncryptionSession;
import de.mox1st.passwordmanager.service.LoginService;
import de.mox1st.passwordmanager.service.BackupService;
import de.mox1st.passwordmanager.service.BackupFileService;
import de.mox1st.passwordmanager.service.BackupImportService;
import de.mox1st.passwordmanager.service.BackupRestoreService;
import de.mox1st.passwordmanager.service.BackupEncryptionService;
import de.mox1st.passwordmanager.model.BackupContainer;
import de.mox1st.passwordmanager.model.BackupPayload;

import java.util.List;
import java.util.ArrayList;
import java.util.Comparator;
import java.awt.Desktop;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.net.URI;
import java.net.URISyntaxException;

public class DashboardController {

    private User currentUser;
    private PasswordEntryRepository passwordEntryRepository;
    private VBox entriesBox;
    private Stage dashboardStage;
    private Stage loginStage;
    private EncryptionSession encryptionSession;
    private LoginService loginService;
    private BackupService backupService;
    private BackupFileService backupFileService;
    private BackupImportService backupImportService;
    private BackupRestoreService backupRestoreService;
    private BackupEncryptionService backupEncryptionService;
    private TextField searchField;
    private PasswordField loginPasswordField;
    private List<PasswordEntry> allEntries = new ArrayList<>();

    private final PasswordGenerator passwordGenerator = new PasswordGenerator();
    private final PasswordStrengthEvaluator passwordStrengthEvaluator =
            new PasswordStrengthEvaluator();

    public void setLoginPasswordField(PasswordField loginPasswordField) {
        this.loginPasswordField = loginPasswordField;
    }

    public void showDashboard(User user) {
        showDashboard(user, null);
    }

    public void showDashboard(User user, EncryptionSession encryptionSession) {
        showDashboard(user, encryptionSession, null);
    }

    public void showDashboard(
            User user,
            EncryptionSession encryptionSession,
            Stage loginStage) {
        this.currentUser = user;
        this.encryptionSession = encryptionSession;
        this.loginStage = loginStage;
        this.loginService = new LoginService(new UserRepository());
        this.passwordEntryRepository =
                new PasswordEntryRepository(encryptionSession);
        this.backupService = new BackupService();
        this.backupFileService = new BackupFileService();
        this.backupImportService = new BackupImportService();
        this.backupRestoreService = new BackupRestoreService();
        this.backupEncryptionService = new BackupEncryptionService();

        dashboardStage = new Stage();

        BorderPane root = new BorderPane();
        root.getStyleClass().add("dashboard-root");
        VBox content = new VBox();
        content.getStyleClass().add("dashboard-content");
        content.setMaxWidth(1080);


        // Box für die gespeicherten Einträge
        entriesBox = new VBox();
        entriesBox.getStyleClass().add("entry-list");
        entriesBox.setSpacing(10);


        // Begrüßung
        Label welcomeLabel =
                new Label("Willkommen, " + user.getUsername());
        welcomeLabel.getStyleClass().add("secondary-text");
        Label dashboardTitle = new Label("Meine Passwörter");
        dashboardTitle.getStyleClass().add("page-title");

        VBox titleBlock = new VBox(welcomeLabel, dashboardTitle);
        titleBlock.getStyleClass().add("dashboard-title-block");
        HBox header = new HBox(titleBlock);
        header.getStyleClass().add("dashboard-header");
        content.getChildren().add(header);


        searchField = new TextField();
        searchField.setPromptText("Passwörter durchsuchen …");
        searchField.getStyleClass().add("search-field");
        searchField.setMaxWidth(Double.MAX_VALUE);
        searchField.textProperty().addListener(
                (observable, oldValue, newValue) ->
                        displayEntries(filterEntries(newValue))
        );

        content.getChildren().add(searchField);

        // Buttons remain outside entriesBox so refreshing the list cannot remove them.
        Button addPasswordButton =
                new Button("+ Neues Passwort");
        addPasswordButton.getStyleClass().add("primary-button");
        addPasswordButton.setOnAction(
                event -> handleAddPassword()
        );

        Button logoutButton =
                new Button("Abmelden");
        logoutButton.getStyleClass().add("secondary-button");
        logoutButton.setOnAction(
                event -> handleLogout()
        );

        Button changeMasterPasswordButton =
                new Button("Master-Passwort ändern");
        changeMasterPasswordButton.getStyleClass().add("secondary-button");
        changeMasterPasswordButton.setOnAction(
                event -> handleChangeMasterPassword()
        );

        HBox primaryActions = new HBox(addPasswordButton);
        primaryActions.getStyleClass().add("toolbar");
        primaryActions.setAlignment(Pos.CENTER_RIGHT);
        header.getChildren().add(primaryActions);
        HBox.setHgrow(titleBlock, javafx.scene.layout.Priority.ALWAYS);
        Button exportBackupButton = new Button("Backup exportieren");
        exportBackupButton.getStyleClass().add("secondary-button");
        exportBackupButton.setOnAction(event -> handleBackupExport());
        Button importBackupButton = new Button("Backup importieren");
        importBackupButton.getStyleClass().add("secondary-button");
        importBackupButton.setOnAction(event -> handleBackupImport());
        Label securityTitle = new Label("Sicherheit & Backup");
        securityTitle.getStyleClass().add("section-label");
        HBox securityActions = new HBox(
                changeMasterPasswordButton,
                exportBackupButton,
                importBackupButton
        );
        securityActions.getStyleClass().add("toolbar");
        VBox securitySection = new VBox(securityTitle, securityActions);
        securitySection.getStyleClass().add("security-section");
        content.getChildren().add(securitySection);

        // Einträge zum Haupt-Layout hinzufügen
        ScrollPane entryScrollPane = new ScrollPane(entriesBox);
        entryScrollPane.setFitToWidth(true);
        entryScrollPane.getStyleClass().add("entry-scroll");
        VBox.setVgrow(entryScrollPane, javafx.scene.layout.Priority.ALWAYS);
        content.getChildren().add(entryScrollPane);
        Region sidebarSpacer = new Region();
        VBox.setVgrow(sidebarSpacer, javafx.scene.layout.Priority.ALWAYS);
        Label sidebarBrand = new Label("Password\nManager");
        sidebarBrand.getStyleClass().add("sidebar-brand");
        Label activeSection = new Label("▣  Meine Passwörter");
        activeSection.getStyleClass().add("sidebar-active");
        Label accountLabel = new Label(user.getUsername());
        accountLabel.getStyleClass().add("sidebar-account");
        VBox sidebar = new VBox(sidebarBrand, activeSection, sidebarSpacer, accountLabel);
        sidebar.getStyleClass().add("sidebar");
        sidebar.getChildren().add(logoutButton);
        root.setLeft(sidebar);
        StackPane contentWrapper = new StackPane(content);
        contentWrapper.setAlignment(Pos.TOP_CENTER);
        root.setCenter(contentWrapper);

        refreshDashboard();


        // Scene erstellen
        Scene scene =
                new Scene(root, 760, 620);
        applyStylesheet(scene);

        dashboardStage.setScene(scene);
        dashboardStage.setOnCloseRequest(event -> {
            clearEncryptionSession();
            clearSensitiveUi();
            showLoginStage();
        });


        // Dashboard anzeigen
        dashboardStage.show();
    }


    // Passwort hinzufügen
    private void handleAddPassword() {

        Stage addPasswordStage =
                new Stage();

        VBox root =
                new VBox();
        root.getStyleClass().add("dialog-root");
        root.setSpacing(10);


        TextField websiteField = new TextField();

        TextField usernameField = new TextField();

        PasswordField passwordField = new PasswordField();
        Label passwordStrengthLabel = new Label("Passwortstärke: Sehr schwach");

        passwordField.textProperty().addListener(
                (observable, oldValue, newValue) ->
                        passwordStrengthLabel.setText(
                                "Passwortstärke: "
                                        + passwordStrengthEvaluator.evaluate(newValue)
                        )
        );


        websiteField.setPromptText("Website");
        usernameField.setPromptText("Benutzername");
        passwordField.setPromptText("Passwort");
        websiteField.getStyleClass().add("input-field");
        usernameField.getStyleClass().add("input-field");
        passwordField.getStyleClass().add("input-field");
        passwordStrengthLabel.getStyleClass().add("strength-label");

        Button saveButton =
                new Button("Speichern");

        Button generatePasswordButton =
                new Button("Passwort generieren");
        generatePasswordButton.getStyleClass().add("secondary-button");
        saveButton.getStyleClass().add("primary-button");

        generatePasswordButton.setOnAction(
                event -> passwordField.setText(
                        passwordGenerator.generatePassword()
                )
        );

        saveButton.setOnAction(
                event -> handleSavePassword(
                        websiteField,
                        usernameField,
                        passwordField,
                        addPasswordStage
                )
        );


        root.getChildren().add(websiteField);
        root.getChildren().add(usernameField);
        root.getChildren().add(passwordField);
        root.getChildren().add(passwordStrengthLabel);
        root.getChildren().add(generatePasswordButton);
        root.getChildren().add(saveButton);


        Scene scene =
                new Scene(root, 440, 340);
        applyStylesheet(scene);

        addPasswordStage.setScene(scene);
        addPasswordStage.setOnHidden(event -> {
            websiteField.clear();
            usernameField.clear();
            passwordField.clear();
        });

        addPasswordStage.show();
    }


    // Passwort speichern
    private void handleSavePassword(
            TextField websiteField,
            TextField usernameField,
            PasswordField             passwordField,
            Stage addPasswordStage) {

        String website =
                websiteField.getText();

        String username =
                usernameField.getText();

        String password =
                passwordField.getText();


        if (website.isEmpty()) {

            return;
        }


        if (username.isEmpty()) {

            return;
        }


        if (password.isEmpty()) {

            return;
        }


        PasswordEntry entry =
                new PasswordEntry(
                        currentUser.getId(),
                        website,
                        username,
                        password
                );


        try {
            passwordEntryRepository.saveEntry(entry);
            refreshDashboard();
            addPasswordStage.close();
            if (!dashboardStage.isShowing()) {
                dashboardStage.show();
            }
            dashboardStage.toFront();
            dashboardStage.requestFocus();
        } catch (RuntimeException exception) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Fehler beim Speichern");
            alert.setHeaderText(null);
            alert.setContentText(
                    "Der Passwort-Eintrag konnte nicht gespeichert werden."
            );
            alert.showAndWait();
        }
    }


    // Passwort-Eintrag löschen
    private void handleDeletePassword(
            PasswordEntry entry,
            VBox entryBox) {

        Alert alert =
                new Alert(Alert.AlertType.CONFIRMATION);

        alert.setTitle("Eintrag löschen");

        alert.setHeaderText(
                "Passwort-Eintrag löschen"
        );

        alert.setContentText(
                "Möchtest du den Eintrag für "
                + entry.getWebsite()
                + " wirklich löschen?"
        );


        var result =
                alert.showAndWait();


        if (result.isPresent()
                && result.get() == ButtonType.OK) {

            if (!passwordEntryRepository.deleteEntry(
                    entry.getId(),
                    currentUser.getId())) {
                throw new IllegalStateException(
                        "Der Passwort-Eintrag konnte nicht gelöscht werden."
                );
            }

            refreshDashboard();
            if (!dashboardStage.isShowing()) {
                dashboardStage.show();
            }
            dashboardStage.toFront();
            dashboardStage.requestFocus();
        }
    }


    // Passwort anzeigen / verbergen
    private void handleShowPassword(
            PasswordEntry entry,
            Label passwordLabel,
            Button showPasswordButton) {

        if (showPasswordButton
                .getText()
                .equals("Anzeigen")) {

            passwordLabel.setText(
                    "Passwort: "
                    + entry.getPassword()
            );

            showPasswordButton.setText(
                    "Verbergen"
            );

        } else {

            passwordLabel.setText(
                    "Passwort: ••••••••••••"
            );

            showPasswordButton.setText(
                    "Anzeigen"
            );
        }
    }


    // Passwort-Eintrag bearbeiten
    private void handleEditPassword(
            PasswordEntry entry) {

        Stage editPasswordStage = new Stage();

        VBox root = new VBox();
        root.getStyleClass().add("dialog-root");
        root.setAlignment(Pos.CENTER);
        root.setSpacing(10);

        TextField websiteField = new TextField();
        TextField usernameField = new TextField();
        PasswordField passwordField = new PasswordField();
        Label passwordStrengthLabel = new Label();

        websiteField.setText(entry.getWebsite());
        usernameField.setText(entry.getUser());
        passwordField.setText(entry.getPassword());
        passwordStrengthLabel.setText(
                "Passwortstärke: "
                        + passwordStrengthEvaluator.evaluate(passwordField.getText())
        );
        passwordField.textProperty().addListener(
                (observable, oldValue, newValue) ->
                        passwordStrengthLabel.setText(
                                "Passwortstärke: "
                                        + passwordStrengthEvaluator.evaluate(newValue)
                        )
        );

        Button saveButton = new Button("Speichern");
        saveButton.getStyleClass().add("primary-button");
        websiteField.getStyleClass().add("input-field");
        usernameField.getStyleClass().add("input-field");
        passwordField.getStyleClass().add("input-field");
        passwordStrengthLabel.getStyleClass().add("strength-label");

        saveButton.setOnAction (
            event -> handleUpdatePassword(
                    entry,
                    websiteField,
                    usernameField,
                    passwordField,
                    editPasswordStage
            )
        );

        root.getChildren().add(websiteField);
        root.getChildren().add(usernameField);
        root.getChildren().add(passwordField);
        root.getChildren().add(passwordStrengthLabel);
        root.getChildren().add(saveButton);

        Scene scene = new Scene(root, 400, 300);
        applyStylesheet(scene);

        editPasswordStage.setScene(scene);
        editPasswordStage.setOnHidden(event -> {
            websiteField.clear();
            usernameField.clear();
            passwordField.clear();
        });

        editPasswordStage.show();


    }

    private void handleUpdatePassword(
            PasswordEntry entry,
            TextField websiteField,
            TextField usernameField,
            PasswordField passwordField,
            Stage editPasswordStage
    ) {

    String website = websiteField.getText();
    String username = usernameField.getText();
    String password = passwordField.getText();

    if (website.isEmpty()){
        return; 
    }

    if (username.isEmpty()){
        return;
    }

    if (password.isEmpty()){
        return;
    }

    PasswordEntry updatedEntry = new PasswordEntry(
            entry.getId(),
            entry.getUserId(),
            website,
            username,
            password
    );

    if (!passwordEntryRepository.updateEntry(
            updatedEntry,
            currentUser.getId())) {
        throw new IllegalStateException(
                "Der Passwort-Eintrag konnte nicht aktualisiert werden."
        );
    }

    refreshDashboard();

    editPasswordStage.close();
    if (!dashboardStage.isShowing()) {
        dashboardStage.show();
    }
    dashboardStage.toFront();
    dashboardStage.requestFocus();

    }

    private void refreshDashboard (){

        allEntries = passwordEntryRepository.findEntriesByUserId(
                currentUser.getId()
        );
        allEntries.sort(
                Comparator.comparing(
                        PasswordEntry::getWebsite,
                        String.CASE_INSENSITIVE_ORDER
                )
        );
        displayEntries(filterEntries(searchField.getText()));
    }

    private List<PasswordEntry> filterEntries(String searchText) {
        String normalizedSearch = searchText.trim().toLowerCase();

        if (normalizedSearch.isEmpty()) {
            return new ArrayList<>(allEntries);
        }

        return allEntries.stream()
                .filter(entry -> entry.getWebsite()
                        .toLowerCase()
                        .contains(normalizedSearch))
                .toList();
    }

    private void displayEntries(List<PasswordEntry> entries) {
        entriesBox.getChildren().clear();

        if (entries.isEmpty()) {
            VBox emptyState = new VBox();
            emptyState.getStyleClass().add("empty-state");
            Label emptyTitle = new Label(
                    allEntries.isEmpty()
                            ? "Noch keine Passwörter"
                            : "Keine Ergebnisse gefunden"
            );
            emptyTitle.getStyleClass().add("empty-state-title");
            Label emptyText = new Label(
                    allEntries.isEmpty()
                            ? "Füge deinen ersten Passwort-Eintrag hinzu, um ihn sicher zu speichern."
                            : "Passe deine Suche an oder lösche den Suchbegriff."
            );
            emptyText.getStyleClass().add("empty-state-text");
            emptyText.setWrapText(true);
            emptyState.getChildren().addAll(emptyTitle, emptyText);
            if (allEntries.isEmpty()) {
                Button addButton = new Button("+ Passwort hinzufügen");
                addButton.getStyleClass().add("primary-button");
                addButton.setOnAction(event -> handleAddPassword());
                emptyState.getChildren().add(addButton);
            } else {
                Button clearSearchButton = new Button("Suche löschen");
                clearSearchButton.getStyleClass().add("secondary-button");
                clearSearchButton.setOnAction(event -> searchField.clear());
                emptyState.getChildren().add(clearSearchButton);
            }
            entriesBox.getChildren().add(emptyState);
            return;
        }

        for (PasswordEntry entry : entries) {

            VBox entryBox = new VBox();
            entryBox.getStyleClass().add("entry-card");
            entryBox.setSpacing(5);

            Label websiteLabel =
                        new Label(entry.getWebsite());
            websiteLabel.getStyleClass().add("entry-website");
            Label websiteInitial = new Label(
                    entry.getWebsite().substring(0, 1).toUpperCase()
            );
            websiteInitial.getStyleClass().add("entry-avatar");
            HBox websiteHeader = new HBox(websiteInitial, websiteLabel);
            websiteHeader.getStyleClass().add("entry-header");
                
            Label usernameLabel = 
                        new Label("Benutzername: " + entry.getUser());
            usernameLabel.getStyleClass().add("entry-username");

            Button copyUsernameButton =
                        new Button("Benutzername kopieren");

            copyUsernameButton.setOnAction(
                    event -> copyUsernameToClipboard(entry.getUser())
            );

            Button openWebsiteButton =
                        new Button("Website öffnen");

            openWebsiteButton.setOnAction(
                    event -> openWebsite(entry.getWebsite())
            );

            Label passwordLabel = 
                        new Label("Passwort: ••••••••••••");
            
            Button showPasswordButton = 
                        new Button("Anzeigen");

            showPasswordButton.setOnAction(
                        event -> handleShowPassword(
                                entry, 
                                passwordLabel,
                                showPasswordButton
                        )
            );

            Button copyPasswordButton =
                        new Button("Kopieren");

            copyPasswordButton.setOnAction(
                        event -> copyPasswordToClipboard(entry.getPassword())
            );

            Button editButton = 
                        new Button("Bearbeiten");

            editButton.setOnAction(
                        event -> handleEditPassword(entry)
            );

            Button deleteButton = 
                        new Button("Löschen");
            deleteButton.getStyleClass().add("danger-button");
            
            deleteButton.setOnAction(
                        event -> handleDeletePassword(
                                    entry,
                                    entryBox
                        )
            );

        passwordLabel.getStyleClass().add("entry-password");
        editButton.getStyleClass().add("secondary-button");
        copyPasswordButton.getStyleClass().add("secondary-button");
        copyUsernameButton.getStyleClass().add("secondary-button");
        openWebsiteButton.getStyleClass().add("secondary-button");
        showPasswordButton.getStyleClass().add("secondary-button");
        HBox entryActions = new HBox(
                openWebsiteButton,
                copyUsernameButton,
                showPasswordButton,
                copyPasswordButton,
                editButton,
                deleteButton
        );
        entryActions.getStyleClass().add("entry-actions");
        entryBox.getChildren().add(websiteHeader);
        entryBox.getChildren().add(usernameLabel);
        entryBox.getChildren().add(passwordLabel);
        entryBox.getChildren().add(entryActions);

        entriesBox.getChildren().add(entryBox);

        }
    }

    private void copyPasswordToClipboard(String password) {
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(password);
        clipboard.setContent(content);

        PauseTransition clearClipboard = new PauseTransition(
                Duration.seconds(15)
        );
        clearClipboard.setOnFinished(event -> {
            if (clipboard.hasString()
                    && password.equals(clipboard.getString())) {
                clipboard.clear();
            }
        });
        clearClipboard.play();
    }

    private void copyUsernameToClipboard(String username) {
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(username);
        clipboard.setContent(content);

        PauseTransition clearClipboard = new PauseTransition(
                Duration.seconds(15)
        );
        clearClipboard.setOnFinished(event -> {
            if (clipboard.hasString()
                    && username.equals(clipboard.getString())) {
                clipboard.clear();
            }
        });
        clearClipboard.play();
    }

    private void openWebsite(String website) {
        try {
            URI websiteUri = normalizeWebsiteUri(website);
            if (!Desktop.isDesktopSupported()) {
                throw new IllegalStateException(
                        "Das Öffnen von Websites wird auf diesem System nicht unterstützt."
                );
            }

            Desktop desktop = Desktop.getDesktop();
            if (!desktop.isSupported(Desktop.Action.BROWSE)) {
                throw new IllegalStateException(
                        "Das Öffnen von Websites wird auf diesem System nicht unterstützt."
                );
            }

            desktop.browse(websiteUri);
        } catch (IllegalArgumentException
                 | IllegalStateException
                 | IOException
                 | URISyntaxException exception) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Website konnte nicht geöffnet werden");
            alert.setHeaderText(null);
            alert.setContentText(
                    "Die gespeicherte Website ist ungültig oder konnte nicht geöffnet werden."
            );
            alert.showAndWait();
        }
    }

    private URI normalizeWebsiteUri(String website) throws URISyntaxException {
        if (website == null || website.trim().isEmpty()) {
            throw new IllegalArgumentException("Die Website ist leer.");
        }

        String normalizedWebsite = website.trim();
        if (!normalizedWebsite.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*$")) {
            normalizedWebsite = "https://" + normalizedWebsite;
        }

        URI uri = new URI(normalizedWebsite);
        String scheme = uri.getScheme();
        if (scheme == null
                || (!scheme.equalsIgnoreCase("http")
                && !scheme.equalsIgnoreCase("https"))
                || uri.getHost() == null) {
            throw new IllegalArgumentException("Die Website-URL ist ungültig.");
        }
        return uri;
    }

    private void handleChangeMasterPassword() {
        Stage changePasswordStage = new Stage();
        VBox root = new VBox();
        root.getStyleClass().add("dialog-root");
        root.setAlignment(Pos.CENTER);
        root.setSpacing(10);

        PasswordField currentPasswordField = new PasswordField();
        currentPasswordField.setPromptText("Aktuelles Master-Passwort");
        PasswordField newPasswordField = new PasswordField();
        newPasswordField.setPromptText("Neues Master-Passwort");
        PasswordField repeatPasswordField = new PasswordField();
        repeatPasswordField.setPromptText("Neues Master-Passwort wiederholen");
        Label strengthLabel = new Label("Passwortstärke: Sehr schwach");
        Label errorLabel = new Label();

        newPasswordField.textProperty().addListener(
                (observable, oldValue, newValue) ->
                        strengthLabel.setText(
                                "Passwortstärke: "
                                        + passwordStrengthEvaluator.evaluate(newValue)
                        )
        );

        Button changeButton = new Button("Master-Passwort ändern");
        changeButton.getStyleClass().add("primary-button");
        currentPasswordField.getStyleClass().add("input-field");
        newPasswordField.getStyleClass().add("input-field");
        repeatPasswordField.getStyleClass().add("input-field");
        strengthLabel.getStyleClass().add("strength-label");
        changeButton.setOnAction(event -> {
            String currentPassword = currentPasswordField.getText();
            String newPassword = newPasswordField.getText();
            String repeatedPassword = repeatPasswordField.getText();

            if (currentPassword.isEmpty()
                    || newPassword.isEmpty()
                    || repeatedPassword.isEmpty()) {
                errorLabel.setText("Bitte alle Felder ausfüllen.");
                return;
            }

            if (!newPassword.equals(repeatedPassword)) {
                errorLabel.setText("Die neuen Passwörter stimmen nicht überein.");
                return;
            }

            try {
                EncryptionSession newSession =
                        loginService.changeMasterPassword(
                                currentUser,
                                currentPassword,
                                newPassword,
                                encryptionSession
                        );
                encryptionSession = newSession;
                passwordEntryRepository =
                        new PasswordEntryRepository(newSession);
                refreshDashboard();
                changePasswordStage.close();

                Alert successAlert = new Alert(Alert.AlertType.INFORMATION);
                successAlert.setTitle("Master-Passwort geändert");
                successAlert.setHeaderText(null);
                successAlert.setContentText(
                        "Das Master-Passwort wurde erfolgreich geändert."
                );
                successAlert.showAndWait();
            } catch (RuntimeException exception) {
                errorLabel.setText(
                        "Das Master-Passwort konnte nicht geändert werden."
                );
            }
        });

        root.getChildren().add(currentPasswordField);
        root.getChildren().add(newPasswordField);
        root.getChildren().add(repeatPasswordField);
        root.getChildren().add(strengthLabel);
        root.getChildren().add(errorLabel);
        root.getChildren().add(changeButton);

        changePasswordStage.setTitle("Master-Passwort ändern");
        Scene changePasswordScene = new Scene(root, 420, 300);
        applyStylesheet(changePasswordScene);
        changePasswordStage.setScene(changePasswordScene);
        changePasswordStage.setOnHidden(event -> {
            currentPasswordField.clear();
            newPasswordField.clear();
            repeatPasswordField.clear();
        });
        changePasswordStage.show();
    }

    private void handleBackupExport() {
        FileChooser fileChooser = createBackupFileChooser();
        File selectedFile = fileChooser.showSaveDialog(dashboardStage);
        if (selectedFile == null) {
            return;
        }

        String[] passwords = showBackupPasswordDialog("Backup exportieren", true);
        if (passwords == null) {
            return;
        }

        try {
            BackupContainer container = backupService.exportUser(
                    currentUser,
                    passwords[0],
                    encryptionSession
            );
            backupFileService.write(
                    container,
                    ensureBackupExtension(selectedFile).toPath()
            );
            showBackupMessage(
                    Alert.AlertType.INFORMATION,
                    "Backup exportiert",
                    "Das Backup wurde erfolgreich exportiert."
            );
        } catch (IOException | RuntimeException exception) {
            showBackupMessage(
                    Alert.AlertType.ERROR,
                    "Backup-Export fehlgeschlagen",
                    "Das Backup konnte nicht exportiert werden."
            );
        }
    }

    private void handleBackupImport() {
        FileChooser fileChooser = createBackupFileChooser();
        File selectedFile = fileChooser.showOpenDialog(dashboardStage);
        if (selectedFile == null) {
            return;
        }

        String[] passwords = showBackupPasswordDialog("Backup importieren", false);
        if (passwords == null) {
            return;
        }

        try {
            BackupContainer container = backupFileService.read(selectedFile.toPath());
            BackupPayload payload = backupEncryptionService.decrypt(
                    container,
                    passwords[0]
            );
            if (currentUser.getUsername().equals(payload.getUsername())) {
                String[] currentPasswords = showSinglePasswordDialog(
                        "Aktuelles Master-Passwort"
                );
                if (currentPasswords == null) {
                    return;
                }
                EncryptionSession restoredSession =
                        backupRestoreService.restore(
                                container,
                                passwords[0],
                                currentUser,
                                currentPasswords[0],
                                encryptionSession
                        );
                encryptionSession = restoredSession;
                passwordEntryRepository =
                        new PasswordEntryRepository(restoredSession);
                refreshDashboard();
            } else {
                String[] newMasterPasswords =
                        showNewMasterPasswordDialog(payload.getUsername());
                if (newMasterPasswords == null) {
                    return;
                }
                backupImportService.importBackup(
                        container,
                        passwords[0],
                        newMasterPasswords[0]
                ).clear();
            }
            showBackupMessage(
                    Alert.AlertType.INFORMATION,
                    "Backup importiert",
                    currentUser.getUsername().equals(payload.getUsername())
                            ? "Das Backup wurde erfolgreich wiederhergestellt."
                            : "Das Backup wurde als neuer Benutzer importiert."
            );
        } catch (GeneralSecurityException exception) {
            showBackupMessage(
                    Alert.AlertType.ERROR,
                    "Backup-Import fehlgeschlagen",
                    "Das Backup-Passwort ist falsch oder das Backup ist ungültig."
            );
        } catch (IOException exception) {
            showBackupMessage(
                    Alert.AlertType.ERROR,
                    "Backup-Import fehlgeschlagen",
                    "Die Backup-Datei ist beschädigt oder ungültig."
            );
        } catch (RuntimeException exception) {
            showBackupMessage(
                    Alert.AlertType.ERROR,
                    "Backup-Import fehlgeschlagen",
                    exception.getMessage() != null
                            && exception.getMessage().contains("existiert bereits")
                            ? "Der Benutzername existiert bereits."
                            : "Das Backup konnte nicht importiert werden."
            );
        }
    }

    private FileChooser createBackupFileChooser() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter(
                        "Password-Manager-Backup (*.pmb)",
                        "*.pmb"
                )
        );
        return fileChooser;
    }

    private File ensureBackupExtension(File file) {
        if (file.getName().toLowerCase().endsWith(".pmb")) {
            return file;
        }
        return new File(file.getParentFile(), file.getName() + ".pmb");
    }

    private String[] showBackupPasswordDialog(String title, boolean repeat) {
        Stage passwordStage = new Stage();
        VBox root = new VBox();
        root.getStyleClass().add("dialog-root");
        root.setAlignment(Pos.CENTER);
        root.setSpacing(10);

        PasswordField passwordField = new PasswordField();
        passwordField.setPromptText("Backup-Passwort");
        PasswordField repeatField = new PasswordField();
        repeatField.setPromptText("Backup-Passwort wiederholen");
        Label errorLabel = new Label();
        Button confirmButton = new Button(repeat ? "Exportieren" : "Importieren");
        confirmButton.getStyleClass().add("primary-button");
        passwordField.getStyleClass().add("input-field");
        repeatField.getStyleClass().add("input-field");
        errorLabel.getStyleClass().add("status-error");
        final String[][] result = new String[1][];

        confirmButton.setOnAction(event -> {
            String password = passwordField.getText();
            if (password.isEmpty()) {
                errorLabel.setText("Bitte ein Backup-Passwort eingeben.");
                return;
            }
            if (repeat && !password.equals(repeatField.getText())) {
                errorLabel.setText(
                        "Die Backup-Passwörter stimmen nicht überein."
                );
                return;
            }
            result[0] = new String[]{password};
            passwordStage.close();
        });

        root.getChildren().add(passwordField);
        if (repeat) {
            root.getChildren().add(repeatField);
        }
        root.getChildren().add(errorLabel);
        root.getChildren().add(confirmButton);
        passwordStage.setTitle(title);
        Scene backupPasswordScene = new Scene(root, 380, repeat ? 220 : 180);
        applyStylesheet(backupPasswordScene);
        passwordStage.setScene(backupPasswordScene);
        passwordStage.setOnHidden(event -> {
            passwordField.clear();
            repeatField.clear();
        });
        passwordStage.showAndWait();
        return result[0];
    }

    private String[] showSinglePasswordDialog(String title) {
        Stage passwordStage = new Stage();
        VBox root = new VBox();
        root.getStyleClass().add("dialog-root");
        root.setAlignment(Pos.CENTER);
        root.setSpacing(10);

        PasswordField passwordField = new PasswordField();
        passwordField.setPromptText(title);
        Label errorLabel = new Label();
        Button confirmButton = new Button("Bestätigen");
        confirmButton.getStyleClass().add("primary-button");
        passwordField.getStyleClass().add("input-field");
        errorLabel.getStyleClass().add("status-error");
        final String[][] result = new String[1][];

        confirmButton.setOnAction(event -> {
            if (passwordField.getText().isEmpty()) {
                errorLabel.setText("Bitte das Passwort eingeben.");
                return;
            }
            result[0] = new String[]{passwordField.getText()};
            passwordStage.close();
        });

        root.getChildren().add(passwordField);
        root.getChildren().add(errorLabel);
        root.getChildren().add(confirmButton);
        passwordStage.setTitle(title);
        Scene singlePasswordScene = new Scene(root, 380, 180);
        applyStylesheet(singlePasswordScene);
        passwordStage.setScene(singlePasswordScene);
        passwordStage.setOnHidden(event -> passwordField.clear());
        passwordStage.showAndWait();
        return result[0];
    }

    private String[] showNewMasterPasswordDialog(String username) {
        Stage passwordStage = new Stage();
        VBox root = new VBox();
        root.getStyleClass().add("dialog-root");
        root.setAlignment(Pos.CENTER);
        root.setSpacing(10);

        PasswordField passwordField = new PasswordField();
        passwordField.setPromptText("Neues Master-Passwort");
        PasswordField repeatField = new PasswordField();
        repeatField.setPromptText("Neues Master-Passwort wiederholen");
        Label strengthLabel = new Label("Passwortstärke: Sehr schwach");
        Label usernameLabel = new Label("Backup-Benutzer: " + username);
        Label errorLabel = new Label();
        Button confirmButton = new Button("Importieren");
        confirmButton.getStyleClass().add("primary-button");
        passwordField.getStyleClass().add("input-field");
        repeatField.getStyleClass().add("input-field");
        strengthLabel.getStyleClass().add("strength-label");
        usernameLabel.getStyleClass().add("secondary-text");
        errorLabel.getStyleClass().add("status-error");
        final String[][] result = new String[1][];

        passwordField.textProperty().addListener(
                (observable, oldValue, newValue) ->
                        strengthLabel.setText(
                                "Passwortstärke: "
                                        + passwordStrengthEvaluator.evaluate(newValue)
                        )
        );
        confirmButton.setOnAction(event -> {
            String password = passwordField.getText();
            if (password.isEmpty()) {
                errorLabel.setText("Bitte ein neues Master-Passwort eingeben.");
                return;
            }
            if (!password.equals(repeatField.getText())) {
                errorLabel.setText(
                        "Die Master-Passwörter stimmen nicht überein."
                );
                return;
            }
            result[0] = new String[]{password};
            passwordStage.close();
        });

        root.getChildren().add(passwordField);
        root.getChildren().add(repeatField);
        root.getChildren().add(usernameLabel);
        root.getChildren().add(strengthLabel);
        root.getChildren().add(errorLabel);
        root.getChildren().add(confirmButton);
        passwordStage.setTitle("Neues Master-Passwort festlegen");
        Scene newMasterPasswordScene = new Scene(root, 420, 240);
        applyStylesheet(newMasterPasswordScene);
        passwordStage.setScene(newMasterPasswordScene);
        passwordStage.setOnHidden(event -> {
            passwordField.clear();
            repeatField.clear();
        });
        passwordStage.showAndWait();
        return result[0];
    }

    private void showBackupMessage(
            Alert.AlertType type,
            String title,
            String message) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

private void handleLogout() {
    dashboardStage.close();
}

private void clearEncryptionSession() {
        if (encryptionSession != null) {
            encryptionSession.clear();
            encryptionSession = null;
        }
    }

    private void clearSensitiveUi() {
        if (loginPasswordField != null) {
            loginPasswordField.clear();
        }
        if (entriesBox != null) {
            entriesBox.getChildren().clear();
        }
        allEntries.clear();
        if (searchField != null) {
            searchField.clear();
        }
        currentUser = null;
        passwordEntryRepository = null;
    }

    private void showLoginStage() {
        if (loginStage != null) {
            loginStage.show();
            loginStage.toFront();
        }
    }

    private void applyStylesheet(Scene scene) {
        var stylesheet = getClass().getResource("/style.css");
        if (stylesheet == null) {
            throw new IllegalStateException("Das UI-Stylesheet konnte nicht geladen werden.");
        }
        scene.getStylesheets().add(stylesheet.toExternalForm());
    }

}