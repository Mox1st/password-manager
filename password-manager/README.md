# 🔐 Password Manager

Ein sicherer lokaler Desktop-Passwortmanager für macOS, entwickelt mit Java 26, JavaFX und SQLite.

Der Password Manager ermöglicht es, Zugangsdaten lokal zu speichern, zu verschlüsseln und über verschlüsselte Backups zu sichern.

## ✨ Funktionen

- 🔐 Sichere lokale Passwortverwaltung
- 🔒 AES-256-GCM-Verschlüsselung
- 🔑 PBKDF2-HMAC-SHA256 für das Passwort-Hashing
- 🎲 Passwortgenerator
- 📊 Passwortstärke-Bewertung
- 💾 Verschlüsselte Backups und Restore
- 🔄 Änderung des Master-Passworts
- 👤 Separates Registrierungsfenster
- 🛡️ Schutz vor wiederholten fehlgeschlagenen Login-Versuchen
- 🗄️ Lokale SQLite-Datenbank
- ✅ 57 automatisierte Tests

## 🔐 Sicherheit

Die Anwendung wurde mit Fokus auf lokale Datensicherheit entwickelt.

### Verschlüsselung

- AES-256-GCM für verschlüsselte Passwortdaten
- PBKDF2-HMAC-SHA256 für die Schlüsselableitung
- Individueller Salt für die Schlüsselableitung
- Das Master-Passwort wird nicht im Klartext gespeichert

### Authentifizierung

- Sicheres Passwort-Hashing
- Schutz vor wiederholten fehlgeschlagenen Login-Versuchen
- Migration älterer SHA-256-Hashes auf PBKDF2

### Backup und Restore

- Verschlüsselte Backup-Dateien
- Validierung beim Import
- Benutzer-Isolation beim Restore
- Transaktionssichere Restore-Operationen

## 📦 Download

### macOS

Die aktuelle Version kann über GitHub Releases heruntergeladen werden:

**[Password Manager v1.0.0 herunterladen](https://github.com/Mox1st/password-manager/releases/tag/v1.0.0)**

1. `PasswordManager-1.0.0.dmg` herunterladen
2. DMG-Datei öffnen
3. **Password Manager** in den Ordner **Programme** ziehen
4. Anwendung starten

Die Anwendung enthält eine eigene Java-Laufzeitumgebung. Java und Maven müssen daher nicht separat installiert werden.

> **Hinweis:** Da die Anwendung aktuell nicht von Apple signiert und notarisiert ist, kann macOS beim ersten Start eine Sicherheitswarnung anzeigen.

## 🛠️ Technologien

- Java 26
- JavaFX 26.0.1
- SQLite
- Maven
- JUnit
- jpackage

## 🧪 Tests

Der aktuelle Stand:

```text
Tests run: 57
Failures: 0
Errors: 0
Skipped: 0