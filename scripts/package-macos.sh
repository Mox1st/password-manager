#!/bin/sh

set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"

if [ "$(uname -s)" != "Darwin" ]; then
    echo "macOS wird fuer jpackage --type dmg benoetigt." >&2
    exit 1
fi

if [ "$(uname -m)" != "arm64" ]; then
    echo "Dieses Packaging-Skript erwartet macOS Apple Silicon (arm64)." >&2
    exit 1
fi

app_name=$(mvn -q -DforceStdout help:evaluate -Dexpression=app.name)
app_version=$(mvn -q -DforceStdout help:evaluate -Dexpression=project.version)
main_class=$(mvn -q -DforceStdout help:evaluate -Dexpression=app.mainClass)
input_dir="target/app-input"
dist_dir="target/dist"

rm -rf "$input_dir" "$dist_dir"
mkdir -p "$input_dir" "$dist_dir"

mvn -q clean package dependency:copy-dependencies \
    -DincludeScope=runtime \
    -DoutputDirectory="$input_dir"
cp "target/password-manager-${app_version}.jar" "$input_dir/"

jpackage \
    --type app-image \
    --name "$app_name" \
    --app-version "$app_version" \
    --input "$input_dir" \
    --dest "$dist_dir" \
    --main-jar "password-manager-${app_version}.jar" \
    --main-class "$main_class" \
    --module-path "$input_dir" \
    --add-modules javafx.controls,javafx.fxml,java.sql,jdk.crypto.ec \
    --mac-package-identifier de.mox1st.passwordmanager

jpackage \
    --type dmg \
    --name "$app_name" \
    --app-version "$app_version" \
    --dest "$dist_dir" \
    --app-image "$dist_dir/${app_name}.app" \
    --mac-package-identifier de.mox1st.passwordmanager

generated_dmg="$dist_dir/${app_name}-${app_version}.dmg"
release_dmg="$dist_dir/PasswordManager-${app_version}.dmg"
if [ -f "$generated_dmg" ]; then
    mv "$generated_dmg" "$release_dmg"
fi

echo "App: $dist_dir/${app_name}.app"
echo "DMG: $release_dmg"