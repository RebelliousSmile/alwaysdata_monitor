#!/usr/bin/env bash
# Sauvegarde et transfert d'appareil coupés pour l'APK de la console : sans
# cela, la sauvegarde automatique ou le transfert vers un nouveau téléphone
# copieraient le jeton, et deux appareils deviendraient indiscernables pour
# la révocation (plan 2026_10_16_console-shell, phase 1).
#
#   scripts/android-no-backup.sh patch            après `tauri android init`
#   scripts/android-no-backup.sh verify <apk>     sur l'APK produit
#
# `fullBackupContent` est ignoré à partir d'Android 12, et `allowBackup`
# seul n'y coupe pas le transfert d'appareil à appareil : il faut aussi
# `dataExtractionRules`. Le jeton vit en plus dans `no_backup` (secret.rs).
#
# Lancé depuis vigie/app. `verify` lit aapt2 dans les build-tools du SDK
# (BUILD_TOOLS_VERSION, ANDROID_HOME).

set -euo pipefail

MAIN=src-tauri/gen/android/app/src/main
MANIFEST=$MAIN/AndroidManifest.xml
RULES=$MAIN/res/xml/data_extraction_rules.xml
DOMAINS="root file database sharedpref"

patch() {
  test -f "$MANIFEST" || { echo "::error::$MANIFEST absent : lancer tauri android init d'abord"; exit 1; }
  if grep -qE 'android:(allowBackup|dataExtractionRules|fullBackupContent)' "$MANIFEST"; then
    echo "::error::le manifeste généré règle déjà la sauvegarde : revoir ce script"
    exit 1
  fi
  mkdir -p "$(dirname "$RULES")"
  {
    echo '<?xml version="1.0" encoding="utf-8"?>'
    echo '<data-extraction-rules>'
    for section in cloud-backup device-transfer; do
      echo "    <$section>"
      for domain in $DOMAINS; do
        echo "        <exclude domain=\"$domain\" path=\".\" />"
      done
      echo "    </$section>"
    done
    echo '</data-extraction-rules>'
  } > "$RULES"
  # Premier <application seulement : les attributs suivent sur leurs lignes.
  sed -i '0,/<application/s//<application android:allowBackup="false" android:dataExtractionRules="@xml\/data_extraction_rules"/' "$MANIFEST"
  test "$(grep -c 'android:allowBackup="false"' "$MANIFEST")" = 1
  test "$(grep -c 'android:dataExtractionRules="@xml/data_extraction_rules"' "$MANIFEST")" = 1
  cat "$RULES"
  grep -n -A3 '<application' "$MANIFEST"
}

verify() {
  local apk=$1
  local aapt2="$ANDROID_HOME/build-tools/$BUILD_TOOLS_VERSION/aapt2"
  local manifest rules path
  manifest=$("$aapt2" dump xmltree --file AndroidManifest.xml "$apk")
  grep -E 'android:(allowBackup|dataExtractionRules)' <<<"$manifest" || true
  grep -qE 'android:allowBackup\([^)]*\)=false' <<<"$manifest" \
    || { echo "::error::allowBackup absent ou vrai dans $apk"; exit 1; }
  grep -qE 'android:dataExtractionRules\([^)]*\)=@' <<<"$manifest" \
    || { echo "::error::dataExtractionRules absent de $apk"; exit 1; }
  # Chemin du fichier dans l'APK : un build release peut raccourcir les
  # chemins des ressources, on le lit dans la table. awk lit tout (pas de
  # exit) : aapt2 coupé par SIGPIPE ferait échouer le pipefail.
  path=$("$aapt2" dump resources "$apk" \
    | awk '/resource .* xml\/data_extraction_rules( |$)/ { found = 1; next } found && !done && /\(file\)/ { print $3; done = 1 }')
  test -n "$path" || { echo "::error::xml/data_extraction_rules absent de $apk"; exit 1; }
  rules=$("$aapt2" dump xmltree --file "$path" "$apk")
  echo "$rules"
  for section in cloud-backup device-transfer; do
    grep -q "E: $section" <<<"$rules" || { echo "::error::$section absent des règles"; exit 1; }
  done
  test "$(grep -c 'E: exclude' <<<"$rules")" = 8 \
    || { echo "::error::règles d'exclusion incomplètes"; exit 1; }
}

case "${1:-}" in
  patch) patch ;;
  verify) verify "${2:?APK attendu}" ;;
  *) echo "usage : $0 patch | verify <apk>" >&2; exit 2 ;;
esac
