---
status: done
---

# Instruction: Contrôle `custom`

## Tasks to do

1. `config.rs` : `CustomCheck`, `Site.custom_checks`, validation (grammaire, unicité, bornes).
2. `checks/custom.rs` et `CheckKind::Custom` ; `capability.rs` (`Needs::CustomChecks`).
3. Tests : configuration (valide, chaque refus) ; contrôle contre un serveur de test (statut, texte présent, texte absent, injoignable, redirection, plusieurs règles) ; registre.
4. Documentation : `config.example.toml`, doc des contrôles ; console : libellé du contrôle, retrait de l'encart `personnalises`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Chaque refus de configuration nomme le site et la règle ; deux règles de même `id` sur un site sont refusées, sur deux sites elles sont admises |
| 2 | Un site sans règle n'a pas de contrôle `custom` surveillé ; avec une règle, oui, quel que soit son CMS |
| 3 | Une règle en échec ouvre un constat de clé égale à son `id` ; une règle qui passe n'en ouvre aucun ; une règle ne masque pas les autres |
| 4 | La console affiche le contrôle `custom` sans l'encart « pas encore disponible » |
