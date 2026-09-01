# Fixture `testrepo_shell` — cible de test pour shellcheck (SHELL_ANALYSIS)

Fixture STATIQUE (pas d'historique git à reconstruire) : un script volontairement
défectueux et un script propre, pour éprouver shellcheck et son wrapper de
récursion (`shellcheck_scan`).

Les défauts de `deploiement.sh` sont VOLONTAIRES — ne pas « corriger » ce
fichier : la suite `test_outil_shellcheck.py` épingle le NOMBRE de findings.
Ce ne sont pas des secrets (voir `testrepo/` pour les fixtures gitleaks).
