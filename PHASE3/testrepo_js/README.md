# testrepo_js — cible de la MESURE ESLint, pas une intégration

Un fichier : `agnt_fixture.js`, deux règles auto-démontrantes (`eval`, `javascript:` URL).

Cette fixture n'existe pas parce qu'ESLint serait intégré — il ne l'est **pas**. Elle existe
parce que le refus doit être rejouable : `PHASE3/test_catalogue_outils.py` (section 7) lance
ESLint sur ce répertoire **depuis deux répertoires courants différents** et montre que le
résultat change (`are ignored`, rc=2 / findings, rc=1). La cage AGNT ne fixe pas le répertoire
de travail d'un outil (`Sandbox.commande()` n'émet pas de `--chdir`, et c'est délibéré) : un
outil qui décide de scanner ou non selon l'endroit où l'opérateur a tapé la commande n'est pas
un outil intégrable en l'état. La décision à prendre est écrite dans
`PHASE3/DECISIONS_PROPOSEES.md` (D8).

Aucun provider du registre ne cible ce répertoire. `ruff` (Python) n'y trouverait qu'un
fichier hors de son périmètre de déclaration.
