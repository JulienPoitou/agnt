"""Parser git-dumper — sortie texte, un constat d'exposition de dépôt.

git-dumper ne rend pas de JSON : il logge ses récupérations (« [-] Fetching <url>
[code] ») et finit par « [-] Running git checkout . » quand le dépôt est restauré.
Un dépôt .git exposé et dumpé est une faille d'information en soi : la preuve est
la liste des chemins récupérés. La sévérité n'est pas portée par l'outil — elle
reste absente, jamais inventée ici.
"""
from __future__ import annotations

from parsers import enregistrer

PREF = "[-] Fetching "
SUF = " [200]"


@enregistrer("gitdumper")
def parser_gitdumper(stdout: str) -> list[dict]:
    recup = []
    for brut in stdout.splitlines():
        ligne = brut.strip()
        if ligne.startswith(PREF) and ligne.endswith(SUF):
            recup.append(ligne[len(PREF):-len(SUF)])
    if not recup:
        return []
    restaure = any("Running git checkout" in l for l in stdout.splitlines())
    return [{
        "regle": "git-dump",
        "nom_regle": "dépôt .git exposé et restauré" if restaure else "dépôt .git exposé (dump partiel)",
        "message": f"{len(recup)} fichier(s) récupérés depuis l'URL .git exposée",
        "confiance": "confirmée" if restaure else "moyenne",
        "remediation": ("Servir une arborescence sans /.git/ ; bloquer l'accès aux "
                        "métadonnées de gestion de version au niveau du serveur web."),
        "reference": "https://github.com/arthaud/git-dumper",
        "cwe": "CWE-538",
        "preuve": " ; ".join(recup[:12]),
    }]
