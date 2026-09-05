"""Parser dotdotpwn — sortie texte du module http-url, un constat de path traversal.

dotdotpwn n'a pas de sortie structurée : chaque payload dont la réponse contient le
motif cherché est loggé « [*] Testing URL: <url> <- VULNERABLE ». Plusieurs encodages
du même traversal touchent la même faille : les URL sont agrégées en UN constat, la
preuve étant la liste des URL (tronquée). La sévérité n'est pas portée par l'outil —
elle reste absente, jamais inventée ici.
"""
from __future__ import annotations

from parsers import enregistrer

PREF = "[*] Testing URL: "
MARQUE = "<- VULNERABLE"


@enregistrer("dotdotpwn")
def parser_dotdotpwn(stdout: str) -> list[dict]:
    urls: list[str] = []
    for brut in (stdout or "").splitlines():
        ligne = brut.strip()
        if ligne.startswith(PREF) and ligne.endswith(MARQUE):
            url = ligne[len(PREF):-len(MARQUE)].strip()
            if url and url not in urls:
                urls.append(url)
    if not urls:
        return []
    # `url` = la PREMIÈRE URL vulnérable mesurée (déterministe : la forme canonique ../
    # est la première séquence engendrée par le moteur) ; les autres restent en preuve.
    return [{
        "regle": "path-traversal",
        "nom_regle": "path traversal HTTP confirmé",
        "message": f"{len(urls)} séquence(s) de traversal ont servi le fichier visé",
        "url": urls[0],
        "confiance": "confirmée",
        "remediation": ("Ne pas construire de chemin de fichier à partir d'un paramètre "
                        "contrôlable par le client ; normaliser le chemin et borner la "
                        "racine servie au niveau du serveur web."),
        "reference": "https://github.com/wireghoul/dotdotpwn",
        "cwe": "CWE-22",
        "preuve": " ; ".join(urls[:12]),
    }]
