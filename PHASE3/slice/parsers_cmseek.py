"""Parser cmseek — journal terminal, constat de détection CMS.

CMSeeK 1.1.3 ne rend pas de JSON lisible au stdout : il logge avec des codes
colorés (retirés ici) et écrit un rapport JSON dans <cwd>/Result/ — chemin NON
paramétrable (mesuré), donc hors autorité. Le journal l'est :

  [i] Scanning Site: http://127.0.0.1:8807
  [*] CMS Detected, CMS ID: wordpress, Detection method: generator_meta
  [x] CMS Detection failed, if you know the cms please help me improve CMSeeK…

Un échec de détection N'EST PAS un item : le parser rend [] et le cœur nomme le
vide (« aucun_item_lisible »). Un CMS détecté est une caractérisation d'empreinte
— pas une vulnérabilité : pas de sévérité, jamais inventée ici.
"""
from __future__ import annotations

import re

from parsers import enregistrer

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_DETEKT = re.compile(
    r"^\[\*\]\s*CMS Detected,\s*CMS ID:\s*(?P<cms>[^,]+?),\s*"
    r"Detection method:\s*(?P<meth>.+?)\s*$"
)
_SITE = re.compile(r"^\[i\]\s*Scanning Site:\s*(?P<url>\S+)\s*$")


def _nu(texte: str) -> list[str]:
    return [_ANSI.sub("", l).strip() for l in (texte or "").splitlines()]


@enregistrer("cmseek")
def parser_cmseek(stdout: str) -> list[dict]:
    lignes = _nu(stdout)
    url = ""
    for ligne in lignes:
        m = _SITE.match(ligne)
        if m:
            url = m.group("url")
            break
    items: list[dict] = []
    for ligne in lignes:
        m = _DETEKT.match(ligne)
        if not m:
            continue
        items.append({
            "regle": "cms-detect",
            "nom_regle": m.group("cms").strip(),
            "url": url,
            "message": f"Detection method: {m.group('meth').strip()}",
            "confiance": "confirmée",
        })
    return items
