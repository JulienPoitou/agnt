"""Parser sslscan — XML de sortie, observations de surface TLS OFFERTE.

sslscan rend son XML (« --xml=- »). Le parser ne retient que ce que le serveur AFFIRME :
un protocole activé (enabled="1"), une suite de chiffrement offerte (status
accepted/preferred), une renégociation insécurisée (secure="0" avec renégociation
supportée). Tout le reste (protocoles désactivés, suites rejetées) n'est pas une surface
— le produire en constat serait du bruit. Sur une cible sans TLS (mesuré : THAUMAS-WEB,
tous protocoles enabled=0, aucun élément cipher), le parser rend zéro item : résultat
vide nommé par le cœur, pas un « scan propre » déguisé. Le chemin « surface présente »
lit les attributs du XML de sslscan 2.1.5 ; il n'est pas mesuré sur cible TLS réelle
(aucune cible TLS autorisée dans la qualification). Sévérité : sslscan n'en porte pas —
absente, jamais inventée ici.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from parsers import enregistrer

STATUS_OFFERTS = ("accepted", "preferred")


def _preuve(element: ET.Element) -> str:
    return "attributs sslscan : " + " ".join(
        f"{k}={v}" for k, v in sorted(element.attrib.items()))


@enregistrer("sslscan")
def parser_sslscan(stdout: str) -> list[dict]:
    texte = (stdout or "").strip()
    if not texte:
        return []
    try:
        racine = ET.fromstring(texte)
    except ET.ParseError:
        return []          # XML tronqué/illisible : aucun item, jamais d'invention
    items: list[dict] = []
    for ssltest in racine.iter("ssltest"):
        hote = ssltest.get("host") or ""
        port = ssltest.get("port") or ""
        url = f"{hote}:{port}" if hote and port else hote
        for protocole in ssltest.iter("protocol"):
            if protocole.get("enabled") == "1":
                items.append({
                    "regle": "sslscan-protocol",
                    "nom_regle": f"{protocole.get('type', '?')} {protocole.get('version', '?')}".strip(),
                    "message": "protocole activé côté serveur",
                    "url": url,
                    "reference": "https://github.com/rbsec/sslscan",
                    "preuve": _preuve(protocole),
                })
        for cipher in ssltest.iter("cipher"):
            if (cipher.get("status") or "") in STATUS_OFFERTS:
                items.append({
                    "regle": "sslscan-cipher",
                    "nom_regle": cipher.get("cipher") or "?",
                    "message": f"suite de chiffrement offerte ({cipher.get('status')})",
                    "url": url,
                    "reference": "https://github.com/rbsec/sslscan",
                    "preuve": _preuve(cipher),
                })
        for rene in ssltest.iter("renegotiation"):
            if rene.get("supported") == "1" and rene.get("secure") == "0":
                items.append({
                    "regle": "sslscan-renegotiation",
                    "nom_regle": "renégociation TLS non sécurisée",
                    "message": "renégociation supportée mais non sécurisée (secure=0)",
                    "url": url,
                    "reference": "https://github.com/rbsec/sslscan",
                    "preuve": _preuve(rene),
                })
    return items
