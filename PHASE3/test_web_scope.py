#!/usr/bin/env python3
"""Périmètre web : canonicalisation, scope, budgets, exclusions (+ adversarial).

Chaque cas se lit `entrée → décision attendue`. Aucun réseau, aucun paquet.

Usage : python PHASE3/test_web_scope.py
"""
from __future__ import annotations

import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

from cible import CibleError                                  # noqa: E402
from web_scope import (ScopeEnforcer, canonicaliser_url,      # noqa: E402
                       dans_perimetre, hote_de)

CAS: list[tuple[str, bool, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond: bool, detail: str = "") -> None:
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


def cas_rejet(nom: str, url: str) -> None:
    try:
        canonicaliser_url(url)
        cas(nom, False, f"acceptée : {url!r}")
    except CibleError as e:
        cas(nom, True, str(e)[:80])
    except Exception as e:                                    # jamais d'autre fuite
        cas(nom, False, f"{type(e).__name__} au lieu de CibleError")


def main() -> int:
    # ------------------------------------------------------- canonicalisation
    for nom, entree, attendu in [
        ("minuscules + port défaut + slash", "HTTPS://HOTE:443/a/",
         "https://hote/a"),
        ("port 80 supprimé", "http://hote:80/", "http://hote/"),
        ("port explicite conservé", "https://hote:8443/a", "https://hote:8443/a"),
        ("fragment supprimé", "https://hote/a#b", "https://hote/a"),
        ("userinfo supprimé", "https://u:p@hote/a", "https://hote/a"),
        ("query conservée", "https://hote/a?x=1", "https://hote/a?x=1"),
        ("racine sans slash", "https://hote", "https://hote/"),
    ]:
        try:
            cas(nom, canonicaliser_url(entree) == attendu,
                f"{canonicaliser_url(entree)!r} != {attendu!r}")
        except CibleError as e:
            cas(nom, False, f"rejet inattendu : {e}")
    # Idempotence : canonicaliser deux fois = même résultat.
    cas("idempotence", canonicaliser_url(canonicaliser_url("HTTPS://H:443/a/"))
        == "https://h/a")
    # ------------------------------------------------------- rejets + adversarial
    for nom, url in [
        ("vide rejetée", "   "),
        ("sans schéma rejetée", "hote/a"),
        ("file:// rejeté", "file:///etc/passwd"),
        ("ftp rejeté", "ftp://hote/a"),
        ("javascript: rejeté", "javascript:alert(1)"),
        ("hôte manquant rejeté", "https://"),
        ("contrôle rejeté", "https://ho\nte/"),
        ("port alpha rejeté", "https://hote:abc/"),
    ]:
        cas_rejet(nom, url)
    # ------------------------------------------------------- scope
    cas("égalité exacte stricte",
        dans_perimetre("https://hote/a", ["hote"], strict=True))
    cas("sous-domaine refusé en strict",
        not dans_perimetre("https://sub.hote/a", ["hote"], strict=True))
    cas("sous-domaine admis en non-strict",
        dans_perimetre("https://sub.hote/a", ["hote"], strict=False))
    cas("@-trick : l'hôte est après le @",
        hote_de(canonicaliser_url("https://trusted@evil.com/")) == "evil.com"
        and not dans_perimetre(canonicaliser_url("https://trusted@evil.com/"),
                               ["trusted"], strict=True))
    cas("autorisés normalisés (schéma, casse, port)",
        dans_perimetre("https://hote/a", ["HTTPS://HOTE:443/"], strict=True))
    # ------------------------------------------------------- enforcer
    enf = ScopeEnforcer(autorises=["target.tld"], strict=True, max_urls=2)
    cas("autoriser ne consomme pas",
        enf.autoriser("https://target.tld/a") == (True, "autorise")
        and enf.urls_distinctes == 0)
    cas("hors périmètre nommé",
        enf.autoriser("https://autre.tld/") == (False, "hors_perimetre : autre.tld"))
    cas("/.git exclu", enf.autoriser("https://target.tld/.git/config")[0] is False
        and "exclu" in enf.autoriser("https://target.tld/.git/config")[1])
    cas("/.env exclu", enf.autoriser("https://target.tld/.env")[1].startswith("exclu"))
    cas("/.environment PAS exclu (préfixe exact)",
        enf.autoriser("https://target.tld/.environment")[0] is True)
    cas("budget : 2 urls puis épuisé",
        enf.enregistrer("https://target.tld/a") == (True, "enregistre")
        and enf.enregistrer("https://target.tld/b") == (True, "enregistre")
        and enf.enregistrer("https://target.tld/c") == (False, "budget_epuise : 2 urls distinctes"))
    cas("ré-enregistrer la même url ne consomme pas",
        enf.enregistrer("https://target.tld/a") == (True, "enregistre")
        and enf.urls_distinctes == 2)
    cas("deux écritures = même canonique (dédup)",
        enf.enregistrer("HTTPS://TARGET.TLD:443/a/") == (True, "enregistre")
        and enf.urls_distinctes == 2)

    print(f"\n{'=' * 50}\n  {len(CAS) - len(ECHECS)}/{len(CAS)} cas passent\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if not cond:
            print(f"  ÉCHEC · {nom}\n        {detail}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
