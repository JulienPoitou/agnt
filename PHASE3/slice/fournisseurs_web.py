"""Providers web : planification + interprétation via les manifests du registre (Stream B).

AUCUNE logique d'outil ici : argv, formats, champs et codes de succès viennent
du manifest déclaré (`capabilities.yaml` via `Registry`), la normalisation de
`findings.depuis_manifest`, les parsers custom de `parsers_*`. Ce module ne fait
que brancher ces pièces pour une cible URL — le même chemin que les adapters,
sans sandbox (le sandboxing arrive avec le runtime Linux).

Marquage honnête : `planifier` ne résout PAS le binaire (`binaire_resolu False`
— la résolution PATH/cache + refus D1 a lieu à l'exécution) et
`RUNTIME_VERIFIED = False` tant qu'aucune sortie réelle n'a été mesurée.
"""
from __future__ import annotations

import dataclasses
import json

RUNTIME_VERIFIED = False


class ErreurPlanification(Exception):
    """Plan web impossible : provider, cible ou egress nommés."""


def charger_manifest(provider_id: str, registre=None):
    """Le manifest déclaré du provider, ou l'erreur du registre telle quelle.

    Un provider SANS manifest (adaptateur historique local) ne peut pas servir
    une cible distante : refusé nommément, pas deviné.
    """
    if registre is None:
        from registre import Registry
        registre = Registry()
    prov = registre.provider(provider_id)
    if prov is None or getattr(prov, "manifest", None) is None:
        raise ErreurPlanification(
            f"{provider_id} : sans manifest déclaratif — inapte à une cible url")
    return prov.manifest


def _hote_port(url_canonique: str) -> str:
    """Forme hôte:port d'une URL canonique — le jeton {HOSTPORT}.

    sslscan et sslyze refusent une URL (mesuré contre THAUMAS-WEB : « Invalid
    target specified. » / « Not a valid host:port ») : la cible TLS leur passe par
    cette forme. Le port par défaut du schéma est RESTAURÉ — la canonicalisation
    le retire, mais un https:// sans port explicite est un 443 réel pour l'outil.
    """
    from urllib.parse import urlsplit
    parts = urlsplit(url_canonique)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{(parts.hostname or '').lower()}:{port}"


def _controle_refuse(valeur: str) -> str:
    """Motif de refus si la valeur porte un caractère de contrôle, sinon vide.

    Un saut de ligne (ou \r, \0, tabulation…) dans un cookie, c'est de
    l'injection d'en-tête CHEZ L'OUTIL : refusé ici, à la source trusted, et
    pas seulement à l'API — `planifier` est appelable par d'autres chemins que
    le POST. `\x7f` (DEL) est refusé avec les autres.
    """
    for c in valeur:
        if ord(c) < 32 or ord(c) == 127:
            return (f"auth_cookies : caractère de contrôle {ord(c)} refusé "
                    f"(un saut de ligne dans un cookie est une injection d'en-tête)")
    return ""


def planifier(provider_id: str, url_canonique: str, out_dir: str,
              egress: bool = False, registre=None, regles: str = "",
              auth_cookies: str = "") -> dict:
    """Plan d'exécution d'un provider web sur une URL canonique.

    Refus nommés : provider inconnu (registre), cible non-`url` au manifest,
    egress requis mais non accordé, caractère de contrôle dans `auth_cookies`.
    L'argv garde `{BIN}` sous le nom du binaire déclaré — résolu à l'exécution
    seulement. `regles` alimente `{REGLES}` (données d'entrée épinglées :
    template nuclei d'épreuve, wordlist ffuf) ; vide, les providers qui
    l'exigent échoueront NOMMÉMENT à l'exécution — jamais silencieusement.

    `auth_cookies` (scan authentifié v1) alimente `{COOKIES}` — chaîne vide si
    aucune valeur fournie. Le jeton est OPT-IN : un manifest qui ne le déclare
    pas ne reçoit rien, et le plan le dit (`auth.declare`). La valeur elle-même
    n'est JAMAIS rendue ici autrement que dans l'argv résolu (transitoire) :
    le plan porte seulement `auth: {declare, fournie}` — jamais le secret.
    """
    try:
        mani = charger_manifest(provider_id, registre)
    except ErreurPlanification:
        raise
    except Exception as e:
        raise ErreurPlanification(
            f"{provider_id} : provider inconnu ou manifest refusé ({e})") from None
    if "url" not in tuple(getattr(mani, "cibles", ()) or ()):
        raise ErreurPlanification(
            f"{provider_id} : non applicable à une url (cibles : {list(mani.cibles)})")
    if getattr(mani, "reseau", False) and not egress:
        raise ErreurPlanification(
            f"{provider_id} : egress requis (outil réseau) — accorder pour cette mission")
    if not isinstance(auth_cookies, str):
        raise ErreurPlanification(f"{provider_id} : auth_cookies : chaîne attendue")
    if auth_cookies and len(auth_cookies.encode("utf-8")) > 4096:
        raise ErreurPlanification(
            f"{provider_id} : auth_cookies trop longs "
            f"({len(auth_cookies.encode('utf-8'))} > 4096 octets)")
    motif_controle = _controle_refuse(auth_cookies)
    if motif_controle:
        raise ErreurPlanification(f"{provider_id} : {motif_controle}")
    from provider_manifest import resoudre_argv
    nom_sortie = f"{mani.id}.{mani.sortie_format}"
    chemins = {"BIN": mani.binaire, "URL": url_canonique, "TARGET": url_canonique,
               "OUT": f"{out_dir}/{nom_sortie}", "OUT_DIR": out_dir,
               "REGLES": str(regles or ""), "DB": "",
               "HOSTPORT": _hote_port(url_canonique),
               "COOKIES": str(auth_cookies or "")}
    try:
        argv = resoudre_argv(mani, chemins)
    except Exception as e:
        raise ErreurPlanification(f"{provider_id} : argv irrésolvable ({e})") from None
    if not auth_cookies:
        # Sans cookie fourni, un jeton {COOKIES} qui se résout en arg VIDE rend la
        # tâche inconstructible (Tache exige des chaînes non vides) et laisserait un
        # flag orphelin. Retrait DÉTERMINISTE de la paire (flag, arg vide) : l'arg
        # porte-{COOKIES} du manifest est vide ET l'arg qui précède est un flag
        # (commence par -). Un arg non vide ("Cookie: " — header vide) est CONSERVÉ,
        # mesuré inoffensif. Avec cookie, rien n'est retiré. Mesuré THAUMAS
        # 2026-09-05 : ffuf -b transmet le cookie, le constat protégé n'apparaît
        # qu'avec ; sans cookie la paire -b/vide est retirée.
        indices = [i for i, a in enumerate(mani.argv) if "{COOKIES}" in str(a)]
        retirer = set()
        for i in indices:
            if i < len(argv) and argv[i] == "" and i > 0 and argv[i - 1].startswith("-"):
                retirer.update({i - 1, i})
        if retirer:
            argv = [a for j, a in enumerate(argv) if j not in retirer]
    declare = any("{COOKIES}" in a for a in mani.argv)
    return {"provider_id": provider_id, "argv": argv, "binaire": mani.binaire,
            "binaire_resolu": False, "codes_succes": list(mani.code_succes),
            "timeout_s": int(getattr(mani, "timeout_s", 0) or 0),
            "risque": getattr(mani, "risque", ""),
            "limite": getattr(mani, "limite", ""),
            "sortie_format": mani.sortie_format,
            "nom_sortie": nom_sortie,
            "auth": {"declare": declare, "fournie": bool(auth_cookies)}}


def interpreter(provider_id: str, code: int, stdout_texte: str = "",
                registre=None) -> dict:
    """Sortie brute → findings normalisés via le manifest. Ne devine jamais :
    sortie illisible = items [], code hors succès = échec nommé."""
    try:
        mani = charger_manifest(provider_id, registre)
    except ErreurPlanification:
        raise
    except Exception as e:
        raise ErreurPlanification(
            f"{provider_id} : provider inconnu ou manifest refusé ({e})") from None
    import extraction as EX
    ex = mani.extraction
    sortie_lue = bool((stdout_texte or "").strip())
    items: list[dict] = []
    ex_eff = ex
    # Comme dans les adapters : le format `custom` délègue au parser nommé,
    # qui est l'autorité sur les items (le manifest reste l'autorité sur les champs).
    sur_mesure = (mani.sortie_format == "custom")
    if sur_mesure:
        import parsers  # noqa: F401 (enregistre les parsers nommés)
        import parsers_zap  # noqa: F401 (enregistre "zap_baseline")
        import parsers_gitdumper  # noqa: F401 (enregistre "gitdumper")
        from parsers import obtenir
        fn = obtenir(getattr(ex, "parser", ""))
        if fn is None:
            return {"provider_id": provider_id, "items": [], "findings": [],
                    "sortie_lue": sortie_lue, "echec": True,
                    "motif": f"parser {getattr(ex, 'parser', '')!r} introuvable"}
        items = fn(stdout_texte or "") or []
        brut: object = {"items": items}
        # Même mapping de champs, modèle plat sur les items parsés : le parser
        # reste l'autorité sur les items, le manifest sur les champs.
        ex_eff = dataclasses.replace(ex, modele="plat", items_from="items")
    elif ex.modele == "lignes_json":
        brut = stdout_texte or ""
        items = EX.extraire(brut, ex_eff)
    else:
        try:
            brut = json.loads(stdout_texte) if sortie_lue else None
        except (ValueError, json.JSONDecodeError):
            brut = None
        items = EX.extraire(brut, ex_eff)
    import findings as F
    try:
        findings = F.depuis_manifest(brut, dataclasses.replace(mani, extraction=ex_eff),
                                     mani.binaire)
    except Exception as e:
        return {"provider_id": provider_id, "items": items, "findings": [],
                "sortie_lue": sortie_lue, "echec": True,
                "motif": f"normalisation_impossible : {type(e).__name__}"}
    echec = code not in tuple(mani.code_succes)
    motif = ""
    if echec:
        motif = f"code {code} hors succès {list(mani.code_succes)}"
    elif not items and not sortie_lue:
        echec, motif = True, "sortie vide : échec d'exécution, pas un scan propre"
    elif not items:
        # Doctrine core (adapters) : code attendu + sortie lue + zéro item =
        # UN RÉSULTAT vide, jamais une preuve d'absence. Le motif le dit.
        motif = "aucun_item_lisible : résultat vide, pas une preuve d'absence"
    return {"provider_id": provider_id, "items": items, "findings": findings,
            "sortie_lue": sortie_lue, "echec": echec, "motif": motif}
