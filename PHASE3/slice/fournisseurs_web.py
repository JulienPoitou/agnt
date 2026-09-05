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


def planifier(provider_id: str, url_canonique: str, out_dir: str,
              egress: bool = False, registre=None, regles: str = "") -> dict:
    """Plan d'exécution d'un provider web sur une URL canonique.

    Refus nommés : provider inconnu (registre), cible non-`url` au manifest,
    egress requis mais non accordé. L'argv garde `{BIN}` sous le nom du
    binaire déclaré — résolu à l'exécution seulement. `regles` alimente
    `{REGLES}` (données d'entrée épinglées : template nuclei d'épreuve,
    wordlist ffuf) ; vide, les providers qui l'exigent échoueront NOMMÉMENT
    à l'exécution — jamais silencieusement.
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
    from provider_manifest import resoudre_argv
    nom_sortie = f"{mani.id}.{mani.sortie_format}"
    chemins = {"BIN": mani.binaire, "URL": url_canonique, "TARGET": url_canonique,
               "OUT": f"{out_dir}/{nom_sortie}", "OUT_DIR": out_dir,
               "REGLES": str(regles or ""), "DB": ""}
    try:
        argv = resoudre_argv(mani, chemins)
    except Exception as e:
        raise ErreurPlanification(f"{provider_id} : argv irrésolvable ({e})") from None
    return {"provider_id": provider_id, "argv": argv, "binaire": mani.binaire,
            "binaire_resolu": False, "codes_succes": list(mani.code_succes),
            "timeout_s": int(getattr(mani, "timeout_s", 0) or 0),
            "risque": getattr(mani, "risque", ""),
            "limite": getattr(mani, "limite", ""),
            "sortie_format": mani.sortie_format,
            "nom_sortie": nom_sortie}


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
