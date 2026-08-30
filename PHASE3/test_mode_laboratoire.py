#!/usr/bin/env python3
"""Batterie déterministe du Mode Laboratoire Propriétaire (P2).

Chaque cas construit un laboratoire local temporaire (jamais dans le repo) et
vérifie la décision du point de garde `mode_laboratoire.analyser`. Les
scénarios couvrent :

  1. baseline : désactivé par défaut, comportement identique sans opt-in ;
  2. opt-in : 0 facteur, 1 facteur, jeton invalide, bloc non conforme
     (permissions, symlink, hors conf, dans la cible, contenu) ;
  3. canaux d'activation interdits (HTTP, LLM, UI, cible, fixture, journal,
     artefact, MCP, provider) ;
  4. cible : URL/hôte distant, traversal, hors racine, symlink sortant,
     symlink interne accepté, cible absente, non autorisée ;
  5. profil : public/production/limites_a_prouver/inconnu refusés ;
  6. egress fermé ; capacités limitées au registre AGNT ;
  7. gardes existantes (policy, règles, empreintes, sandbox) requises ;
  8. conservation : contexte/registre/opérateurs/cible_autorisee intacts ;
  9. audit redacted (aucun secret, argv, chemin absolu, payload) ;
 10. gardes existantes intactes (P0.1, garde de chemin, profils, sandbox) ;
 11. E2E OPA/bwrap : NON ÉVALUÉ si les binaires sont absents, jamais PASS.

Usage : python3 PHASE3/test_mode_laboratoire.py   (exit non nul = échec)
"""

from __future__ import annotations

import dataclasses
import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

RACINE = pathlib.Path(__file__).resolve().parent
REPO = RACINE.parent

spec = importlib.util.spec_from_file_location("mode_laboratoire",
                                              str(RACINE / "mode_laboratoire.py"))
ML = importlib.util.module_from_spec(spec)
sys.modules["mode_laboratoire"] = ML
assert spec and spec.loader
spec.loader.exec_module(ML)

CHECKS: list[tuple[str, str, object]] = []
_section = ""


def section(titre: str) -> None:
    global _section
    _section = titre


def verifie(nom: str):
    def deco(fn):
        CHECKS.append((_section, nom, fn))
        return fn
    return deco


JETON_CLI = "cli-" + "A" * 40
JETON_FICHIER = "bloc-" + "B" * 40
OPERATEUR = "proprietaire-01"


def preparer_labo(tmp: pathlib.Path, symlink_interne: bool = False,
                  symlink_sortant: bool = False) -> tuple[pathlib.Path, pathlib.Path]:
    """Crée conf/ (opt-in 0600) et cible/ (fixture contrôlée `sain.py`)."""
    conf = tmp / "conf"
    conf.mkdir(parents=True, exist_ok=True)
    cible = tmp / "cible"
    cible.mkdir(parents=True, exist_ok=True)
    (cible / "sain.py").write_text("x = 1\n", encoding="utf-8")
    (cible / "notes.md").write_text("audit local\n", encoding="utf-8")
    bloc = conf / "optin-fichier"
    bloc.write_text("agnt-labo-optin-" + JETON_FICHIER, encoding="utf-8")
    bloc.chmod(0o600)
    for nom, cree in (("lien_interne", symlink_interne),
                      ("lien_sortant", symlink_sortant)):
        chemin = cible / nom
        if chemin.is_symlink() or chemin.exists():
            chemin.unlink()
        if cree:
            os.symlink(cible / "sain.py" if nom == "lien_interne"
                       else "/etc/hostname", chemin)
    return conf, cible


def contexte_avec(conf: pathlib.Path, cible: pathlib.Path,
                  **variations) -> ML.ContexteLabo:
    """Contexte complet accepté sur un labo déjà préparé."""
    base = dict(
        operateur=OPERATEUR,
        canal_activation="cli-local",
        profil="controlled_dev",
        jeton_cli=JETON_CLI,
        jeton_cli_attendu=JETON_CLI,
        optin_fichier=str(conf / "optin-fichier"),
        jeton_fichier_attendu=JETON_FICHIER,
        racine_conf=conf,
        cible_proposee=str(cible),
        racines_autorisees=(cible,),
        registre_cibles=(ML.CibleAutorisee(str(cible), True),),
        operateurs_autorises=(OPERATEUR,),
        capacites_demandees=("CODE_STATIC_ANALYSIS",),
        capacites_autorisees=("CODE_STATIC_ANALYSIS", "SECRET_DETECTION"),
        providers_demandes=("semgrep",),
        providers_autorises=("semgrep", "gitleaks"),
        policy_disponible=True,
        policy_allow=True,
        regles_presentes=True,
        empreintes_conformes=True,
        sandbox_conforme=True,
    )
    base.update(variations)
    return ML.ContexteLabo(**base)


def contexte_ok(tmp: pathlib.Path, **variations) -> ML.ContexteLabo:
    """Contexte complet accepté (toutes gardes vertes) + variations."""
    conf, cible = preparer_labo(tmp)
    return contexte_avec(conf, cible, **variations)


def attend_codes(v: ML.DecisionLabo, *codes: str) -> list[str]:
    manques = set(codes) - v.codes
    if manques:
        return [f"codes manquants {sorted(manques)} ; obtenu {sorted(v.codes)}"]
    return []


# ══════════════════════════════════════════════════════════════════════════
# 1. Baseline — désactivé par défaut
# ══════════════════════════════════════════════════════════════════════════
section("baseline")


@verifie("desactive-par-defaut")
def _():
    assert ML.DESACTIVE_PAR_DEFAUT is True
    return []


@verifie("zero-opt-in-refuse-et-comportement-baseline")
def _():
    v = ML.analyser(ML.ContexteLabo())
    assert not v.ok and not v.actif
    assert "optin-absent" in v.codes
    # baseline : aucune capacité ne devient disponible, rien n'est activé.
    assert v.chemin_cible_resolu == ""
    return attend_codes(v, "optin-absent")


@verifie("le-mode-nintroduit-aucun-etat-global-actif")
def _():
    # Un simple import ne change rien : pas de variable de mode, pas de fichier.
    assert not hasattr(ML, "MODE_ACTIF")
    return []


# ══════════════════════════════════════════════════════════════════════════
# 2. Double opt-in
# ══════════════════════════════════════════════════════════════════════════
section("opt-in")


@verifie("double-opt-in-local-et-cible-fixture-controlee-acceptes")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td)))
    assert v.ok and v.actif, v
    assert not v.raisons
    assert v.chemin_cible_resolu
    return []


@verifie("un-seul-opt-in-cli-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td), optin_fichier=None))
    assert not v.ok and not v.actif
    return attend_codes(v, "optin-incomplet")


@verifie("un-seul-opt-in-fichier-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td), jeton_cli=None))
    assert not v.ok
    return attend_codes(v, "optin-incomplet")


@verifie("jeton-cli-invalide-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                     jeton_cli="cli-" + "Z" * 40))
    assert not v.ok
    return attend_codes(v, "optin-invalide")


@verifie("jeton-cli-sans-config-locale-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td), jeton_cli_attendu=""))
    assert not v.ok
    return attend_codes(v, "optin-cli-sans-config")


@verifie("bloc-de-possession-invalide-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                     jeton_fichier_attendu="bloc-" + "Z" * 40))
    assert not v.ok
    return attend_codes(v, "optin-fichier-invalide")


@verifie("bloc-permissif-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        ctx = contexte_ok(pathlib.Path(td))
        bloc = pathlib.Path(ctx.optin_fichier)
        bloc.chmod(0o644)
        v = ML.analyser(ctx)
    assert not v.ok
    return attend_codes(v, "optin-fichier-permissif")


@verifie("bloc-symlink-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        ctx = contexte_ok(pathlib.Path(td))
        cible_reelle = pathlib.Path(ctx.optin_fichier)
        os.unlink(cible_reelle)
        os.symlink(ctx.racine_conf / "autre", cible_reelle)
        (ctx.racine_conf / "autre").write_text(
            "agnt-labo-optin-" + JETON_FICHIER, encoding="utf-8")
        v = ML.analyser(ctx)
    assert not v.ok
    return attend_codes(v, "optin-fichier-symlink")


@verifie("bloc-hors-racine-conf-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        hors = pathlib.Path(td) / "hors"
        hors.mkdir()
        (hors / "bloc").write_text("agnt-labo-optin-" + JETON_FICHIER,
                                   encoding="utf-8")
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                    optin_fichier=str(hors / "bloc")))
    assert not v.ok
    return attend_codes(v, "optin-fichier-non-local")


@verifie("bloc-dans-la-cible-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        ctx = contexte_ok(pathlib.Path(td))
        # Un fichier d'opt-in posé dans la cible ne doit JAMAIS activer.
        cible_bloc = ctx.racines_autorisees[0] / "optin"
        cible_bloc.write_text("agnt-labo-optin-" + JETON_FICHIER,
                              encoding="utf-8")
        v = ML.analyser(dataclasses.replace(ctx, optin_fichier=str(cible_bloc)))
    assert not v.ok
    return attend_codes(v, "optin-fichier-dans-cible")


@verifie("bloc-contenu-arbitraire-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        ctx = contexte_ok(pathlib.Path(td))
        pathlib.Path(ctx.optin_fichier).write_text("nimporte quoi",
                                                   encoding="utf-8")
        v = ML.analyser(ctx)
    assert not v.ok
    return attend_codes(v, "optin-fichier-invalide")


@verifie("bloc-non-absolu-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                     optin_fichier="conf/optin-fichier"))
    assert not v.ok
    return attend_codes(v, "optin-fichier-non-absolu")


# ══════════════════════════════════════════════════════════════════════════
# 3. Canaux interdits
# ══════════════════════════════════════════════════════════════════════════
section("canaux")


@verifie("canaux-non-locaux-tous-refuses")
def _():
    canaux = ["http-corps", "http-en-tete", "llm", "ui", "cible", "fixture",
              "journal", "artefact", "mcp", "provider", "inconnu"]
    echecs = []
    with tempfile.TemporaryDirectory() as td:
        ctx = contexte_ok(pathlib.Path(td))
        for canal in canaux:
            v = ML.analyser(dataclasses.replace(ctx, canal_activation=canal))
            if "canal-interdit" not in v.codes:
                echecs.append(f"{canal}: {sorted(v.codes)}")
    assert not echecs, "; ".join(echecs)
    return []


@verifie("le-module-ne-lit-jamais-la-cible-pour-activer")
def _():
    # Une cible remplie de jetons/optins ne modifie pas la décision : le module
    # ne lit que le chemin d'opt-in fourni par le canal local.
    with tempfile.TemporaryDirectory() as td:
        conf, cible = preparer_labo(pathlib.Path(td))
        for nom in ("optin", "bloc", "jeton.txt", "fixture.json"):
            (cible / nom).write_text("agnt-labo-optin-" + "C" * 40,
                                     encoding="utf-8")
        v = ML.analyser(contexte_ok(pathlib.Path(td), optin_fichier=None))
    assert not v.ok
    return attend_codes(v, "optin-incomplet")


# ══════════════════════════════════════════════════════════════════════════
# 4. Cible locale
# ══════════════════════════════════════════════════════════════════════════
section("cible")


@verifie("url-et-hotes-distants-refuses")
def _():
    cibles = ["https://exemple.com/repo", "ssh://serveur/tmp/a",
              "//hote/partage", "git@hote:repo", "hote:2222/srv",
              "file:///etc/passwd"]
    echecs = []
    with tempfile.TemporaryDirectory() as td:
        ctx = contexte_ok(pathlib.Path(td))
        for cible in cibles:
            v = ML.analyser(dataclasses.replace(ctx, cible_proposee=cible))
            if "cible-non-locale" not in v.codes:
                echecs.append(f"{cible!r}: {sorted(v.codes)}")
    assert not echecs, "; ".join(echecs)
    return []


@verifie("traversal-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                     cible_proposee=str(
                                         pathlib.Path(td) / ".." / "x")))
    assert not v.ok
    return attend_codes(v, "cible-traversal")


@verifie("chemin-absolu-hors-racine-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                     cible_proposee="/etc/passwd"))
    assert not v.ok
    return attend_codes(v, "cible-hors-racine")


@verifie("chemin-accueil-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                     cible_proposee="~/mon-labo"))
    assert not v.ok
    return attend_codes(v, "cible-hors-racine")


@verifie("symlink-sortant-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        conf, cible = preparer_labo(pathlib.Path(td), symlink_sortant=True)
        v = ML.analyser(contexte_avec(conf, cible))
    assert not v.ok
    return attend_codes(v, "cible-symlink-sortant")


@verifie("symlink-interne-accepte")
def _():
    with tempfile.TemporaryDirectory() as td:
        conf, cible = preparer_labo(pathlib.Path(td), symlink_interne=True)
        v = ML.analyser(contexte_avec(conf, cible))
    assert v.ok, v
    return []


@verifie("cible-absente-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        ctx = contexte_ok(pathlib.Path(td))
        manquante = ctx.racines_autorisees[0] / "absente"
        v = ML.analyser(dataclasses.replace(ctx, cible_proposee=str(manquante)))
    assert not v.ok
    return attend_codes(v, "cible-absente")


@verifie("cible-hors-registre-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        ctx = contexte_ok(pathlib.Path(td))
        v = ML.analyser(dataclasses.replace(ctx, registre_cibles=()))
    assert not v.ok
    return attend_codes(v, "cible-non-autorisee")


@verifie("cible_autorisee-is-not-True-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        ctx = contexte_ok(pathlib.Path(td))
        cible = ctx.racines_autorisees[0]
        v = ML.analyser(dataclasses.replace(
            ctx, registre_cibles=(ML.CibleAutorisee(str(cible), False),)))
    assert not v.ok
    return attend_codes(v, "cible-non-autorisee")


@verifie("operateur-hors-liste-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                    operateur="inconnu-99"))
    assert not v.ok
    return attend_codes(v, "operateur-inconnu")


@verifie("sans-operateur-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td), operateur=""))
    assert not v.ok
    return attend_codes(v, "operateur-inconnu")


@verifie("cible-non-absolue-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                     cible_proposee="cible/sain.py"))
    assert not v.ok
    return attend_codes(v, "cible-non-absolue")


# ══════════════════════════════════════════════════════════════════════════
# 5. Profil
# ══════════════════════════════════════════════════════════════════════════
section("profil")


@verifie("profils-public-production-incertains-refuses")
def _():
    profils = ["public", "production", "limites_a_prouver", "inconnu",
               "durci", "utilisateur"]
    echecs = []
    with tempfile.TemporaryDirectory() as td:
        ctx = contexte_ok(pathlib.Path(td))
        for nom in profils:
            v = ML.analyser(dataclasses.replace(ctx, profil=nom))
            if "profil-interdit" not in v.codes or v.ok:
                echecs.append(f"{nom}: {sorted(v.codes)}")
    assert not echecs, "; ".join(echecs)
    return []


# ══════════════════════════════════════════════════════════════════════════
# 6. Egress et capacités
# ══════════════════════════════════════════════════════════════════════════
section("egress-capacites")


@verifie("egress-ouvert-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                    egress_ouverture_demandee=("mcp",)))
    assert not v.ok
    return attend_codes(v, "egress-non-ferme")


@verifie("egress-global-implicite-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                    egress_global_implicite=True))
    assert not v.ok
    return attend_codes(v, "egress-global-interdit")


@verifie("capacite-hors-registre-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(
            pathlib.Path(td),
            capacites_demandees=("CODE_STATIC_ANALYSIS", "RESEAU_GLOBAL")))
    assert not v.ok
    return attend_codes(v, "capacite-non-autorisee")


@verifie("provider-hors-registre-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                    providers_demandes=("metasploit",)))
    assert not v.ok
    return attend_codes(v, "provider-non-autorise")


@verifie("commande-ou-argument-libre-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                    commandes_liberes=("nc -e /bin/sh",)))
    assert not v.ok
    return attend_codes(v, "commande-libre-interdite")


@verifie("liste-capacites-vide-refusee")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                    capacites_autorisees=()))
    assert not v.ok
    return attend_codes(v, "capacites-aucune")


@verifie("capacites-du-registre-agnt-acceptees")
def _():
    # Les IDs réels de capabilities.yaml (source de vérité AGNT) : la capacité
    # demandée existe dans le registre → acceptée.
    source = (RACINE / "slice" / "capabilities.yaml").read_text(
        encoding="utf-8")
    ids_cap = re.findall(r"^  - id: ([A-Z0-9_]+)$", source, re.M)
    ids_prov = re.findall(r"^      - id: ([a-z0-9_]+)$", source, re.M)
    assert "CODE_STATIC_ANALYSIS" in ids_cap
    assert "gitleaks" in ids_prov
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(
            pathlib.Path(td),
            capacites_demandees=("CODE_STATIC_ANALYSIS",),
            capacites_autorisees=tuple(ids_cap),
            providers_demandes=("gitleaks",),
            providers_autorises=tuple(ids_prov)))
    assert v.ok, v
    return []


# ══════════════════════════════════════════════════════════════════════════
# 7. Gardes existantes
# ══════════════════════════════════════════════════════════════════════════
section("gardes-existantes")


@verifie("policy-indisponible-refusee")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                    policy_disponible=False))
    assert not v.ok
    return attend_codes(v, "policy-indisponible")


@verifie("policy-refusee")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td), policy_allow=False))
    assert not v.ok
    return attend_codes(v, "policy-refusee")


@verifie("regles-absentes-refusees")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td), regles_presentes=False))
    assert not v.ok
    return attend_codes(v, "regles-absentes")


@verifie("empreintes-divergentes-refusees")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td),
                                     empreintes_conformes=False))
    assert not v.ok
    return attend_codes(v, "integrite-divergente")


@verifie("sandbox-non-conforme-refuse")
def _():
    with tempfile.TemporaryDirectory() as td:
        v = ML.analyser(contexte_ok(pathlib.Path(td), sandbox_conforme=False))
    assert not v.ok
    return attend_codes(v, "sandbox-non-conforme")


# ══════════════════════════════════════════════════════════════════════════
# 8. Conservation — rien n'est muté
# ══════════════════════════════════════════════════════════════════════════
section("conservation")


@verifie("contexte-immuable")
def _():
    ctx = ML.ContexteLabo(operateur="o")
    try:
        ctx.operateur = "autre"
        return ["ContexteLabo n'est pas immuable"]
    except dataclasses.FrozenInstanceError:
        return []


@verifie("registre-cible_autorisee-et-liste-operateur-conserves")
def _():
    with tempfile.TemporaryDirectory() as td:
        ctx = contexte_ok(pathlib.Path(td))
        registre_avant = tuple(ctx.registre_cibles)
        operateurs_avant = tuple(ctx.operateurs_autorises)
        v = ML.analyser(ctx)
    assert v.ok
    assert ctx.registre_cibles == registre_avant
    assert ctx.operateurs_autorises == operateurs_avant
    assert ctx.registre_cibles[0].autorisee is True
    assert ctx.registre_cibles[0].chemin == registre_avant[0].chemin
    return []


@verifie("attributs-p0-1-conserves-dans-la-chaine-existante")
def _():
    # P0.1 : `cible_autorisee` défaut False dans `analyser.lancer`, l'état se
    # relit depuis l'appelant (aucun canal d'activation dans le pipeline).
    src = (RACINE / "analyser.py").read_text(encoding="utf-8")
    assert "cible_autorisee: bool = False" in src
    assert "cible_autorisee" in src
    return []


# ══════════════════════════════════════════════════════════════════════════
# 9. Audit redacted
# ══════════════════════════════════════════════════════════════════════════
section("audit")


@verifie("audit-utilile-sans-secret-argv-chemin-payload")
def _():
    with tempfile.TemporaryDirectory() as td:
        ctx = contexte_ok(pathlib.Path(td))
        v = ML.analyser(ctx)
        texte = str(v) + "\n" + ML.synthese_audit(v)
    assert v.ok
    for interdit in (JETON_CLI, JETON_FICHIER, "agnt-labo-optin-",
                     OPERATEUR, "conf/", "cible/", str(ctx.racine_conf),
                     "sain.py", "payload"):
        assert interdit not in texte, f"fuite dans l'audit : {interdit}"
    assert len(v.audit) == 1
    entree = v.audit[0]
    assert entree["decision"] == "autorise"
    assert entree["reseau"] == "ferme"
    assert len(entree["operateur_empreinte"]) == 16
    assert len(entree["cible_empreinte"]) == 16
    return []


@verifie("refus-sans-fuite-de-chemin")
def _():
    # Le message de refus de la garde de chemin ne doit pas contenir le chemin.
    with tempfile.TemporaryDirectory() as td:
        ctx = contexte_ok(pathlib.Path(td), cible_proposee="/etc/passwd")
        v = ML.analyser(ctx)
        texte = str(v)
    assert not v.ok
    assert "/etc/passwd" not in texte
    assert "cible-hors-racine" in v.codes
    return []


# ══════════════════════════════════════════════════════════════════════════
# 10. Gardes existantes intactes (non-régression structurelle)
# ══════════════════════════════════════════════════════════════════════════
section("gardes-intactes")


@verifie("garde-de-chemin-existante-disponible")
def _():
    assert hasattr(ML._garde, "verifier_cible")
    assert hasattr(ML._garde, "CheminInterdit")
    return []


@verifie("profil-actif-reste-controlled_dev")
def _():
    spec = importlib.util.spec_from_file_location(
        "profils", str(RACINE / "slice" / "profils.py"))
    p = importlib.util.module_from_spec(spec)
    sys.modules["profils"] = p
    assert spec and spec.loader
    spec.loader.exec_module(p)
    assert p.actif().nom == "controlled_dev"
    try:
        p.obtenir("limites_a_prouver")
        return ["le profil limites_a_prouver ne doit pas être utilisable"]
    except PermissionError:
        return []


@verifie("sandbox-empreintes-toujours-presentes")
def _():
    if str(RACINE / "slice") not in sys.path:
        sys.path.insert(0, str(RACINE / "slice"))
    spec = importlib.util.spec_from_file_location(
        "sandbox", str(RACINE / "slice" / "sandbox.py"))
    s = importlib.util.module_from_spec(spec)
    sys.modules["sandbox"] = s
    assert spec and spec.loader
    spec.loader.exec_module(s)
    assert hasattr(s, "empreintes_conformes")
    assert hasattr(s, "Sandbox")
    return []


@verifie("aucun-fichier-de-garde-modifie")
def _():
    p = subprocess.run(
        ["git", "-C", str(REPO), "status", "--porcelain",
         "--", "PHASE3/slice", "PHASE3/analyser.py", "PHASE3/interface",
         "PHASE3/policy", "PHASE3/regles"],
        capture_output=True, text=True)
    if p.returncode != 0:
        return ["git indisponible"]
    modifs = [l for l in p.stdout.splitlines() if l]
    if modifs:
        return [f"fichiers de garde modifiés : {modifs}"]
    return []


# ══════════════════════════════════════════════════════════════════════════
# 11. E2E — OPA / bwrap : NON ÉVALUÉ si binaires absents, jamais PASS
# ══════════════════════════════════════════════════════════════════════════
section("e2e-environnement")

E2E_NON_EVALUE: list[str] = []


@verifie("e2e-policy-sandbox-conditionnel")
def _():
    opa = shutil.which("opa")
    bwrap = shutil.which("bwrap")
    if not opa or not bwrap:
        E2E_NON_EVALUE.append(
            f"opa={'absent' if not opa else 'présent'} · "
            f"bwrap={'absent' if not bwrap else 'présent'}")
        return []
    # Preuve E2E réelle : la porte bloquante existante (couche exécution +
    # sandbox) doit rester verte avec les binaires présents.
    p = subprocess.run([sys.executable, str(RACINE / "test_securite.py")],
                       capture_output=True, text=True, timeout=300)
    if p.returncode != 0:
        return [f"test_securite.py: code {p.returncode}"]
    return []


def main() -> int:
    print("MODE LABORATOIRE PROPRIÉTAIRE — PHASE3/mode_laboratoire.py")
    total, echecs = 0, []
    courant = ""
    for sec, nom, fn in CHECKS:
        if sec != courant:
            courant = sec
            print(f"\n[{courant}]")
        total += 1
        try:
            resultat = fn()
            if resultat:
                echecs.append((sec, nom, "; ".join(resultat)))
                print(f"  ÉCHEC  {nom} — {'; '.join(resultat)}")
            else:
                print(f"  OK     {nom}")
        except AssertionError as e:
            echecs.append((sec, nom, str(e)))
            print(f"  ÉCHEC  {nom} — {e}")
        except Exception as e:
            echecs.append((sec, nom, f"exception {e!r}"))
            print(f"  ÉCHEC  {nom} — exception {e!r}")
    ok = total - len(echecs)
    print(f"\n{ok}/{total} vérifications · {len(echecs)} échec(s)")
    if E2E_NON_EVALUE:
        for motif in sorted(set(E2E_NON_EVALUE)):
            print(f"  NON ÉVALUÉ · preuve E2E OPA/bwrap : {motif} — "
                  f"aucun PASS ne sera affirmé à la place")
    if echecs:
        print("Résumé des échecs :")
        for sec, nom, msg in echecs:
            print(f"  [{sec}] {nom} — {msg}")
    return 1 if echecs else 0


if __name__ == "__main__":
    sys.exit(main())
