#!/usr/bin/env python3
"""
Batterie « couverture Go du mapping » — ce que le mapping peut, et ne peut pas, prouver.

Occurrence de départ (mesurée, pas supposée) :

    mapping_regles_genere.yaml  regles_par_fichier = {python.yaml, security-audit.yaml,
                                                       javascript.yaml}
    bootstrap.sh                épingle QUATRE jeux : python, security-audit,
                                                       javascript, GOLANG
    manifeste_dependances.yaml  déclare les quatre, golang.yaml compris (sha256 7c08b953…)

Donc `golang.yaml` a été ajouté au bootstrap le 2026-08-29 (chantier largeur-Go), le
générateur parcourt `*.yaml` AU HASARD DU CACHE, et le mapping versionné ne dit nulle
part qu'un jeu épinglé lui a manqué. Une couverture perdue silencieusement ressemble
à s'y méprendre à une couverture inexistante — ou pire, à un choix délibéré.

Ce que cette batterie exige, dans cet ordre :

  A. le générateur connaît la LISTE D'AUTORITÉ (le manifeste), pas seulement ce qui
     traîne dans le cache : un jeu épinglé manquant est une ERREUR, pas un trou de plus ;
  B. le mapping compte les règles LUES et les règles MAPPÉES par jeu : « 0 mappées »
     doit être visible, sinon « j'ai régénéré » veut dire « j'ai augmenté un compteur » ;
  C. un paquet Go s'écrit en CHEMIN DE MODULE. `gin` ne rencontre jamais
     `github.com/gin-gonic/gin`, la clé que l'outil de dépendances déclare : accepter la
     forme courte produirait un mapping vivant dans le YAML et mort dans le clusterer.
     Le refus se fait à la production du mapping, pas au moment du lien ;
  D. aucune corrélation inventée : sur les captures RÉELLES de `testrepo_go`, les deux
     findings semgrep portent `technology: [go]` — un langage, pas une dépendance. Le
     mapping doit donc rester muet (`paquet: null`, `methode: inconnu`) et le clusterer
     ne doit produire AUCUN cluster inter-outils sur ce dépôt. C'est le cas négatif, et
     c'est lui qui décide si C vaut la peine d'être codé plus loin.

Usage : python3 PHASE3/test_mapping_go.py        (aucun outil requis, hors ligne)
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import extraire_mapping as EM  # noqa: E402
import findings as F           # noqa: E402

CAS = []
ECHECS = []
NON_EVALUES = []
CONSTATS = []


def cas(nom: str, cond: bool, detail: str = ""):
    CAS.append((nom, cond, detail))
    if not cond:
        ECHECS.append(nom)


def cas_non_evalue(nom: str, motif: str):
    NON_EVALUES.append((nom, motif))


def constat(nom: str, texte: str):
    """Un fait mesuré, ni succès ni échec — affiché pour ne pas être oublié."""
    CONSTATS.append((nom, texte))


# ------------------------------------------------------------------ fabrication de jeu de règles
REGLE_PY = {"rules": [{"id": "python.lang.security.audit.x.evil",
                       "metadata": {"technology": ["python", "flask"]}}]}
REGLE_GO_LANG = {"rules": [{"id": "go.lang.security.audit.crypto.use-of-md5",
                            "metadata": {"technology": ["go"]}}]}
REGLE_GO_COURTE = {"rules": [{"id": "go.github.gin.g15.bind",
                             "metadata": {"technology": ["go", "gin"]}}]}
REGLE_GO_MODULE = {"rules": [{"id": "go.github.gin.g15.xss",
                             "metadata": {"technology": ["go", "github.com/gin-gonic/gin"]}}]}


def ecrire(dossier: Path, nom: str, doc: dict) -> Path:
    import yaml
    p = dossier / nom
    p.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return p


def lancer_generateur(regles: Path, sortie: Path, *args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(RACINE / "extraire_mapping.py"),
         "--regles", str(regles), "--sortie", str(sortie), *args],
        capture_output=True, text=True, timeout=120)


def main() -> int:
    # ================================================ A. liste d'autorité = manifeste épinglé
    # Le générateur ne doit pas découvrir la couverture en globant un cache : la liste
    # des jeux de règles attendus est ÉPINGLÉE dans le manifeste (sha256 par fichier).
    declarees = EM.regles_declarees()
    cas("A1. la liste des jeux de règles vient du manifeste épinglé, pas d'un glob",
        len(declarees) >= 4 and "golang.yaml" in declarees, f"{declarees}")
    # Une entrée MAPPABLE (valeur non nulle) que IGNORES annule est une couverture perdue
    # sans bruit : la règle est lue, sa technologie reconnue, et le lien disparaît dans un
    # `continue` — c'est ainsi que « react » a vécu. Une entrée à valeur None est au
    # contraire un doublon assumé (« c'est un langage, pas un paquet », dit deux fois) :
    # même critère que le garde-fou du générateur, pour ne pas avoir deux définitions.
    cas("A2. aucune entrée mappable de la table n'est contredite par IGNORES",
        EM.valider_tables(EM.TECHNO_VERS_PAQUET, EM.IGNORES) == [],
        f"entrées mortes : {EM.valider_tables(EM.TECHNO_VERS_PAQUET, EM.IGNORES)}")
    cas("A3. le générateur refuse d'écrire si ses propres tables sont incohérentes",
        EM.valider_tables({"react": "react"}, {"react"}) != [], "aucune anomalie signalée")

    # Constat mesuré sur le fichier VERSIONNÉ, ni succès ni échec : ce fichier est une
    # donnée générée, il ne s'édite pas à la main, et le régénérer exige le cache de
    # règles (injoignable ici). Il gardera son ancien format jusqu'à la prochaine
    # génération sur la machine source — c'est exactement ce que B/A1 rendent visible.
    import yaml
    mapping = yaml.safe_load((RACINE / "slice" / "mapping_regles_genere.yaml")
                             .read_text(encoding="utf-8"))
    pf_versionne = mapping.get("regles_par_fichier") or {}
    format_ = type(next(iter(pf_versionne.values()))).__name__ if pf_versionne else "vide"
    comptabilite = [k for k in ("regles_declarees", "regles_absentes", "refusees") if k in mapping]
    constat("état du mapping versionné sur ce dépôt",
            "clés=" + str(sorted(pf_versionne)) + " · format par fichier=" + format_
            + " · champs de comptabilité présents=" + str(comptabilite)
            + " → ce fichier est GÉNÉRÉ : il prendra le nouveau format à la prochaine "
              "génération sur la machine source (section G). Il ne s'édite pas à la main.")

    # ============================== B. lues vs mappées : « 0 mappées » doit être lisible
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        reg = t / "rules"
        reg.mkdir()
        ecrire(reg, "python.yaml", REGLE_PY)
        ecrire(reg, "golang.yaml", REGLE_GO_LANG)      # langage seul : rien à mapper
        out = t / "mapping.yaml"
        r = lancer_generateur(reg, out, "--partiel")
        doc = yaml.safe_load(out.read_text(encoding="utf-8")) if out.exists() else {}
        pf = doc.get("regles_par_fichier") or {}
        py, go = pf.get("python.yaml") or {}, pf.get("golang.yaml") or {}
        cas("B1. par jeu : règles LUES et règles MAPPÉES sont distinctes",
            py.get("lues") == 1 and py.get("mappees") == 1
            and go.get("lues") == 1 and go.get("mappees") == 0,
            f"python={py} go={go}")
        cas("B2. un jeu lu à 0 mapping reste écrit (visible), pas effacé",
            "golang.yaml" in pf, f"{list(pf)}")
        cas("B3. les jeux épinglés absents du cache sont listés, avec le rappel du bootstrap",
            doc.get("regles_absentes") == ["javascript.yaml", "security-audit.yaml"],
            f"{doc.get('regles_absentes')}")
        cas("B4. en mode strict (défaut), un jeu épinglé manquant fait ÉCHOUER la génération",
            lancer_generateur(reg, t / "strict.yaml").returncode != 0,
            "le générateur a accepté un cache incomplet en silence")

        # ============================================ C. le chemin de module, pas le nom court
        cas("C1. « gin » (forme courte) n'est PAS un paquet Go recevable",
            not EM.paquet_go_valide("gin"), "serait mort face à github.com/gin-gonic/gin")
        cas("C2. « github.com/gin-gonic/gin » l'est",
            EM.paquet_go_valide("github.com/gin-gonic/gin"))
        cas("C3. « golang.org/x/text » l'est (la forme que trivy déclare sur go.mod)",
            EM.paquet_go_valide("golang.org/x/text"))

        reg2 = t / "rules2"
        reg2.mkdir()
        ecrire(reg2, "golang.yaml", REGLE_GO_COURTE)
        out2 = t / "m2.yaml"
        r2 = lancer_generateur(reg2, out2, "--partiel")
        doc2 = yaml.safe_load(out2.read_text(encoding="utf-8")) if out2.exists() else {}
        cas("C4. une règle Go à forme courte est REFUSÉE et tracée comme refusée",
            not (doc2.get("regles") or {}).get("go.github.gin.g15.bind")
            and bool((doc2.get("refusees") or [])),
            f"refusees={doc2.get('refusees')} · regles={list((doc2.get('regles') or {}))}")

        reg3 = t / "rules3"
        reg3.mkdir()
        ecrire(reg3, "golang.yaml", REGLE_GO_MODULE)
        out3 = t / "m3.yaml"
        lancer_generateur(reg3, out3, "--partiel")
        doc3 = yaml.safe_load(out3.read_text(encoding="utf-8")) if out3.exists() else {}
        e3 = (doc3.get("regles") or {}).get("go.github.gin.g15.xss") or {}
        cas("C5. une règle Go en chemin de module EST acceptée (le mapping reste possible)",
            e3.get("paquet") == "github.com/gin-gonic/gin", f"{e3}")

        # ============================ D. le lien, jugé sur les données — pas sur les stats
        import clusterer as CL
        from registre import Registry
        regt = Registry()

        cap = RACINE / "testrepo_go" / "artefacts_captures"
        if all((cap / n).is_file() for n in ("semgrep_go.json", "trivy.json")) \
                and (cap / "semgrep_go.json").stat().st_size > 0:
            sg = json.loads((cap / "semgrep_go.json").read_text(encoding="utf-8"))
            tv = json.loads((cap / "trivy.json").read_text(encoding="utf-8"))
            fs = (F.normaliser("semgrep", sg, racines=())
                  + F.normaliser("trivy", tv, racines=()))
            paquets_sg = {f.location.get("package") for f in fs if f.source["tool"] == "semgrep"}
            cas("D1. sur les captures réelles : aucune règle semgrep Go ne nomme de dépendance",
                paquets_sg == {None}, f"paquets={paquets_sg}")
            inter = CL.regrouper(fs)["clusters_inter_outils"]
            cas("D2. donc AUCUN cluster inter-outils inventé sur testrepo_go",
                not inter, f"{[c['cle'] for c in inter]}")
            constats_vus = [(f.source["tool"], f.location.get("package"),
                             f.source.get("package_mapping", {}).get("method")) for f in fs[:2]]
            constat("D3. ce que les données disent",
                    f"{len(fs)} findings réels · semgrep→{constats_vus}")
        else:
            cas_non_evalue("D1/D2. captures réelles testrepo_go", f"absentes : {cap}")

        # ---- E. ce que C devrait produire pour être autre chose qu'un compteur de plus.
        # Cas construit de toutes pièces : la SEULE configuration où un mapping Go sert —
        # une règle semgrep qui nomme le module, et un outil de dépendances qui le déclare.
        doc_tv = {"Results": [{"Target": "go.mod", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-TEST", "PkgName": "github.com/gin-gonic/gin",
             "InstalledVersion": "v1.7.0", "Severity": "HIGH", "Title": "t"}]}]}
        with tempfile.TemporaryDirectory() as td2:
            t2 = Path(td2)
            r4 = t2 / "rules"
            r4.mkdir()
            ecrire(r4, "golang.yaml", REGLE_GO_MODULE)
            m4 = t2 / "mapping.yaml"
            lancer_generateur(r4, m4, "--partiel")
            # On injecte le mapping produit dans le cache de lookup DÉJÀ présent dans
            # findings (F._MAPPING_GENERE) : c'est exactement ce que _paquet_concerne
            # consomme — aucun trou ajouté au code de production, clusterer intact.
            avant = F._MAPPING_GENERE
            F._MAPPING_GENERE = (yaml.safe_load(m4.read_text(encoding="utf-8")) or {}).get("regles")
            try:
                fs2 = (F.normaliser("semgrep", {
                    "results": [{"check_id": "go.github.gin.g15.xss", "path": "main.go",
                                 "start": {"line": 12}, "extra": {"severity": "ERROR",
                                                                 "message": "xss", "lines": ""}}]},
                    racines=())
                    + F.normaliser("trivy", doc_tv, racines=()))
                paquets = sorted({f.location.get("package") for f in fs2 if f.location.get("package")})
                inter2 = CL.regrouper(fs2)["clusters_inter_outils"]
                cas("E1. avec un mapping Go en chemin de module : les deux outils parlent du MÊME paquet",
                    paquets == ["github.com/gin-gonic/gin"], f"{paquets}")
                cas("E2. → cluster inter-outils justifié (same_dependency_usage), pas un rapprochement manuel",
                    len(inter2) == 1 and "same_dependency_usage" in inter2[0]["reason"]
                    and "cross_tool" in inter2[0]["reason"],
                    f"{[c['reason'] for c in inter2]}")
            finally:
                F._MAPPING_GENERE = avant

            # ---- F. négatif strict : module présent chez l'outil de dépendances, AUCUNE
            # règle semgrep ne le nomme → rien ne doit être corrélé « quand même ».
            fs3 = (F.normaliser("semgrep", {
                "results": [{"check_id": "go.lang.security.audit.crypto.use-of-md5",
                             "path": "main.go", "start": {"line": 12},
                             "extra": {"severity": "WARNING", "message": "md5", "lines": ""}}]},
                racines=())
                + F.normaliser("trivy", doc_tv, racines=()))
            inter3 = CL.regrouper(fs3)["clusters_inter_outils"]
            cas("F. paquet Go vulnérable sans règle le nommant → aucun cluster (prudence > lien)",
                not inter3 and all(f.location.get("package") != "gin" for f in fs3),
                f"{[c['cle'] for c in inter3]}")

    # ---- G. l'état réel du cache de règles sur CETTE machine (jugera le régénéré).
    cache = EM.REGLES
    if cache.is_dir() and any(cache.glob("golang.yaml")):
        cas("G. golang.yaml présent → la régénération peut être jugée ici",
            True, "présent")
    else:
        cas_non_evalue(
            "G. régénération du mapping avec golang.yaml (la mesure qui tranche C)",
            f"jeu de règles absent du cache ({cache / 'golang.yaml'}) — semgrep.dev "
            f"injoignable ici ; à lancer sur la machine source : python3 PHASE3/extraire_mapping.py")
        constat("commande qui décide de C",
                "python3 PHASE3/extraire_mapping.py  →  regarder « golang.yaml : N lues, M mappées ». "
                "M = 0 ⇒ aucune règle Go ne nomme de dépendance ⇒ la corrélation Go n'est pas "
                "codable maintenant (même verdict que le mapping npm, DOGFOODING_BILAN).")

    for nom, cond, detail in CAS:
        print(("OK   " if cond else "ECHEC") + f" {nom}"
              + (f"\n      → {detail}" if detail and not cond else ""))
    for nom, texte in CONSTATS:
        print(f"CONSTAT {nom} — {texte}")
    for nom, motif in NON_EVALUES:
        print(f"NON EVALUÉ {nom} — {motif}")
    print(f"\ntest_mapping_go : {len(CAS) - len(ECHECS)}/{len(CAS)} cas vérifiés"
          + (f" · {len(NON_EVALUES)} non évalués" if NON_EVALUES else ""))
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
