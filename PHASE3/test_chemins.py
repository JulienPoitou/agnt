#!/usr/bin/env python3
"""
Batterie « normalisation des chemins » — identité indépendante de la machine.

Décision 2026-08-28 (dogfooding, campagne 2). Défaut mesuré :
- 72 findings eslint portaient le chemin absolu du montage sandbox
  (/home/user/PHASE3/mt-scan/…) ; 7 clés de cluster l'embarquaient ;
- les fingerprints incluent le fichier : leur stabilité ne tient qu'à la
  constance du point de montage codé en dur — le jour où il devient dynamique
  (portabilité), toutes les identités changent d'un coup ;
- hors isolateur, la normalisation produit des chemins de la machine hôte.

Correctif : les chemins sont relativisés à la normalisation (avant calcul du
fingerprint), par rapport aux racines CONNUES (montage, cible). Clustering et
modèle de findings intacts — ils consomment des valeurs plus propres.

Aucun outil exécuté : artefacts capturés + documents synthétiques sur formes
réelles.

Usage: python3 PHASE3/test_chemins.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import findings as F  # noqa: E402
from registre import Registry  # noqa: E402
from sandbox import Sandbox  # noqa: E402

CAS = []
ECHECS = []


def cas(nom: str, cond: bool, detail: str = ""):
    CAS.append((nom, cond, detail))
    if not cond:
        ECHECS.append(nom)


def raw_semgrep_eslint() -> dict:
    logs = RACINE / "dogfooding" / "logs"
    m = re.search(r"artefacts : (\S+)", (logs / "eslint2.log").read_text())
    d = RACINE / m.group(1)
    src = d / "raw_semgrep.json"
    if not src.is_file():                      # conservation : brut ou redacted
        src = d / "raw_semgrep.redacted.json"
    return json.loads(src.read_text())


def doc_checkov(fichier: str) -> dict:
    return [{"check_type": "terraform",
             "results": {"failed_checks": [{
                 "check_id": "CKV_AWS_3", "check_name": "EBS encryption",
                 "file_path": fichier, "file_line_range": [17, 22],
                 "severity": None, "guideline": None}]}},
            ]


# TROIS ÉTATS, JAMAIS MÉLANGÉS (convention de test_correlation.py) : succès · échec ·
# non évalué quand la dépendance d'environnement manque (logs de dogfooding non
# versionnés). Un cas non évalué n'est JAMAIS compté comme un succès.
NON_EVALUES: list[tuple[str, str]] = []


def cas_non_evalue(nom: str, motif: str):
    NON_EVALUES.append((nom, motif))


def doc_semgrep(fichier: str, ligne: int, regle: str = "python.lang.x.y.rule-a") -> dict:
    return {"version": "1.175.0",
            "results": [{"check_id": regle, "path": fichier,
                         "start": {"line": ligne, "col": 1},
                         "extra": {"severity": "WARNING", "message": "m", "lines": "code"}}]}


def doc_gitleaks(fichier: str, ligne: int) -> list:
    return [{"RuleID": "generic-api-key", "Description": "d", "File": fichier,
             "StartLine": ligne, "Match": "x", "Secret": "s", "Entropy": 3.1,
             "Commit": "abc", "Author": "a"}]


def bloc_canonique():
    """Identité canonique de fichier — le correctif qui manquait à la décision de 2026-08-28.

    Ce qui était déjà fait (2026-08-28) : relativisation aux racines CONNUES avant
    fingerprint. Ce qui restait, mesuré le 2026-08-30 sur les artefacts capturés :

        « ./main.go »        inchangé  → ne marque pas « main.go »
        « foo/../bar.py »     inchangé  → ne marque pas « bar.py »
        « /PHASE3/testrepo_iac/k8s.yaml » → « PHASE3/testrepo_iac/k8s.yaml »
                                            (20 findings checkov de la fixture iac) alors
                                            que kics/trivy disent « k8s.yaml »
        « /.. »               → « .. »  : une remontée HORS cible fabriquée en chemin « valide »

    Invariant visé, et lui seul : `finding.file == finding2.file` doit dire « même
    fichier ». Le clusterer reste bête (`clusterer.py` n'est pas touché) — la
    normalisation vit au point où le finding devient canonique (`findings.py`).

    Deux garde-fous valent plus que le repli lui-même :
      · un chemin qui REMONTE hors de la cible n'est jamais aplati (`../x` ≠ `x`) ;
      · ce qui n'est pas un chemin (paquet, asset, dépôt) n'est jamais touché.
    """
    m_scan = Sandbox.M_SCAN
    cible_iac = "PHASE3/testrepo_iac"          # la cible nommée relativement au dépôt
    R = (m_scan, cible_iac)

    # ---------------------------------------------------------- 1. les formes annoncées
    pour_ = {
        f"{m_scan}/foo.py": "foo.py",
        "foo.py": "foo.py",
        f"{m_scan}/docs/foo.py": "docs/foo.py",
        "./foo.py": "foo.py",
        "foo/../bar.py": "bar.py",
        "foo\\bar.py": "foo/bar.py",
        "foo//bar/": "foo/bar",
        f"/{cible_iac}/k8s.yaml": "k8s.yaml",
    }
    for entree, attendu in pour_.items():
        obtenu = F.normalise_chemin(entree, R)
        cas(f"1. {entree!r} → {attendu!r}", obtenu == attendu, f"obtenu={obtenu!r}")

    # ------------------------------------------------------ 2. les refus explicites
    refuse_avant = F.normalise_chemin("../foo.py", R)
    cas("2a. « ../foo.py » n'est JAMAIS aplati en « foo.py »",
        refuse_avant == "../foo.py", f"obtenu={refuse_avant!r}")
    canon_foo = F.normalise_chemin("foo.py", R)
    cas("2b. et reste DISTINCT de « foo.py » (pas de faux same_file)",
        refuse_avant != canon_foo, f"{refuse_avant!r} vs {canon_foo!r}")
    cas("2c. « /.. » n'est pas rendu « .. » : une remontée hors cible reste ce qu'elle est",
        F.normalise_chemin("/..", R) == "/..", f"obtenu={F.normalise_chemin('/..', R)!r}")
    cas("2d. un absolu d'ailleurs ne collisionne jamais avec le nom court",
        F.normalise_chemin("/home/user/autre/foo.py", R) != "foo.py",
        F.normalise_chemin("/home/user/autre/foo.py", R))

    # ------------------------------------- 3. ce qui n'est pas un chemin ne doit pas l'être
    for non_chemin in ("flask", "golang.org/x/text", "pkg:npm/lodash",
                       "go.mod:golang.org/x/text", "repository", "asset:depot", ""):
        cas(f"3. non-chemin intact : {non_chemin!r}",
            F.normalise_chemin(non_chemin, R) == non_chemin,
            f"obtenu={F.normalise_chemin(non_chemin, R)!r}")

    # ----------------------------------------------- 4. idempotence (pas d'oscillation)
    for entree in list(pour_) + ["../foo.py", "/..", "a/./b/../c.py", "C:\\x\\y.py"]:
        une = F.normalise_chemin(entree, R)
        deux = F.normalise_chemin(une, R)
        cas(f"4. idempotent : {entree!r}", une == deux, f"{une!r} puis {deux!r}")

    # ------------------------ 5. l'hypothèse isolateur (cas 6 historique) reste vraie
    prov = Registry().provider("checkov")
    ck = F.normaliser("checkov", doc_checkov("/main.tf"), mani=prov.manifest, racines=(m_scan,))
    cas("5. checkov '/main.tf' → 'main.tf' (convention conservée)",
        ck and ck[0].location["file"] == "main.tf", ck[0].location["file"] if ck else "vide")

    # =========================================== INTER-OUTILS : l'identité devient cluster
    import clusterer as CL

    def inter(fs):
        out = CL.regrouper(fs)
        return out["clusters_inter_outils"] or [], out

    # 6a. même fichier, lignes proches, deux outils : c'est LE cas qui compte.
    fs = (F.normaliser("semgrep", doc_semgrep(f"{m_scan}/app.py", 42), racines=R)
          + F.normaliser("gitleaks", doc_gitleaks("./app.py", 45), racines=R))
    it, _ = inter(fs)
    raisons = it[0]["reason"] if it else []
    cas("6a. semgrep '<montage>/app.py:42' + gitleaks './app.py:45' → même cluster",
        len(it) == 1 and "same_file" in raisons and "ligne_proche" in raisons
        and "cross_tool" in raisons, f"{raisons}")

    # 6b. négatif : fichiers différents → aucun cluster same_file.
    fs = (F.normaliser("semgrep", doc_semgrep(f"{m_scan}/app.py", 42), racines=R)
          + F.normaliser("gitleaks", doc_gitleaks("autre.py", 43), racines=R))
    it, _ = inter(fs)
    cas("6b. app.py vs autre.py → PAS de cluster inter-outils", not it,
        f"{[c['cle'] for c in it]}")

    # 6c. négatif dur : la remontée hors cible ne crée pas de lien.
    fs = (F.normaliser("semgrep", doc_semgrep(f"{m_scan}/app.py", 42), racines=R)
          + F.normaliser("gitleaks", doc_gitleaks("../app.py", 43), racines=R))
    it, _ = inter(fs)
    cas("6c. '<montage>/app.py' vs '../app.py' → PAS de fusion (prudence > regroupement)",
        not any("same_file" in c["reason"] for c in it), f"{[c['reason'] for c in it]}")

    # 6d. trivy ne porte AUCUNE ligne (location.line = None, vérifié) : same_file oui,
    #     ligne_proche structurellement impossible. Le cas est là pour qu'on ne le
    #     présente jamais comme acquis : la forme « trivy app.py:42 ↔ semgrep app.py:45 »
    #     citée en revue n'existe pas dans nos données.
    doc_tv = {"Results": [{"Target": "app.py", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "flask", "InstalledVersion": "1",
         "Severity": "HIGH", "Title": "t"}]}]}
    fs = (F.normaliser("semgrep", doc_semgrep(f"{m_scan}/app.py", 42), racines=R)
          + F.normaliser("trivy", doc_tv, racines=R))
    it, _ = inter(fs)
    lignes = [f.location.get("line") for f in fs if f.source["tool"] == "trivy"]
    cas("6d. trivy + semgrep sur app.py → same_file, et JAMAIS ligne_proche (trivy n'a pas de ligne)",
        any("same_file" in c["reason"] for c in it)
        and not any("ligne_proche" in c["reason"] for c in it) and lignes == [None],
        f"{[c['reason'] for c in it]} lignes_trivy={lignes}")

    # 6e. L'OCCURRENCE mesurée : checkov dit « /PHASE3/testrepo_iac/k8s.yaml », les
    #     autres « k8s.yaml ». Avant ce correctif, les 20 findings checkov de la
    #     fixture iac ne pouvaient rencontrer personne.
    ck2 = F.normaliser("checkov", doc_checkov(f"/{cible_iac}/k8s.yaml"),
                        mani=prov.manifest, racines=R)
    sg2 = F.normaliser("semgrep", doc_semgrep("k8s.yaml", 8), racines=R)
    it, _ = inter(ck2 + sg2)
    cas("6e. checkov '/PHASE3/testrepo_iac/k8s.yaml' + semgrep 'k8s.yaml' → même cluster",
        len(ck2) == 1 and ck2[0].location["file"] == "k8s.yaml" and len(it) == 1
        and "same_file" in it[0]["reason"],
        f"fichier={ck2[0].location['file'] if ck2 else None} clusters={[c['reason'] for c in it]}")

    # ------------------------- 7. sur les artefacts RÉELS : aucune identité ne dérive
    # Les captures de testrepo_go contiennent déjà des chemins relatifs propres : le
    # correctif ne doit rien changer là où il n'y a rien à corriger (sinon : empreintes
    # de findings déplacées pour rien, et fausses ruptures de rejeu).
    cap = RACINE / "testrepo_go" / "artefacts_captures"
    if all((cap / n).is_file() for n in ("semgrep_go.json", "gitleaks.json", "trivy.json")):
        sg_r = json.loads((cap / "semgrep_go.json").read_text(encoding="utf-8"))
        gl_r = json.loads((cap / "gitleaks.json").read_text(encoding="utf-8"))
        tv_r = json.loads((cap / "trivy.json").read_text(encoding="utf-8"))
        avant = [f.identity["fingerprint"] for f in
                 F.normaliser("semgrep", sg_r, racines=())
                 + F.normaliser("gitleaks", gl_r, racines=())
                 + F.normaliser("trivy", tv_r, racines=())]
        apres = [f.identity["fingerprint"] for f in
                 F.normaliser("semgrep", sg_r, racines=R)
                 + F.normaliser("gitleaks", gl_r, racines=R)
                 + F.normaliser("trivy", tv_r, racines=R)]
        derive = [(a, b) for a, b in zip(avant, apres) if a != b]
        cas("7. artefacts réels testrepo_go : empreintes inchangées (aucune dérive d'identité)",
            len(avant) == len(apres) > 0 and not derive,
            f"{len(avant)} findings · {len(derive)} empreinte(s) dérivée(s)")
        noms = sorted({f.location["file"] for f in
                       F.normaliser("semgrep", sg_r, racines=R)
                       + F.normaliser("gitleaks", gl_r, racines=R)})
        cas("7b. et les clés de fichier restent « main.go » (ATTENDUS.yaml non ébranlé)",
            noms == ["main.go"], f"{noms}")
    else:
        cas_non_evalue("7. artefacts réels testrepo_go : empreintes inchangées",
                       f"captures absentes : {cap}")
        cas_non_evalue("7b. clés de fichier restées « main.go »", "idem")

    # ============ 8. ce que le correctif change, mesuré sur les captures RÉELLES iac
    # checkov_multiframework.json (38 findings) + kics.json (110) : deux outils, un
    # même dépôt. C'est l'occurrence qui a motivé le correctif, rejouée ici sans lancer
    # le moindre outil — les sorties sont celles des runs archivés.
    cap_iac = RACINE / "testrepo_iac" / "artefacts_captures"
    if all((cap_iac / n).is_file() for n in ("checkov_multiframework.json", "kics.json")):
        ck_m = Registry().provider("checkov").manifest
        ki_m = Registry().provider("kics").manifest
        fs = (F.normaliser("checkov", json.loads((cap_iac / "checkov_multiframework.json")
                                                 .read_text(encoding="utf-8")),
                           mani=ck_m, racines=R)
              + F.normaliser("kics", json.loads((cap_iac / "kics.json").read_text(encoding="utf-8")),
                             mani=ki_m, racines=R))
        out = CL.regrouper(fs)
        inter = out["clusters_inter_outils"]
        # 8a. pas de lien abusif : un cluster « same_file » ne doit mélanger qu'UN seul
        #     chemin. C'est la contrepartie obligatoire du relâchement de la clé.
        melanges = []
        par_id = {f.id: f for f in fs}
        for c in inter:
            if "same_file" not in c["reason"]:
                continue
            fichiers = {par_id[m].location["file"] for m in c["members"] if m in par_id}
            if len(fichiers) > 1:
                melanges.append((c["cle"], sorted(fichiers)))
        cas("8a. captures iac réelles (148 findings) : aucun cluster same_file ne mêle deux fichiers",
            not melanges and len(inter) > 0, f"{len(inter)} inter-outils · abus={melanges[:2]}")
        # 8b. le payoff : k8s.yaml, que checkov nommait « /PHASE3/testrepo_iac/… »,
        #     rencontre enfin les findings kics du même fichier.
        k8 = [c for c in inter if c["cle"].startswith("fichier:k8s.yaml")]
        outils_k8 = {par_id[m].source["tool"] for c in k8 for m in c["members"] if m in par_id}
        cas("8b. checkov + kics sur k8s.yaml → cluster inter-outils (impossible avant)",
            bool(k8) and outils_k8 == {"checkov", "kics"}, f"{outils_k8}")
        # 8c. l'A/B sans dupliquer l'ancien code : ce que rendait l'absence
        #     d'ancrage, et ce que rend l'orthographe du dépôt ajoutée.
        cas("8c. A/B mesuré : sans l'orthographe relative, le chemin reste décalé",
            F.normalise_chemin("/PHASE3/testrepo_iac/k8s.yaml", (m_scan,))
            == "PHASE3/testrepo_iac/k8s.yaml"
            and F.normalise_chemin("/PHASE3/testrepo_iac/k8s.yaml", R) == "k8s.yaml",
            F.normalise_chemin("/PHASE3/testrepo_iac/k8s.yaml", (m_scan,)))
    else:
        for nom in ("8a. captures iac réelles : aucun cluster same_file mêlant deux fichiers",
                    "8b. checkov + kics sur k8s.yaml → cluster inter-outils",
                    "8c. A/B mesuré sur le chemin checkov de la fixture iac"):
            cas_non_evalue(nom, f"captures absentes : {cap_iac}")


def main() -> int:
    m_scan = Sandbox.M_SCAN

    # 1. Artefact réel : les chemins absolus du montage deviennent relatifs
    logs = RACINE / "dogfooding" / "logs"
    if not (logs / "eslint2.log").is_file():
        # Les logs de dogfooding ne sont pas versionnés ('.gitignore') : sur un clone
        # vierge, ces deux cas ne sont PAS évaluables. Convention des trois états
        # (test_correlation.py) : non évalué ≠ succès ≠ échec — et surtout ≠ crash.
        cas_non_evalue("1. artefact eslint : plus aucun chemin absolu",
                       f"journal absent : {logs / 'eslint2.log'}")
        cas_non_evalue("1b. les chemins relatifs obtenus sont non vides", "idem")
        cas_non_evalue("2. fingerprints identiques d'une machine à l'autre", "idem")
    else:
        brut = raw_semgrep_eslint()
        fs = F.normaliser("semgrep", brut, racines=(m_scan,))
        absolus = [f.location["file"] for f in fs if str(f.location["file"]).startswith("/")]
        cas("1. artefact eslint : plus aucun chemin absolu", not absolus,
            f"{len(absolus)} absolus, ex: {absolus[0] if absolus else ''}")
        cas("1b. les chemins relatifs obtenus sont non vides",
            all(str(f.location["file"]) for f in fs) and len(fs) > 0, f"{len(fs)} findings")

        # 2. Indépendance machine : même dépôt, autre point de montage → mêmes identités
        autre = "/mnt/autre-machine/scan"
        brut2 = json.loads(json.dumps(brut).replace(m_scan, autre))
        fs2 = F.normaliser("semgrep", brut2, racines=(autre,))
        id1 = sorted(f.identity["fingerprint"] for f in fs)
        id2 = sorted(f.identity["fingerprint"] for f in fs2)
        cas("2. fingerprints identiques d'une machine à l'autre", id1 == id2 and len(id1) > 0,
            f"{len(id1)} vs {len(id2)}")

    # 3. Convention checkov : chemin à slash meneur → relatif au dépôt
    prov = Registry().provider("checkov")
    ck = F.normaliser("checkov", doc_checkov("/main.tf"), mani=prov.manifest,
                      racines=(m_scan,))
    cas("3. checkov '/main.tf' → 'main.tf'",
        len(ck) == 1 and ck[0].location["file"] == "main.tf",
        str(ck[0].location["file"]) if ck else "vide")
    ck2 = F.normaliser("checkov", doc_checkov(f"{m_scan}/k8s.yaml"), mani=prov.manifest,
                       racines=(m_scan,))
    cas("3b. checkov sous le montage → relatif",
        ck2[0].location["file"] == "k8s.yaml", ck2[0].location["file"])

    # 4. Régression : les chemins déjà relatifs ne bougent pas (formes trivy/gitleaks)
    doc_trivy = {"Results": [{"Target": "docs/package-lock.json", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "vite", "InstalledVersion": "1.0",
         "Severity": "HIGH", "Title": "t"}]}]}
    tv = F.normaliser("trivy", doc_trivy, racines=(m_scan,))
    cas("4. trivy : chemin relatif inchangé",
        tv and tv[0].location["file"] == "docs/package-lock.json",
        tv[0].location["file"] if tv else "vide")

    # 5. Compatibilité : normaliser() sans racines fonctionne comme avant
    tv0 = F.normaliser("trivy", doc_trivy)
    cas("5. appel sans racines : comportement historique",
        tv0 and tv0[0].location["file"] == "docs/package-lock.json")
    ck0 = F.normaliser("checkov", doc_checkov("/main.tf"), mani=prov.manifest)
    cas("5b. sans racines, le slash meneur est retiré aussi",
        ck0[0].location["file"] == "main.tf", ck0[0].location["file"])

    # 6. Hypothèse documentée : dans l'isolateur, la cible est la seule arborescence
    #    visible — un chemin à slash meneur EST relatif à la cible. '/etc/x' devient
    #    donc 'etc/x' : assumé et testé tel quel, pas découvert en production.
    ck3 = F.normaliser("checkov", doc_checkov("/etc/x"), mani=prov.manifest, racines=())
    cas("6. slash meneur hors cible connu : relativisé (hypothèse isolateur)",
        ck3[0].location["file"] == "etc/x", ck3[0].location["file"])

    bloc_canonique()

    for nom, cond, detail in CAS:
        print(("OK   " if cond else "ECHEC") + f" {nom}" + (f" — {detail}" if detail and not cond else ""))
    for nom, motif in NON_EVALUES:
        print(f"NON EVALUÉ {nom} — {motif}")
    print(f"\n{len(CAS) - len(ECHECS)}/{len(CAS)} cas vérifiés"
          + (f" · {len(NON_EVALUES)} non évalués" if NON_EVALUES else ""))
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
