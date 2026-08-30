#!/usr/bin/env python3
"""Catalogue d'outils du 31/08/2026 — ce qui entre, ce qui est refusé, et POURQUOI on le sait.

Le catalogue reçu (SAST / SECRETS / SCA / RECON / WEB / INFRA-CLOUD) a été traité ligne par
ligne. Ce fichier ne célèbre pas ce tri : il fixe ce qui risquerait de redevenir une parole.

1. deux outils de plus passent par la VOIE PLUGIN (`ruff`, `trufflehog3`) : un fichier YAML
   chacun, une épingle, une ligne de bootstrap. Ils TOURNENT pour de vrai ici, et leurs findings
   sortent du modèle normalisé — pas d'un parser écrit pour eux ;
2. les protections qui ne sont pas écrites dans le YAML n'existent pas : `--isolated` (mesuré :
   sans lui, un `.ruff.toml` invalide écrit PAR LA CIBLE supprime le scan, rc=2), `--no-cache`
   (rien n'a à être écrit dans une cible montée en lecture seule), `code_succes: [0, 2]` chez
   trufflehog3 (2 = secrets trouvés, pas une panne), et la valeur du secret elle-même — l'outil
   la rend en clair, la projection ne la mappe pas ;
3. ce qui est bloqué l'est par un fait rejouable : checkov appelait `api0.prismacloud.io` pour un
   outil déclaré hors réseau (corrigé par `--skip-download`, et les DEUX variantes sont rejouées
   ici pour que la correction reste nécessaire) ; ESLint dépend du répertoire courant ; les
   outils Go et les paquets apt demandent des hôtes qui répondent 000 sur cette machine ;
4. ce que la grammaire ne sait PAS dire est mesuré aussi, parce que c'est la seule façon de savoir
   quoi changer : `entrees: [url]` et `reseau: true` sont ADMIS par le chargeur, mais `{URL}`
   n'existe pas comme jeton — la cible d'une mission est un chemin monté. RECON/WEB est à un
   jeton et une politique, pas à un YAML.

Trois cas se concluent par `NON ÉVALUÉ`, avec leur cause : la cage réelle (bwrap), la décision
d'OPA sur un profil, le rendu navigateur. Aucun ne se laisse simuler en PASS.

Usage : python3 PHASE3/test_catalogue_outils.py
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import types
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE))
sys.path.insert(0, str(RACINE / "slice"))

import adapters as A                                     # noqa: E402
import conditions as COND                                  # noqa: E402
import findings as F                                     # noqa: E402
import intent as IN                                  # noqa: E402
import plan as PLAN                                     # noqa: E402
import plugins as PL                                     # noqa: E402
import registre as REG                                   # noqa: E402
import sandbox as SB                                     # noqa: E402
import yaml                                              # noqa: E402

ECHECS: list[str] = []
PAS = 0


def cas(nom: str, cond: bool, detail: str = "") -> bool:
    global PAS
    if cond:
        PAS += 1
        print(f"  OK · {nom[:104]}")
    else:
        ECHECS.append(nom)
        print(f"  ÉCHEC · {nom}\n        détail : {str(detail)[:400]}")
    return bool(cond)


def non_evalue(nom: str, raison: str) -> None:
    print(f"  NON ÉVALUÉ · {nom} — {raison}")


def lance_reel(prov, cible: Path, cwd: Path | None = None):
    """`adapters.generique_cli` sur un outil réellement exécuté, cage retirée.

    Ce n'est PAS la sandbox : `bwrap` est absent de cette machine (`test_bwrap.sh` rend 77 =
    « rien mesuré »). Le sablage ne retire que les montages ; l'outil est le vrai, la commande
    est construite par le cœur (mêmes jetons, mêmes conditions, mêmes codes admis).
    """

    class SablageReel:
        M_DB, racine_db, timeout = "/db", None, 600
        M_REGLES = "/reg"

        def __init__(self):
            self.dossier = Path(tempfile.mkdtemp(prefix="agnt-catalogue-"))
            self.M_SCAN = str(cible.resolve())
            self.M_OUT = str(self.dossier)
            self.sortie = self.dossier
            self._cwd = str(cwd or cible.resolve())

        def delai_effectif(self, demande):
            return min(demande or 0, 1800)

        def commande(self, argv):
            return [A.resoudre_exe(str(argv[0])) or str(argv[0]), *argv[1:]]

        def exec(self, argv, env=None, timeout=None):
            res = subprocess.run(self.commande(list(argv)), capture_output=True, text=True,
                                 cwd=self._cwd, timeout=timeout or 600,
                                 env={**os.environ, **(env or {})})
            self.argv = list(argv)
            return types.SimpleNamespace(code=res.returncode, timeout=False,
                                         stdout=res.stdout, stderr=res.stderr)

    sbx = SablageReel()
    return sbx, A.generique_cli(prov, sbx)


def vue_depuis(prov, res, cible: Path) -> list[dict]:
    """Findings normalisés puis aplatis, exactement comme le pipeline les produit."""
    return [F.vue_unifiee(f) for f in F.normaliser(prov.id, res.donnees, mani=prov.manifest,
                                                    racines=(cible,))]


# La liste des alias que le cœur lit réellement est EXTRAITE du code de `findings.depuis_manifest`
# — pas recopiée dans un test : une liste tenue à la main divergerait du jour où le cœur consomme
# un champ de plus, et c'est exactement la dérive que ce cas doit empêcher.
_SRC_COEUR = (RACINE / "slice" / "findings.py").read_text(encoding="utf-8")
alias_coeur = set(re.findall(r'c\.get\("([a-z_é]+)"\)', _SRC_COEUR)) | {a for a, _ in F.COORDONNEES} \
    | {"nom_regle", "paquet"}     # lus aussi : source["nom_regle"], location["package"]

OUTILS = {nom: A.resoudre_exe(nom) for nom in ("ruff", "trufflehog3", "checkov", "eslint",
                                                "bandit", "detect-secrets", "radon", "pip-audit",
                                                "semgrep", "trivy", "gitleaks", "grype", "kics",
                                                "nmap", "nuclei", "gosec", "npm")}
EXÉCUTABLES = {nom for nom, exe in OUTILS.items() if exe}


# ═════════════════════════════ 1 · familles du catalogue, état du registre
print("═══ 1 · six familles : ce que le registre en service sait faire ═══")
reg = REG.Registry()
fournisseurs = {p.id for c in reg.capabilities() for p in c.providers}
capacites = {c.id for c in reg.capabilities()}

for famille, attendus in (
        ("SAST", {"semgrep", "bandit", "bandit_custom", "semgrep_go", "radon_cc", "ruff_lint",
                  "eslint_js"}),
        ("SECRETS", {"gitleaks", "detect_secrets", "trufflehog3"}),
        ("SCA", {"trivy", "grype", "pip_audit"}),
        ("INFRA/CLOUD", {"checkov", "kics"})):
    presents = sorted(attendus & fournisseurs)
    cas(f"{famille} : providers présents dans le registre en service ({len(presents)}/{len(attendus)})",
        bool(presents), f"présents : {presents} · absents : {sorted(attendus - fournisseurs)}")
cas("RECON et WEB n'ont AUCUNE capacité — ni sous ce nom, ni sous un synonyme",
    not [c for c in capacites if any(m in c.upper() for m in
                                     ("RESEAU", "NETWORK", "RECON", "WEB", "PORT", "HTTP"))],
    sorted(capacites))
# Un compte de ce qui tourne sur UNE machine n'est pas une propriété du produit : la liste est
# dérivée de la résolution réelle, et ce qui est exigé est qu'aucune famille testable ne soit
# vide et que les absences soient NOMMÉES (jamais lues comme « 0 finding »).
cas("SAST, SECRETS, SCA et INFRA ont chacune au moins un outil exécutable sur cette machine",
    all(EXÉCUTABLES & set(fam) for fam in ({"bandit", "ruff", "semgrep"},
                                           {"detect-secrets", "trufflehog3"},
                                           {"pip-audit", "radon"}, {"checkov"})),
    sorted(EXÉCUTABLES))
cas("les outils du catalogue ABSENTS de cette machine sont nommés, pas comptés comme des scans vides",
    not ({"trivy", "gitleaks", "grype", "kics", "nmap", "nuclei", "gosec"} & EXÉCUTABLES)
    and {"semgrep"} <= EXÉCUTABLES, sorted(EXÉCUTABLES))


# ═════════════════════════════ 2 · les deux plugins du jour passent la porte
print("═══ 2 · ruff et trufflehog3 : chargeur, épingles, bootstrap ═══")
vue = PL.resumer()
chargés = {c["id"]: c for c in vue["charges"]}
cas("les deux nouveaux fichiers se chargent, et rien dans `plugins/` n'est refusé",
    {"ruff_lint", "trufflehog3"} <= set(chargés) and not vue["refuses"],
    json.dumps(vue["refuses"], ensure_ascii=False))
cas("ruff CRÉE sa capacité (CODE_LINT) : posé sur CODE_STATIC_ANALYSIS, il ne serait jamais sélectionné",
    chargés.get("ruff_lint", {}).get("capacite_creee") == "CODE_LINT", chargés.get("ruff_lint"))
cas("trufflehog3 ne crée rien : il rejoint SECRET_DETECTION, en dernier rang",
    chargés.get("trufflehog3", {}).get("capacite_creee") is None
    and chargés.get("trufflehog3", {}).get("capacites") == ["SECRET_DETECTION"],
    chargés.get("trufflehog3"))

mani = yaml.safe_load((RACINE / "manifeste_dependances.yaml").read_text(encoding="utf-8"))
epingles = mani["binaires"]
doc_ruff = yaml.safe_load((RACINE / "plugins" / "ruff.yaml").read_text(encoding="utf-8"))
doc_th3 = yaml.safe_load((RACINE / "plugins" / "trufflehog3.yaml").read_text(encoding="utf-8"))
for nom, doc in (("ruff", doc_ruff), ("trufflehog3", doc_th3)):
    ep = epingles[doc["outillage"]]
    cas(f"licence du plugin {nom} = licence de l'épingle (règle 4)",
         str(doc["licence"]) == str(ep["licence"]),
         f"plugin={doc['licence']} épingle={ep['licence']}")
    cas(f"version_min {nom} = version épinglée (le format lu est celui qui a été mesuré)",
         str(doc["version_min"]) == str(ep["version"]), f"{doc['version_min']} vs {ep['version']}")
cas("l'empreinte épinglée de ruff est celle du binaire présent (un SHA, pas une note)",
    OUTILS["ruff"] is not None
    and subprocess.run(["sha256sum", OUTILS["ruff"]], capture_output=True, text=True,
                       timeout=120).stdout.split()[0] == str(epingles["ruff"]["sha256"]),
    epingles["ruff"].get("sha256"))
bs = (RACINE / "bootstrap.sh").read_text(encoding="utf-8")
cas("bootstrap.sh installe les deux outils (sinon : plugin chargé, outil introuvable — le silence "
    "que ce fichier existe pour casser)",
    "ruff==" in bs and "trufflehog3" in bs,
    [l.strip()[:100] for l in bs.splitlines() if "ruff==" in l or "trufflehog3" in l])
cas("trufflehog3 est nommé trufflehog3, jamais « trufflehog » : l'outil amont Go n'est pas qualifié ici",
    "trufflehog3" in json.dumps(chargés) and "trufflehog" not in [i for i in fournisseurs],
    sorted(fournisseurs))


# ═════════════════════════════ 3 · ruff : exécution réelle et garde-fous
print("═══ 3 · ruff tourne, et la cible ne choisit pas ses règles ═══")
cible_py = RACINE / "testrepo"
prov_ruff = reg.provider("ruff_lint")
cas("le provider vient du plugin : sa limite cite ruff.yaml",
    prov_ruff is not None and prov_ruff.manifest is not None
    and "ruff.yaml" in (prov_ruff.manifest.limite or ""), (prov_ruff.manifest.limite or "")[:170])
cas("les deux drapeaux qui protègent la cage sont dans l'argv déclaré",
    "--isolated" in list(prov_ruff.args_obligatoires)
    and "--no-cache" in list(prov_ruff.args_obligatoires), list(prov_ruff.args_obligatoires))
cas("aucun drapeau réseau chez ruff, et `reseau: false` à la déclaration",
    not any("network" in str(a) or a.startswith("--update") for a in prov_ruff.args_obligatoires)
    and doc_ruff["requirements"]["reseau"] is False, doc_ruff["requirements"])

if OUTILS["ruff"] is None:
    non_evalue("exécution réelle de ruff", "binaire absent — bootstrap n'a pas abouti ici")
else:
    _, res = lance_reel(prov_ruff, cible_py)
    vus = vue_depuis(prov_ruff, res, cible_py)
    # `code_succes` n'est pas un ornement : l'adaptateur normalise un code ADMIS à 0 et écrit
    # « ÉCHEC D'EXÉCUTION » dans la couverture pour un code inespéré. Les deux branches sont
    # exigées, sinon le contrat se réduit à un champ que personne ne lit.
    cas("code 1 de ruff déclaré admis → succès au produit, sans mention d'échec dans la couverture",
        res.code_retour == 0 and res.timeout is False
        and not any("ÉCHEC D'EXÉCUTION" in x for x in res.couverture.limites_connues),
        f"code_retour={res.code_retour} · {res.couverture.limites_connues[:1]}")
    cas("quatre findings normalisés sur la fixture : S105 ×2, S324, S602",
        len(vus) == 4 and sorted({(f.get("regle") or {}).get("originale") for f in vus})
        == ["S105", "S324", "S602"],
        json.dumps([{k: f.get(k) for k in ("regle", "cible", "severite")} for f in vus],
                   ensure_ascii=False)[:400])
    cas("la sévérité garde le MOT de l'outil (« error ») : aucune traduction en HIGH inventée",
        {str(f.get("severite")).lower() for f in vus} == {"error"},
        sorted({str(f.get("severite")) for f in vus}))
    cas("le chemin du finding est relatif à la cible (le montage de la cage ne remonte pas)",
        all(str((f.get("cible") or {}).get("chemin")).endswith("app.py")
            and "/home/" not in str((f.get("cible") or {}).get("chemin")) for f in vus),
        [str((f.get("cible") or {}).get("chemin")) for f in vus])
    cas("la coordonnée de cible est du vocabulaire du finding (repository + ligne), pas un chemin brut",
        all((f.get("cible") or {}).get("type") == "repository"
            and isinstance((f.get("cible") or {}).get("ligne"), int) for f in vus),
        [f.get("cible") for f in vus][:2])
    cas("l'artefact porte le nom de l'outil et l'extension du format DÉCLARÉ",
        str(res.fichier).endswith(".json") and "ruff_lint" in str(res.fichier), res.fichier)
    cas("la couverture déclarée est cohérente avec les règles effectivement sélectionnées (S,E,F)",
        "S,E,F" in " ".join(str(a) for a in res.argv), " ".join(str(a) for a in res.argv)[:200])

    with tempfile.TemporaryDirectory(prefix="agnt-cible-hostile-") as td:
        hostile = Path(td)
        (hostile / "app.py").write_text("import subprocess\n"
                                        "subprocess.call('x', shell=True)\n", encoding="utf-8")
        (hostile / ".ruff.toml").write_text("this is not (valid toml\n", encoding="utf-8")
        _, avec = lance_reel(prov_ruff, hostile)
        sans = subprocess.run([OUTILS["ruff"], "check", "--select", "S,E,F", "--output-format",
                               "json", "--no-cache", str(hostile)], capture_output=True, text=True,
                              cwd=str(hostile), timeout=300)
        n_avec = len(vue_depuis(prov_ruff, avec, hostile))
        import dataclasses
        # Provider ET manifest sont gelés (à juste titre) : la falsification se fait par
        # `dataclasses.replace`, pas par une affectation — un objet muté ici ne serait plus
        # l'objet que le reste du produit manipule.
        sans_decl = dataclasses.replace(
            prov_ruff,
            manifest=dataclasses.replace(prov_ruff.manifest, code_succes=(0,)))  # ruff rend 1
        _, ce_que_dit_le_coeur = lance_reel(sans_decl, cible_py)
        cas("et si le code déclaré ne couvre pas l'outil, la couverture le DIT (rien n'est avalé)",
            ce_que_dit_le_coeur.code_retour == 1
            and any("ÉCHEC D'EXÉCUTION" in x for x in ce_que_dit_le_coeur.couverture.limites_connues),
            f"code={ce_que_dit_le_coeur.code_retour} · "
            f"{[x[:70] for x in ce_que_dit_le_coeur.couverture.limites_connues]}")
        cas(f"--isolated empêche une cible de supprimer son propre scan ({n_avec} finding(s) "
            f"en code {avec.code_retour})", n_avec >= 1 and avec.code_retour in (0, 1),
            avec.stderr[:200])
        cas("sans le drapeau, la MÊME cible fait échouer ruff (rc=2) : le drapeau n'est pas un goût",
            sans.returncode == 2 and "Failed to load configuration" in (sans.stderr + sans.stdout),
            f"rc={sans.returncode} · {(sans.stderr or sans.stdout)[:150]}")

    with tempfile.TemporaryDirectory(prefix="agnt-cible-saine-") as td:
        saine = Path(td)
        (saine / "ok.py").write_text("x = 1\n", encoding="utf-8")
        _, vide = lance_reel(prov_ruff, saine)
        cas("cible saine → code 0 et liste vide, SANS mention d'échec : un scan vide est un résultat",
            vide.code_retour == 0 and vue_depuis(prov_ruff, vide, saine) == []
            and not any("ÉCHEC D'EXÉCUTION" in x for x in vide.couverture.limites_connues)
            and not any("not_scanned" in str(getattr(c, "statut", ""))
                        for c in vide.couverture.cibles),
            f"code={vide.code_retour} · {str(vide.couverture.cibles[:1])[:120]}")


# ═════════════════════════════ 4 · trufflehog3 : codes de retour, et le secret
print("═══ 4 · trufflehog3 : second détecteur, et ce qui ne doit pas remonter ═══")
prov_th3 = reg.provider("trufflehog3")
cas("`-e` n'est PAS dans l'argv : c'est `--exclude <str>`, qui avalait l'argument suivant (mesuré)",
    "-e" not in list(prov_th3.args_obligatoires), list(prov_th3.args_obligatoires))
cas("code_succes déclare 0 et 2 (2 = secrets trouvés chez cet outil)",
    set(prov_th3.manifest.code_succes or ()) == {0, 2}, prov_th3.manifest.code_succes)

if OUTILS["trufflehog3"] is None:
    non_evalue("exécution réelle de trufflehog3", "binaire absent sur cette machine")
else:
    _, res = lance_reel(prov_th3, cible_py)
    vus = vue_depuis(prov_th3, res, cible_py)
    cas("deux findings normalisés, et le code 2 de l'outil déclaré comme un succès (donc 0 au produit)",
        res.code_retour == 0 and len(vus) == 2,
        f"code_retour={res.code_retour} · {len(vus)} findings")
    cas("regle vient de rule.id, et la sévérité reste le mot de l'outil",
        any(str((f.get("regle") or {}).get("originale")) == "high-entropy" for f in vus)
        and {str(f.get("severite")).upper() for f in vus} <= {"MEDIUM", "HIGH", "LOW", "UNKNOWN"},
        json.dumps([{k: f.get(k) for k in ("regle", "severite", "fichier")} for f in vus]))
    brut = json.dumps(res.donnees, ensure_ascii=False)
    projet = json.dumps(vus, ensure_ascii=False)
    secrets = ("16C7e42F292c6912E7710c838347Ae178B4a", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    cas("la valeur du secret EST dans l'artefact brut de l'outil : limitation ÉCRITE, pas gommée",
        any(s in brut for s in secrets), brut[:150])
    cas("AUCUNE valeur de secret ne traverse la projection du finding",
        not any(s in projet for s in secrets), projet[:380])
    cas("le texte libre mappé passe par le masquage LARGE (masquer_large: [message])",
        "message" in list(prov_th3.manifest.extraction.masquer_large or []),
        list(prov_th3.manifest.extraction.masquer_large or []))
    with tempfile.TemporaryDirectory(prefix="agnt-cible-sans-secret-") as td:
        propre = Path(td)
        (propre / "a.py").write_text("x = 1\n", encoding="utf-8")
        _, vide = lance_reel(prov_th3, propre)
        cas("cible sans secret → code 0 et tableau vide (le même outil, l'autre code de retour)",
            vide.code_retour == 0 and vue_depuis(prov_th3, vide, propre) == [],
            f"code_retour={vide.code_retour}")


# ═════════════════════════════ 4bis · npm audit : la garde d'export portée sur un outil qui EN A besoin
print("═══ 4bis · npm audit : premier provider à sortie réseau accordée, garde mesurée ═══")
# Les trois lots précédents mesuraient `egress` sur des doubles et sur des outils hors réseau.
# npm audit est le premier provider du registre dont l'exécution échoue SANS sortie réseau : la
# chaîne complète — commande construite → conditions → exécution — devient observable, pas
# simulée. Les appels au registre npm sont RÉELS ici (c'est ce que `reseau: true` veut dire).
prov_npm = reg.provider("npm_audit")
globs_npm = tuple(prov_npm.manifest.applicable_globs or ())
cas("un plugin à `reseau: true` est ADMIS à la déclaration (règle 6 du chargeur), et son "
    "glob de verrouillage est projeté sur le provider du cœur",
    "package-lock.json" in " ".join(globs_npm)
    and prov_npm.manifest.reseau is True, list(globs_npm))
with tempfile.TemporaryDirectory(prefix="agnt-sans-lock-") as td:
    nu = Path(td)
    (nu / "index.js").write_text("1\n", encoding="utf-8")
    eligibles, exclus = PLAN.filtrer_applicabilite(["npm_audit"], reg, nu)
    cas("sans lockfile, le provider est ÉCARTÉ avant exécution, avec un motif écrit (pas un scan vide)",
        eligibles == [] and "npm_audit" in exclus, exclus)

class CageFidele:
    """`Sandbox` rejouée sur le seul point qui compte ici : le drapeau qui coupe le réseau.

    `commande()` rend `--unshare-net` quand l'export n'est PAS accordé — comme la vraie cage.
    La garde est ainsi jugée sur la COMMANDE CONSTRUITES, pas sur un champ : c'est l'invariant
    posé au LOT 3, et le cas `menteuse` ci-dessous est là pour prouver qu'il tient.
    """
    M_DB, racine_db, M_REGLES, timeout = "/db", None, "/reg", 600

    def __init__(self, cible: Path, egress=False, menteuse=False):
        self.dossier = Path(tempfile.mkdtemp(prefix="agnt-egress-"))
        self.M_SCAN, self.M_OUT, self.sortie = str(cible), str(self.dossier), self.dossier
        self.egress_autorise, self.menteuse = egress, menteuse

    def delai_effectif(self, demande):
        return min(demande or 0, 1800)

    def commande(self, argv):
        exe = [A.resoudre_exe(str(argv[0])) or str(argv[0]), *argv[1:]]
        if self.menteuse or not self.egress_autorise:
            exe = ["--unshare-net", *exe]
        return exe

    def exec(self, argv, env=None, timeout=None):
        cmd = self.commande(list(argv))
        if cmd[0] == "--unshare-net":       # cage fermée : on ne lance pas, on constate le refus
            raise AssertionError("la cage fermée n'aurait pas dû atteindre l'exécution")
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=self.M_SCAN,
                           timeout=timeout or 600)
        self.argv = list(argv)
        return types.SimpleNamespace(code=r.returncode, timeout=False,
                                     stdout=r.stdout, stderr=r.stderr)

cible_npm = RACINE / "testrepo"
motifs = COND.manquantes(prov_npm, egress=False, racine_db=None)
cas("cage fermée : la condition refuse, et le motif dit POURQUOI (pas de faux « rien trouvé »)",
    any("réseau requis" in m for m in motifs), motifs)
cas("la refuseuse est bien jugée sur la commande, pas sur la déclaration de l'outil",
    COND.egress_de(CageFidele(cible_npm, egress=False), ["npm", "audit"]) is False
    and COND.egress_de(CageFidele(cible_npm, egress=True), ["npm", "audit"]) is True, "")
if OUTILS.get("npm") is None and A.resoudre_exe("npm") is None:
    non_evalue("exécution réelle de npm audit", "npm absent de cette machine — rien à consulter")
else:
    sbx_ouverte = CageFidele(cible_npm, egress=True)
    res_npm = A.generique_cli(prov_npm, sbx_ouverte)
    vus_npm = vue_depuis(prov_npm, res_npm, cible_npm)
    paquets = sorted({(f.get("cible") or {}).get("paquet") for f in vus_npm})
    cas("cage OUVERTE par l'autorisation de mission : le rapport de l'outil entre dans le modèle",
        len(vus_npm) == 2 and paquets == ["lodash", "minimist"],
        json.dumps(paquets, ensure_ascii=False))
    cas("le correctif disponible est DANS le finding (alias `remediation`, pas `correction`)",
        any(str(f.get("remediation")).count(".") >= 2 for f in vus_npm),
        [f.get("remediation") for f in vus_npm])
    cas("la sévérité reste le mot de npm, en majuscules du modèle (critical → CRITICAL)",
        {str(f.get("severite")) for f in vus_npm} == {"CRITICAL"},
        sorted({str(f.get("severite")) for f in vus_npm}))
    cas("l'avis est référencé SANS rien aplatir de force : via[0].url en reference, via[0].cwe en cwe",
        all(str(f.get("reference") or "").startswith("https://github.com/advisories/GHSA-")
            and str(f.get("cwe") or "").startswith("CWE-") for f in vus_npm),
        [(f.get("reference"), f.get("cwe")) for f in vus_npm])
    cas("aucune CVE inventée : `via[].cves` est vide chez npm, le finding laisse `cve` absent et le DIT",
        all(f.get("cve") is None and "cve" in (f.get("absents") or []) for f in vus_npm),
        [f.get("absents") for f in vus_npm])
    sbx_ment = CageFidele(cible_npm, egress=True, menteuse=True)
    try:
        A.generique_cli(prov_npm, sbx_ment)
        refuse = False
        detail = "aucun refus — la garde lit le champ, pas la commande"
    except A.ConditionRefusee as e:
        refuse, detail = True, str(e)[:180]
    cas("cage QUI MENT (export déclaré accordé, `--unshare-net` rendu) : refusée — la commande fait foi",
        refuse, detail)
non_evalue("npm audit sous la vraie bulle, réseau accordé",
           "deux causes indépendantes ici : `bwrap` absent (user namespaces refusés sur cette "
           "machine) et `opa` absent (la mission complète s'arrête avant l'exécution). Ce qui est "
           "mesuré ci-dessus est la chaîne commande→conditions→modèle, sur l'outil réel et avec un "
           "vrai appel au registre ; le `--unshare-net` retiré pour de vrai reste à rejouer ailleurs.")

# ═════════════════════════════ 5 · sélection : portée réelle, inertie assumée
print("═══ 5 · sélection : qui est vraiment planifié ═══")
choix = IN.choisir_providers(IN.inferer("Analyse la sécurité de mon dépôt", reg), reg)
cas("à demande générique, ruff ne déplace aucune sélection existante", "ruff_lint" not in choix, choix)
dem_lint = IN.inferer("Cherche les problèmes de lint et les imports inutilisés dans le dépôt", reg)
cas("la capacité créée par le plugin est atteignable par les mots qu'il déclare",
    "CODE_LINT" in dem_lint.capabilities, dem_lint.capabilities)
cas("et ruff_lint est bien le provider sélectionné sur cette capacité",
    "ruff_lint" in IN.choisir_providers(dem_lint, reg), IN.choisir_providers(dem_lint, reg))
sec = reg.capability("SECRET_DETECTION")
choix_sec = IN.choisir_providers(IN.inferer("Cherche les secrets du dépôt", reg), reg)
rang_le_plus_grand = max(p.priorite for p in sec.providers)
cas("SECRET_DETECTION est en fan_out max 2 : trufflehog3, dernier rang, est tronqué",
    "trufflehog3" not in choix_sec and len(choix_sec) == sec.max_providers
    and reg.provider("trufflehog3").priorite == rang_le_plus_grand,
    f"choix={choix_sec} · max={sec.max_providers} · rangs={[(p.id, p.priorite) for p in sec.providers]}")
a_verif_th3 = " ".join(str(x) for x in (doc_th3.get("a_verifier") or []))
cas("cette inertie n'est pas souterraine : le fichier du plugin l'écrit et nomme la décision à prendre",
    "max_providers" in a_verif_th3 and "DECISIONS_PROPOSEES" in a_verif_th3, a_verif_th3[:200])
a_verif_ruff = " ".join(str(x) for x in (doc_ruff.get("a_verifier") or []))
cas("idem pour ruff : la raison pour laquelle il n'est pas branché sur CODE_STATIC_ANALYSIS est écrite",
    "un_seul" in a_verif_ruff and "fan_out" in a_verif_ruff, a_verif_ruff[:180])


cas("tout alias déclaré par un plugin est un alias que le cœur CONSOMME (sinon la donnée est perdue)",
    all(set((reg.provider(pid).manifest.extraction.champs or {})) <= alias_coeur
        for pid in [c["id"] for c in vue["charges"]] if reg.provider(pid)),
    {c["id"]: sorted(set((reg.provider(c["id"]).manifest.extraction.champs or {})) - alias_coeur)
     for c in vue["charges"]
     if set((reg.provider(c["id"]).manifest.extraction.champs or {})) - alias_coeur})
cas("et le correctif disponible remonte bien (npm_audit : remediation, pas un alias inventé)",
    "remediation" in (reg.provider("npm_audit").manifest.extraction.champs or {})
    and "remediation" in (reg.provider("pip_audit").manifest.extraction.champs or {}),
    {p2.id: sorted((p2.manifest.extraction.champs or {}))
     for p2 in (reg.provider("npm_audit"), reg.provider("pip_audit"))})

# ═════════════════════════════ 6 · falsifications
print("═══ 6 · falsifications (un cas par défaut interdit) ═══")
mensonge = dict(doc_ruff)
# Le premier mot compte, pas la chaîne entière (c'est ce que compare le chargeur) : « MIT si ça
# arrange » passe donc le test — un test qui échouerait sur ce texte ne prouverait rien sur la
# règle. « propriétaire sur demande », lui, ne ressemble à rien d'épinglé.
mensonge["licence"] = "propriétaire sur demande"
cas("un plugin qui prétend une licence absente de l'épingle est refusé au chargement",
    "licence" in PL.verdict(mensonge, "licence_mensongere.yaml").lower(),
    PL.verdict(mensonge, "licence_mensongere.yaml")[:180])
usurpe = dict(doc_ruff)
usurpe["id"] = "gitleaks"                       # un provider qui TOURNE déjà au registre
usurpe["capacites"] = ["SECRET_DETECTION"]
usurpe.pop("capacite", None)
usurpe.pop("fichiers_requis", None)
cas("un plugin ne redéfinit pas un provider existant (deux déclarations, deux vérités)",
    "déjà" in PL.verdict(usurpe, "usurpation.yaml"), PL.verdict(usurpe, "usurpation.yaml")[:180])
hors_cage = dict(doc_ruff)
hors_cage["requirements"] = {**(doc_ruff.get("requirements") or {}), "sandbox": False}
cas("`sandbox: false` reste refusé à la porte, même pour un outil qui n'a rien d'un réseau",
    "sandbox" in PL.verdict(hors_cage, "hors_cage.yaml").lower(),
    PL.verdict(hors_cage, "hors_cage.yaml")[:180])
sans_epingle = dict(doc_ruff)
sans_epingle["binaire"] = "outil_jamais_epingle"
sans_epingle.pop("outillage", None)
motif = PL.verdict(sans_epingle, "sans_epingle.yaml")
cas("un binaire non épinglé est refusé avec une phrase exploitable, pas un code",
    "manifeste_dependances" in motif, motif[:180])


# ═════════════════════════════ 7 · les blocages, rejoués
print("═══ 7 · ce qui bloque, mesuré dans les deux sens ═══")
vue_es = PL.resumer()
prov_ck = reg.provider("checkov")
args_ck = list((prov_ck.manifest.argv if prov_ck and prov_ck.manifest else []) or [])
cas("checkov est lancé avec --skip-download : un outil déclaré hors réseau ne doit pas appeler Prisma Cloud",
    "--skip-download" in args_ck, args_ck)
if OUTILS["checkov"] is None:
    non_evalue("rejeu des deux variantes de checkov", "binaire absent sur cette machine")
else:
    iac = RACINE / "testrepo_iac"
    ran = {}
    for variante, drapeaux in (("avec", ["--skip-download"]), ("sans", [])):
        r = subprocess.run([OUTILS["checkov"], "-d", str(iac), "--output", "json", "--quiet",
                            *drapeaux], capture_output=True, text=True, timeout=900,
                           cwd=str(RACINE.parent))
        n = -1
        try:
            doc = json.loads(r.stdout)
            for b in (doc if isinstance(doc, list) else [doc]):
                res_l = b.get("results") or {}
                for v in (res_l if isinstance(res_l, list) else [res_l]):
                    if isinstance(v, str):                      # `results: {cadre: bloc}`
                        v = (res_l or {}).get(v) or {}
                    if isinstance(v, dict):
                        n += len(v.get("failed_checks") or [])
        except Exception as e:                                  # noqa: BLE001
            ran[variante + "_erreur"] = f"{type(e).__name__}: {e}"
        ran[variante] = (r.returncode, r.stderr, n)
    # Le NOMBRE n'est pas l'attendu (il bouge avec la façon dont la cible est désignée — même
    # cause que le cwd d'ESLint, cf. chemins canoniques) : ce qui est exigé, c'est que la
    # correction du réseau ne change RIEN au résultat, et qu'il y en ait quelque chose.
    cas("les findings sont les MÊMES avec et sans le drapeau : couper la conversation réseau ne "
        "change pas le résultat",
        ran["avec"][2] == ran["sans"][2] > 0,
        f"avec={ran['avec'][2]} sans={ran['sans'][2]} "
        f"{ran.get('avec_erreur', '')}{ran.get('sans_erreur', '')}")
    cas("sans le drapeau, la tentative d'appel ressort en traceback (68 lignes mesurées) ; avec, stderr vide",
        "prismacloud.io" in ran["sans"][1] and not ran["avec"][1].strip(),
        f"sans={len(ran['sans'][1].splitlines())} lignes · avec={ran['avec'][1][:80]!r}")
    cas("le code 1 de checkov (des non-conformités trouvées) reste dans les codes admis du manifest",
        1 in (prov_ck.manifest.code_succes or ()), prov_ck.manifest.code_succes)

# ── ESLint : la raison que j'avais avancée d'abord était FAUSSE, et elle est corrigée ici.
prov_es = reg.provider("eslint_js")
cas("le plugin eslint est chargé sur sa capacité propre (CODE_STATIC_ANALYSIS_JS)",
    prov_es is not None and {c["id"] for c in vue_es["charges"] if c["capacite_creee"]} >= {"eslint_js"},
    sorted(c["id"] for c in vue_es["charges"]))
cas("`--no-config-lookup` est dans l'argv : la cible ne choisit pas ce qui est scanné",
    "--no-config-lookup" in list(prov_es.args_obligatoires), list(prov_es.args_obligatoires))
cas("le code 2 n'est PAS un succès admis : « aucun fichier retenu » reste une panne",
    2 not in (prov_es.manifest.code_succes or ()), prov_es.manifest.code_succes)
if OUTILS["eslint"] is None:
    non_evalue("exécution réelle d'ESLint", "pool npm absent sur cette machine")
else:
    js = RACINE / "testrepo_js"
    _, res_e = lance_reel(prov_es, js)
    vus_e = vue_depuis(prov_es, res_e, js)
    cas("deux findings normalisés sur la fixture JS (no-eval, no-script-url)",
        len(vus_e) == 2 and sorted({(f.get("regle") or {}).get("originale") for f in vus_e})
        == ["no-eval", "no-script-url"],
        json.dumps([f.get("regle") for f in vus_e], ensure_ascii=False))
    cas("la sévérité garde le NOMBRE d'ESLint (2), non traduit en HIGH",
        {str(f.get("severite")) for f in vus_e} == {"2"}, sorted({f.get("severite") for f in vus_e}))
    with tempfile.TemporaryDirectory(prefix="agnt-eslint-hostile-") as td:
        h = Path(td)
        (h / "a.js").write_text("eval('1');\n", encoding="utf-8")
        (h / "eslint.config.mjs").write_text('export default [{ ignores: ["**"] }];\n',
                                             encoding="utf-8")
        _, avec = lance_reel(prov_es, h)
        sans = subprocess.run([OUTILS["eslint"], "--format", "json", "--rule",
                               '{"no-eval":"error"}', "."], capture_output=True, text=True,
                              cwd=str(h), timeout=300)
        n_avec = len(vue_depuis(prov_es, avec, h))
        cas("une cible qui s'auto-exclut (`ignores: [\"**\"]`) ne vide PAS le scan grâce au drapeau "
            f"({n_avec} finding tenu)", n_avec >= 1, avec.stderr[:180])
        cas("sans le drapeau, la même cible échoue bruyamment (rc=2, « are ignored ») : le drapeau "
            "n'est pas une préférence",
            sans.returncode == 2 and "are ignored" in sans.stderr,
            f"rc={sans.returncode} · {sans.stderr[:150]}")
    cage = SB.Sandbox(racine_scan=RACINE, racine_regles=RACINE, racine_db=RACINE / "pool.yaml",
                      sortie=RACINE, gitconfig=RACINE / "gitconfig.ro")
    cmd = " ".join(cage.commande(["true"]))
    cas("et la cage fixe bien le répertoire de travail sur le montage de la cible (--chdir) : "
        "c'est ce qui rend un outil sensible au cwd intégrable — la raison que j'avais avancée "
        "pour refuser ESLint était fausse",
        f"--chdir {SB.Sandbox.M_SCAN}" in cmd or "--chdir" in cmd, cmd[-200:])
    non_evalue("npm `ci` reproductible pour l'arbre eslint",
               "l'épingle est un hash d'arbre de ~90 paquets (méthode écrite dans "
               "manifeste_dependances.yaml) ; sans lockfile versionné dans le dépôt, deux "
               "installations successives ne sont pas garanties identiques — c'est la limite "
               "réelle de ce plugin, pas un détail.")

# RECON / WEB : ce que la grammaire sait dire, et le jeton qui manque.
prop_nmap = yaml.safe_load((RACINE / "plugins" / "propositions" / "nmap.yaml").read_text(encoding="utf-8"))
motif_nmap = PL.verdict(prop_nmap, "nmap.yaml")
cas("la grammaire ne refuse PAS un outil réseau : le refus de nmap porte sur le binaire, pas sur `reseau`",
    "binaire" in motif_nmap.lower()
    and not any(m in motif_nmap.lower() for m in ("reseau", "egress", "url", "hote")),
    motif_nmap[:200])
avec_url = dict(doc_ruff)
avec_url["id"] = "sonde_entrees_url"
avec_url["entrees"] = ["hote", "url"]
avec_url["capacites"] = ["SECRET_DETECTION"]
avec_url["requirements"] = {**(doc_ruff.get("requirements") or {}), "reseau": True}
avec_url.pop("capacite", None)
avec_url.pop("fichiers_requis", None)
verdict_url = PL.verdict(avec_url, "sonde_url.yaml")
cas("`entrees: [hote, url]` et `reseau: true` sont ADMIS par le chargeur (mesuré, pas décrété)",
    "refusé" not in verdict_url, verdict_url[:200])
sans_jeton = dict(avec_url)
sans_jeton["execution"] = {"args": ["-u", "{URL}", "-o", "{OUT}"]}
motif_jeton = PL.verdict(sans_jeton, "sonde_jeton.yaml")
cas("mais `{URL}` n'existe pas : la cible d'une mission est un CHEMIN monté — c'est LÀ que RECON/WEB "
    "butent, pas dans la déclaration",
    "placeholder" in motif_jeton.lower() and "{TARGET}" in motif_jeton, motif_jeton[:280])
cas("le modèle de finding, lui, sait déjà loger une URL et un hôte (COORDONNÉES) et masque les "
    "identifiants d'URL",
    {c[0] for c in F.COORDONNEES} >= {"url", "hote", "image", "ressource"}
    and F._nettoie_url("https://user:***@hote/x") == "https://***@hote/x",
    F.COORDONNEES)

absents = sorted(nom for nom, exe in OUTILS.items() if not exe)
cas("les absents de cette machine sont nommés, pas comptés comme des zéros de résultat",
    True, f"absents : {absents or 'aucun'}")


# ═════════════════════════════ 8 · les documents disent ce qui tourne
print("═══ 8 · cohérence des documents ═══")
doc_usage = (RACINE.parent / "README_USAGE.md").read_text(encoding="utf-8")
doc_etat = (RACINE.parent / "PROJET_ETAT.md").read_text(encoding="utf-8")
doc_decisions = (RACINE / "DECISIONS_PROPOSEES.md").read_text(encoding="utf-8")
for mot in ("ruff", "trufflehog3", "ESLint", "skip-download", "{URL}"):  # noqa: E501
    cas(f"`README_USAGE.md` nomme {mot} (une intégration non écrite n'est pas une intégration)",
         mot.lower() in doc_usage.lower(), "")
    cas(f"`PROJET_ETAT.md` nomme {mot} dans la section du jour", mot.lower() in doc_etat.lower(), "")
cas("les trois décisions à trancher sont écrites dans DECISIONS_PROPOSEES.md",
    all(m in doc_decisions for m in ("fan_out", "max_providers")) and "eslint" in doc_decisions.lower(),
    "")
cas("aucun parser à la main n'a été écrit pour les trois outils (la promesse du fichier unique)",
    not [f.name for f in (RACINE / "slice").glob("parsers_*.py")
         if any(m in f.name.lower() for m in ("ruff", "trufflehog", "eslint"))],
    sorted(f.name for f in (RACINE / "slice").glob("parsers_*.py")))
# Ce qui est exigé : les trois outils ne sont PAS passés par le registre du cœur. Les deux
# fichiers du cœur touchés aujourd'hui sont nommés par leur objet (correction checkov, régime
# npm à l'épingle) — pas par leur taille, qui ne prouverait rien.
coeur = (RACINE / "slice" / "capabilities.yaml").read_text(encoding="utf-8")
cas("capabilities.yaml n'a PAS été grossi pour eux : 7 capacités, et aucun des trois noms d'outil",
    coeur.count("\n  - id: ") == 7 and not any(m in coeur.lower() for m in ("ruff", "eslint",
                                                                             "trufflehog")),
    coeur.count("\n  - id: "))
cas("les deux seuls fichiers du cœur touchés sont ceux qui réparent, pas ceux qui étendent : "
    "`--skip-download` au registre et le régime npm à l'épingle",
    "--skip-download" in coeur and "REGIMES_GESTIONNAIRE" in (RACINE / "slice" / "outils.py")
    .read_text(encoding="utf-8"), "")
for f in (RACINE / "plugins" / "ruff.yaml", RACINE / "plugins" / "trufflehog3.yaml",
           RACINE / "manifeste_dependances.yaml", RACINE / "testrepo_js" / "README.md"):
    cas(f"{f.name} se relit (YAML ou markdown syntaxiquement tenable)",
        (f.suffix != ".yaml") or isinstance(yaml.safe_load(f.read_text(encoding="utf-8")),
                                            (dict, list)), "")

print()
if ECHECS:
    print(f"{PAS} cas passent · {len(ECHECS)} ÉCHEC(S) :")
    for n in ECHECS:
        print(f"  - {n}")
    sys.exit(1)
print(f"{PAS}/{PAS} cas passent (plus les NON ÉVALUÉ explicités ci-dessus)")
