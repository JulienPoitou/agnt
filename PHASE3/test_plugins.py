#!/usr/bin/env python3
"""
Batterie « intégration d'un outil public par un fichier de plugin » — LOT 2.

Ce que la plateforme doit savoir faire, énoncé par la commande du 2026-08-30 : « un outil
public peut être intégré sans toucher au cœur ». Deux outils sont intégrés par cette voie et
par elle seule :

  · `radon` (mesure de complexité, hors réseau) — il TOURNE pour de vrai dans cette batterie,
    sur le code de la plateforme elle-même, et rend 45 findings (cas 5) ;
  · `pip-audit` (audit de dépendances, sort sur PyPI) — il prouve l'autre moitié : un outil
    réseau est REFUSÉ par les conditions, et le refus doit être lisible (cas 6).

Touche du cœur, pour l'un comme pour l'autre : zéro ligne dans `capabilities.yaml`, zéro
`parsers_*.py`, zéro ajout dans `BINAIRES_AUTORISES`. Les deux touches légitimes sont le fichier
`plugins/<id>.yaml` et l'épingle dans `manifeste_dependances.yaml` — l'épingle EST la porte, le
plugin se borne à la nommer.

Comment ce qui est affirmé est mesuré :
  - les portes du chargeur sont mesurées par FALSIFICATION : un plugin fautif par défaut
    interdit, avec le motif attendu. Un contrôle qui n'a jamais vu d'erreur ne vaut rien ;
  - la sortie de `radon` est celle de l'outil, capturée par `subprocess.run` : l'isolateur est
    remplacé par un double dont `exec` lance réellement la commande. Les MONTAGES (ro-bind,
    unshare) ne sont donc pas mesurés — bloc NON ÉVALUÉ en fin de fichier ;
  - `csv` est exercé sur les OCTETS RÉELS de `bandit -f csv` ; `jsonl`/`xml` sur leur forme
    documentée, faute d'outil installable ici qui les rende (mesuré : `openpolicyagent.org`
    répond 000 et `release-assets.githubusercontent.com` échoue en TLS, donc nmap/nikto ne sont
    pas téléchargeables sur cette machine).

Usage : python3 PHASE3/test_plugins.py        (PYTHONPATH doit voir PyYAML)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE))
sys.path.insert(0, str(RACINE / "slice"))

import adapters as A                                     # noqa: E402
import conditions as COND                                # noqa: E402
import extraction as EX                                  # noqa: E402
import findings as F                                     # noqa: E402
import intent as IN                                      # noqa: E402
import plugins as PL                                     # noqa: E402
import provider_manifest as PM                           # noqa: E402
import registre as REG                                   # noqa: E402

CAS: list[tuple[str, bool, str]] = []
NON_EVALUE: list[tuple[str, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond: bool, detail: str = "") -> bool:
    CAS.append((nom, bool(cond), str(detail)[:240]))
    if not cond:
        ECHECS.append(nom)
    return bool(cond)


def non_evalue(nom: str, raison: str) -> None:
    NON_EVALUE.append((nom, raison))


try:
    import yaml                                          # noqa: E402
except Exception:
    print("PyYAML introuvable — `export PYTHONPATH=/chemin/vers/pool` (ou bash PHASE3/bootstrap.sh).")
    sys.exit(2)

ATELIER = Path(tempfile.mkdtemp(prefix="agnt-plugins-"))


def ecrire_plugin(dossier: Path, nom: str, **champs) -> Path:
    """Écrit un plugin au minimum valide, puis applique les modifications demandées."""
    base = {
        "id": "outil_test",
        "capacites": ["CODE_STATIC_ANALYSIS"],
        "binaire": "bandit",
        "outillage": "bandit",
        "risque": "PASSIVE",
        "licence": "Apache-2.0",
        "execution": {"args": ["-r", "{TARGET}"]},
        "sortie": {"format": "json"},
        "lecture": {"modele": "plat", "items_from": "results",
                    "champs": {"regle": "test_id", "message": "issue_text"}},
        "requirements": {"reseau": False, "sandbox": True},
    }
    base.update(champs)
    for cle, val in list(base.items()):
        if val is None:
            base.pop(cle)
    chemin = dossier / nom
    chemin.write_text(yaml.safe_dump(base, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return chemin


def motif_refus(chemin: Path, *, capacites=(), fournisseurs=()) -> str:
    """Motif de refus, ou '' si accepté. Un autre type d'exception est un défaut, pas un refus."""
    try:
        PL.charger_un(chemin, set(capacites), set(fournisseurs))
    except PL.PluginError as e:
        return str(e)
    except Exception as e:                              # noqa: BLE001
        return f"!!! {type(e).__name__}: {e}"
    return ""


def lance_reel(prov, cible: Path):
    """`generique_cli` sur un outil réellement exécuté, hors montages (voir docstring)."""

    class SablageReel:
        M_DB, racine_db, timeout = "/db", None, 600
        M_REGLES = "/reg"

        def __init__(self):
            self.dossier = Path(tempfile.mkdtemp(prefix="agnt-plugin-"))
            self.M_SCAN = str(cible.resolve())
            self.M_OUT = str(self.dossier)
            self.sortie = self.dossier

        def delai_effectif(self, demande):
            return min(demande or 0, 1800)

        def commande(self, argv):
            return [A.resoudre_exe(str(argv[0])) or str(argv[0]), *argv[1:]]

        def exec(self, argv, env=None, timeout=None):
            res = subprocess.run(self.commande(list(argv)), capture_output=True, text=True,
                                 cwd=self.M_SCAN, timeout=timeout or 600)
            self.argv = list(argv)
            return types.SimpleNamespace(code=res.returncode, timeout=False,
                                         stdout=res.stdout, stderr=res.stderr)

    sbx = SablageReel()
    return sbx, A.generique_cli(prov, sbx)


# ═════════════════════════════ 1 · ce qui est livré se charge
print("═══ 1 · les plugins du dépôt ═══")
vue = PL.resumer()
cas("le dossier chargé est `plugins/`, jamais `plugins/propositions/`",
    Path(vue["dossier"]) == RACINE / "plugins", vue["dossier"])
chargés = {c["id"]: c for c in vue["charges"]}
# Ce n'est plus « deux » : le dossier a grandi (ruff, trufflehog3 le 31/08/2026). Un compte
# figé ne prouve rien — il échoue quand le travail est fait et passe quand il est faux. Ce qui
# est exigé ici : TOUT le dossier se charge, et rien n'est refusé.
cas("tout le dossier `plugins/` se charge, et aucun fichier n'est refusé",
    len(vue["charges"]) == len(PL.fichiers()) and not vue["refuses"],
    json.dumps(vue["refuses"], ensure_ascii=False))
cas("radon_cc vise une capacité qu'il CRÉE",
    chargés.get("radon_cc", {}).get("capacite_creee") == "CODE_METRICS", chargés.get("radon_cc"))
cas("pip_audit se branche sur une capacité qui EXISTE déjà, sans en créer",
    chargés.get("pip_audit", {}).get("capacite_creee") is None
    and chargés.get("pip_audit", {}).get("capacites") == ["DEPENDENCY_ANALYSIS"],
    chargés.get("pip_audit"))
cas("le binaire d'un plugin épinglé est admis sans toucher BINAIRES_AUTORISES",
    PM.binaire_autorise("radon") and not PM.binaire_autorise("nmap")
    and "radon" not in PM.BINAIRES_AUTORISES,
    f"radon={PM.binaire_autorise('radon')} nmap={PM.binaire_autorise('nmap')}")
cas("un chemin, un `./radon` ou le nom vide restent refusés (l'épingle n'est pas un blanc-seing)",
    not PM.binaire_autorise("/bin/sh") and not PM.binaire_autorise("./radon")
    and not PM.binaire_autorise(""), "")
cas("la raison d'un refus non épinglé est une phrase exploitable, pas un code",
    "manifeste_dependances.yaml" in PM.binaire_est_autorise("nmap"), PM.binaire_est_autorise("nmap"))

# ═════════════════════════════ 2 · les portes, vues de l'extérieur : falsifications
print("═══ 2 · falsifications (un cas par défaut interdit) ═══")
d = ATELIER / "falsifs"
d.mkdir(exist_ok=True)
CODE = ["CODE_STATIC_ANALYSIS"]

m = motif_refus(ecrire_plugin(d, "cle_inconnue.yaml", champ_de_jargon="x"), capacites=CODE)
cas("clé inconnue refusée, et le fichier est nommé dans le motif",
    "champ_de_jargon" in m and "cle_inconnue.yaml" in m, m)

m = motif_refus(ecrire_plugin(d, "redefinition.yaml", id="bandit"), capacites=CODE,
                fournisseurs={"bandit"})
cas("redéfinir un provider du cœur est refusé", "existe déjà" in m, m)

m = motif_refus(ecrire_plugin(d, "sans_epingle.yaml", binaire="nmap", outillage="nmap"),
                capacites=CODE)
cas("outil non épinglé refusé au chargement, avec le nom du manifeste dans le motif",
    "manifeste_dependances.yaml" in m, m)

m = motif_refus(ecrire_plugin(d, "licence_fausse.yaml", licence="Propriétaire"), capacites=CODE)
cas("licence qui ne correspond pas à celle de l'épingle : refus", "licence" in m.lower(), m)

m = motif_refus(ecrire_plugin(d, "hors_sandbox.yaml",
                              requirements={"sandbox": False, "reseau": False}), capacites=CODE)
cas("`requirements.sandbox: false` refusé — la frontière ne se négocie pas par manifest",
    "isolateur" in m, m)

m = motif_refus(ecrire_plugin(d, "commande_double.yaml",
                              execution={"commande": ["semgrep"], "args": ["-r", "{TARGET}"]}),
                capacites=CODE)
cas("`execution.commande` en désaccord avec `binaire` : refus (deux écritures = deux vérités)",
    "commande" in m, m)

m = motif_refus(ecrire_plugin(d, "version_inapte.yaml", version_min="99.0.0"), capacites=CODE)
cas("`version_min` au-dessus de la version épinglée : refus au chargement, pas au run",
    "version_min" in m, m)

m = motif_refus(ecrire_plugin(d, "capacite_orpheline.yaml", id="chose", capacites=["RESEAU_X"]),
                capacites=CODE)
cas("capacité inconnue sans bloc `capacite:` : refus (sinon le plugin est décoratif)",
    "RESEAU_X" in m and "capacite" in m, m)

m = motif_refus(ecrire_plugin(d, "capacite_muette.yaml", id="muet", capacites=["CODE_METRICS"],
                              capacite={"description": "x", "domaines": ["code"],
                                        "sortie": "findings"}), capacites=CODE)
cas("capacité créée sans `mots_cles` : refus — personne ne pourra la demander",
    "mots_cles" in m, m)

m = motif_refus(ecrire_plugin(d, "paire_inlisible.yaml", sortie={"format": "xml"},
                              lecture={"modele": "plat", "champs": {"regle": "a"}}),
                capacites=CODE)
cas("format xml lu en modèle plat : refus (c'est la paire format↔modèle qui doit être lisible)",
    "xml" in m or "modele" in m, m)

m = motif_refus(ecrire_plugin(d, "custom_sans_parser.yaml", sortie={"format": "custom"},
                              lecture={"modele": "custom"}), capacites=CODE)
cas("`custom` sans `parser` nommé : refus", "parser" in m, m)

m = motif_refus(ecrire_plugin(d, "shell.yaml", execution={"args": ["-c", "curl x | sh"]}),
                capacites=CODE)
cas("fragment de shell dans un argument : refus (seconde barrière, celle du cœur)",
    "|" in m or "shell" in m.lower() or "interdit" in m.lower(), m)

m = motif_refus(ecrire_plugin(d, "deux_nouvelles.yaml", id="deux",
                              capacites=["CAP_UN", "CAP_DEUX"],
                              capacite={"description": "d", "domaines": ["code"],
                                        "sortie": "findings", "mots_cles": ["w"]}),
                capacites=CODE)
cas("un plugin ne crée pas deux capacités à la fois", "une seule capacité" in m, m)

m = motif_refus(ecrire_plugin(d, "sans_risque.yaml", risque=None), capacites=CODE)
cas("`risque` absent : refus — aucun niveau n'est appliqué par défaut à un plugin",
    "risque" in m and "PASSIVE" in m, m)
m = motif_refus(ecrire_plugin(d, "risque_inventoire.yaml", risque="TRES_DANGEREUX"),
                capacites=CODE)
cas("`risque` hors énumération : refus", "EXPLOIT" in m, m)

# les propositions de l'inventaire sont écrites DANS cette grammaire : elles ne peuvent pas
# être refusées pour une raison de syntaxe — seulement pour une mesure absente.
from inventaire_plateforme import construis, rendus_propositions      # noqa: E402
from registre import REGISTRY_PATH as CHEMIN_REGISTRE                 # noqa: E402
_doc = yaml.safe_load(Path(CHEMIN_REGISTRE).read_text(encoding="utf-8")) or {}
_ids = {str(c.get("id")) for c in (_doc.get("capabilities") or [])}
_fourn = {str(p_.get("id")) for c in (_doc.get("capabilities") or [])
          for p_ in (c.get("providers") or [])}
rendus = rendus_propositions(construis())
cas("dix propositions générées, écrites en grammaire de plugin", len(rendus) == 10, sorted(rendus))
grammaire, mesures = [], []
for nom, contenu in sorted(rendus.items()):
    doc = yaml.safe_load(contenu)
    try:
        PL.charger_doc(doc, nom, _ids, _fourn)
        grammaire.append(f"{nom} : accepté sans mesure (inattendu)")
    except PL.PluginError as e:
        motif = str(e)
        (mesures if "clé" not in motif else grammaire).append(f"{nom} : {motif[:90]}")
    except Exception as e:                              # noqa: BLE001
        grammaire.append(f"{nom} : {type(e).__name__}: {e}")
cas("aucune proposition n'est refusée pour sa GRAMMAIRE (clé inconnue, forme illisible)",
    not grammaire, grammaire[:3])
cas("toute proposition est refusée pour une MESURE absente (binaire, risque, mapping)",
    len(mesures) == len(rendus) and all("binaire" in x or "risque" in x or "champs" in x
                                        for x in mesures), mesures[:2])

# le verdict publié dans l'en-tête est recalculé, donc il correspond au chargeur réel
verdicts = []
for nom, contenu in sorted(rendus.items()):
    publie = [l for l in contenu.splitlines() if "verdict du chargeur" in l]
    calcule = PL.verdict(yaml.safe_load(contenu), nom)
    verdicts.append((nom, bool(publie) and publie[0].split(":", 1)[1].strip() == calcule))
cas("l'en-tête de chaque proposition cite le verdict ACTUEL du chargeur (pas une phrase figée)",
    all(ok for _, ok in verdicts), [n for n, ok in verdicts if not ok])
# et le chemin inverse : un plugin du dépôt, lu comme une proposition, se dit chargeable
try:
    import plugins as PL2
    charge = PL2.verdict(yaml.safe_load((RACINE / "plugins" / "radon.yaml").read_text(encoding="utf-8")),
                         "radon.yaml")
except Exception as e:                                  # noqa: BLE001
    charge = f"!!! {type(e).__name__}: {e}"
cas("le même contrôle, appliqué au plugin livré, dit « chargerait » (le diagnostic ne diverge "
    "pas du chargement)", charge.startswith("chargerait"), charge)

# un plugin correct se charge, et son provider est lisible par les fonctions du cœur
c = ecrire_plugin(d, "correct.yaml")
try:
    prov_t, cap_t, visees = PL.charger_un(c, set(CODE), set())
    ok = (prov_t["id"] == "outil_test" and visees == CODE and cap_t is None
          and prov_t["args_obligatoires"] == ["-r", "{TARGET}"])
    detail = f"{prov_t['id']} · args={prov_t.get('args_obligatoires')}"
except Exception as e:                                  # noqa: BLE001
    ok, detail = False, f"{type(e).__name__}: {e}"
cas("plugin valide accepté : le provider porte la commande, les args et le manifest", ok, detail)

# ═════════════════════════════ 3 · ce que le registre devient
print("═══ 3 · registre augmenté ═══")
reg = REG.Registry()
coeur = yaml.safe_load((RACINE / "slice" / "capabilities.yaml").read_text(encoding="utf-8"))
cas("aucune capacité n'a été écrite à la main dans le registre du cœur pour un plugin",
    len(coeur.get("capabilities") or []) == 7, len(coeur.get("capabilities") or []))
creees = sorted({c["capacite_creee"] for c in vue["charges"] if c["capacite_creee"]})
cas("le registre en service = les 7 capacités du cœur + celles que les plugins créent réellement",
    len(reg.capabilities()) == 7 + len(creees)
    and set(creees) <= {c.id for c in reg.capabilities()},
    f"cœur 7 + {creees} = {len(reg.capabilities())}")
capm = reg.capability("CODE_METRICS")
cas("la capacité créée porte le vocabulaire déclaré dans le plugin",
    "cyclomatique" in capm.mots_cles, capm.mots_cles[:4])
cas("une capacité de plugin ne rejoint PAS la suite générique par défaut",
    capm.generique is False, capm.generique)
cas("les capacités du cœur gardent generique=true (le comportement par défaut n'est pas inversé)",
    all(c.generique for c in reg.capabilities() if c.id not in set(creees)),
    [c.id for c in reg.capabilities() if not c.generique])
deps = reg.capability("DEPENDENCY_ANALYSIS")
ids = [p.id for p in deps.providers]
cas("le provider de plugin est ajouté EN FIN de liste (l'ordre d'arbitrage du cœur ne bouge pas)",
    ids[:2] == ["trivy", "grype"] and ids[-1] == "pip_audit", ids)
choix = IN.choisir_providers(IN.inferer("Analyse la sécurité de mon dépôt", reg), reg)
cas("à demande générique, le plugin à priorité basse ne déplace aucune sélection existante",
    "pip_audit" not in choix, choix)

empreintes = {}
VIDE = ATELIER / "vide"
VIDE.mkdir(exist_ok=True)
for nom, dossier in (("sans_plugin", VIDE), ("avec_plugin", RACINE / "plugins")):
    code = (f"import sys; sys.path.insert(0, {str(RACINE / 'slice')!r}); "
            "import registre as R; print(R.Registry().empreinte())")
    env = dict(os.environ)
    env["AGNT_PLUGINS"] = str(dossier)
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                         text=True, timeout=180)
    empreintes[nom] = out.stdout.strip()
cas("l'empreinte change quand un plugin est chargé : un plan prouve CONTRE QUEL JEU il a été "
    "autorisé", empreintes["sans_plugin"] and empreintes["sans_plugin"] != empreintes["avec_plugin"],
    empreintes)
cas("l'empreinte utilisée par le produit est bien celle calculée avec les plugins du dépôt",
    reg.empreinte() == empreintes["avec_plugin"],
    f"{reg.empreinte()} vs {empreintes['avec_plugin']}")
reprise = subprocess.run([sys.executable, "-c", code], env=dict(os.environ, AGNT_PLUGINS=str(VIDE)),
                         capture_output=True, text=True, timeout=180).stdout.strip()
cas("la même configuration se recalcule à l'identique (déterminisme, pas d'horodatage)",
    bool(reprise) and reprise == empreintes["sans_plugin"],
    f"{reprise} vs {empreintes['sans_plugin']}")

base = IN.inferer("Analyse la sécurité de mon dépôt", reg)
cas("la sélection d'une demande du cœur est strictement inchangée par la présence des plugins",
    base.capabilities == ("CODE_STATIC_ANALYSIS", "CODE_STATIC_ANALYSIS_GO", "DEPENDENCY_ANALYSIS",
                          "SECRET_DETECTION", "IAC_SCAN"), base.capabilities)
demande_plugin = IN.inferer("Évalue la complexité cyclomatique de ce dépôt", reg)
cas("la capacité du plugin est atteignable par les mots qu'il déclare",
    "CODE_METRICS" in demande_plugin.capabilities, demande_plugin.capabilities)

n_avant = len(PL.fichiers())
brouillon = RACINE / "plugins" / "propositions" / "zz_faux_plugin.yaml"
sous = RACINE / "plugins" / "sous-dossier-test"
try:
    brouillon.write_text("id: pas_un_plugin\ncapacites: [X]\n", encoding="utf-8")
    sous.mkdir(exist_ok=True)
    (sous / "radon.yaml").write_text("id: x\n", encoding="utf-8")
    noms = [f.name for f in PL.fichiers()]
    cas("une brouillon correct dans `propositions/` n'est jamais chargé, et un sous-répertoire "
        "n'est pas récursif", len(noms) == n_avant and "zz_faux_plugin.yaml" not in noms, noms)
finally:
    brouillon.unlink(missing_ok=True)
    shutil.rmtree(sous, ignore_errors=True)

# ═════════════════════════════ 4 · lire les formats, sur des octets
print("═══ 4 · modèles de lecture ═══")
bandit_bin = shutil.which("bandit") or str(Path.home() / ".cache/arena_secops/bin/bandit")
brut_csv = ""
if Path(bandit_bin).exists():
    r = subprocess.run([bandit_bin, "-r", "-f", "csv", str(RACINE / "testrepo")],
                       capture_output=True, text=True, timeout=300)
    brut_csv = r.stdout or ""
lignes = [x for x in brut_csv.splitlines() if x.strip()]
cas("bandit -f csv : l'outil est présent et a rendu quelque chose (mesure réelle, pas fixture)",
    len(lignes) >= 2, f"{len(lignes)} lignes depuis {bandit_bin}")
colonnes = [c.strip() for c in (lignes[0].split(",") if lignes else [])]
# Les candidats sont des noms de colonnes DOCUMENTÉS par bandit ; le mapping ne retient que ce
# que l'entête rend réellement. Si l'outil change ses colonnes, ce cas échoue — c'est le but.
mapping = {}
for alias, candidats in (("fichier", ("filename", "Location")),
                         ("regle", ("test_id", "Test ID")),
                         ("severite", ("issue_severity", "Severity")),
                         ("ligne", ("line_number", "Line Range")),
                         ("message", ("issue_text", "Description"))):
    for cand in candidats:
        if cand in colonnes:
            mapping[alias] = cand
            break
ex_csv = PM.Extraction(modele="csv", champs=mapping)
it = EX.extraire(brut_csv, ex_csv) if mapping else []
cas("modèle csv : mapping lu sur l'ENTÊTE RÉELLE de l'outil, jamais supposé",
    len(mapping) == 5 and len(it) == len(lignes) - 1,
    f"colonnes={colonnes} · mapping={mapping} · {len(it)} items")
proj = [EX.champs(x, ex_csv) for x in it]
cas("modèle csv : chaque item projeté remplit fichier, règle, ligne, sévérité et message",
    len(proj) >= 1 and all(all(str(v or "").strip() for v in f.values()) for f in proj),
    json.dumps(proj[:1], ensure_ascii=False))
entete_espace = '" id "," message "\n 42 , secret \n'
ex_esp = PM.Extraction(modele="csv", champs={"regle": "id", "message": "message"})
it_esp = EX.extraire(entete_espace, ex_esp)
cas("modèle csv : une entête espacée ne rend pas tous les champs à None (défaut trouvé le "
    "30/08/2026 — `skipinitialspace`)",
    bool(it_esp) and EX.champs(it_esp[0], ex_esp) == {"regle": "42", "message": "secret"},
    it_esp)
semis = PM.Extraction(modele="csv", separateur=";", champs={"regle": "id", "message": "msg"})
it_semi = EX.extraire("id;msg\na;b\n", semis)
cas("modèle csv : le séparateur DÉCLARÉ est respecté, jamais deviné",
    bool(it_semi) and EX.champs(it_semi[0], semis) == {"regle": "a", "message": "b"}, it_semi)
sale = '{"regle": "R1"}\n\npas du json {{{\n{"regle": "R2"}\n'
cas("modèle lignes_json : une ligne illisible est ignorée, la mission continue",
    [i.get("regle") for i in EX.extraire(sale, PM.Extraction(modele="lignes_json"))]
    == ["R1", "R2"], EX.extraire(sale, PM.Extraction(modele="lignes_json")))
xml_brut = ('<nmaprun><host><status state="up"/>'
            '<address addr="127.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>'
            '</host></nmaprun>')
ex_xml = PM.Extraction(modele="xml", nested_from="host", nested_key="port",
                       contexte={"hote": "address@addr"},
                       champs={"port": "@portid", "etat": "state@state", "cible": "hote"})
lu = EX.extraire(xml_brut, ex_xml)
cas("modèle xml : attributs (`@`), `balise@attr`, contexte du conteneur (forme de `nmap -oX`)"
    " — les alias de contexte restent aussi lisibles dans l'item",
    [ {k: x.get(k) for k in ("port", "etat", "cible")} for x in lu ]
    == [{"port": "22", "etat": "open", "cible": "127.0.0.1"}] and lu[0]["hote"] == "127.0.0.1",
    lu)
cas("modèle xml : document illisible → liste vide, pas d'exception qui fait tomber la mission",
    EX.extraire("<a><b>", PM.Extraction(modele="xml", nested_from="a")) == [], "")
radon_doc = json.loads('{"app.py": [{"name": "gros", "rank": "F", "lineno": 12,'
                       ' "complexity": 44, "type": "function"}]}')
ex_radon = PM.Extraction(modele="imbriqué", nested_from="$", nested_key="*",
                         contexte={"fichier": "*"},
                         champs={"regle": "rank", "nom_regle": "type", "fichier": "fichier",
                                 "ligne": "lineno", "message": "name"})
it = EX.extraire(radon_doc, ex_radon)
cas('modèle imbriqué `nested_key: "*"` : la CLÉ du conteneur devient un champ (défaut trouvé '
    'en lisant la sortie réelle de radon)',
    bool(it) and it[0]["fichier"] == "app.py", it)
cas("projection `champs` sur cet item : regle/nom_regle/ligne remplis par les chemins déclarés",
    EX.champs(it[0], ex_radon) == {"regle": "F", "nom_regle": "function", "fichier": "app.py",
                                  "ligne": 12, "message": "gros"}, EX.champs(it[0], ex_radon))

# ═════════════════════════════ 5 · l'outil tourne, par le chemin du produit
print("═══ 5 · exécution réelle du provider de plugin ═══")
prov = reg.provider("radon_cc")
cas("le provider vient du plugin : sa limite cite le fichier qui l'a déclaré",
    prov is not None and "radon.yaml" in (prov.manifest.limite or ""),
    (prov.manifest.limite or "")[:150])
cas("l'épingle est citée dans la limite (version + licence lues depuis le manifeste)",
    "6.0.1" in prov.manifest.limite and "MIT" in prov.manifest.limite, prov.manifest.limite[-160:])
cas("les args obligatoires sont transmis au programme (sans eux : outil lancé sans cible)",
    list(prov.args_obligatoires[:4]) == ["cc", "--json", "--min", "D"], prov.args_obligatoires)
cas("le nom du programme est `binaire`, une seule fois",
    list(prov.commande) == ["radon"], prov.commande)

sbx, res = lance_reel(prov, RACINE)
cas("l'argv exécuté pointe sur l'exécutable résolu et sur la cible du scan",
    sbx.argv[0].endswith("/radon") and sbx.argv[-1] == str(RACINE.resolve())
    and "--min" in sbx.argv, sbx.argv)
cas("l'outil a rendu du JSON exploitable, code 0",
    res.code_retour == 0 and isinstance(res.donnees, dict) and res.donnees,
    f"code={res.code_retour} · {str(res.stderr)[:150]}")
items = EX.extraire(res.donnees, prov.manifest.extraction)
blocs = sum(len(v) for v in (res.donnees or {}).values() if isinstance(v, list))
cas("autant d'items que de blocs rendus par l'outil (le cœur ne perd ni n'invente)",
    len(items) == blocs and blocs > 0, f"{len(items)} items · {blocs} blocs")
norm = F.normaliser(prov.id, res.donnees, mani=prov.manifest, racines=(str(sbx.M_SCAN),))
cas("des findings sortent d'un outil que le cœur ne connaît pas",
    len(norm) > 0, f"{len(norm)} findings")
if norm:
    un = norm[0] if isinstance(norm[0], dict) else vars(norm[0])
    loc, src = un.get("location") or {}, un.get("source") or {}
    cas("le finding porte fichier et ligne issus de l'outil (jamais devinés)",
        bool(loc.get("file")) and bool(loc.get("line")), json.dumps(un, ensure_ascii=False)[:200])
    cas("la capacité du finding est celle CRÉÉE par le plugin",
        src.get("capability") == "CODE_METRICS", src.get("capability"))
    cas("l'identité de règle est construite depuis le provider (traçable, pas inventée)",
        str(src.get("canonical_rule_id") or "").startswith("radon_cc:"), src.get("canonical_rule_id"))
    sev = ((un.get("severity") or {}).get("value") if isinstance(un.get("severity"), dict)
           else un.get("severity")) or ""
    cas("aucune sévérité n'est inventée là où l'outil ne classe pas",
        str(sev).upper() in ("", "UNKNOWN"), f"severity={sev!r}")
else:
    cas("aucune sévérité n'est inventée (0 finding rendu)", True, "0 finding")

nom_brut = A.conserver_brut(sbx, sbx.dossier, res, "radon_cc")
cas("le brut de l'outil est conservé dans le dossier sous un nom qui le dit",
    bool(nom_brut) and nom_brut.startswith("brut_radon_cc"), nom_brut)
if nom_brut:
    copie = (sbx.dossier / nom_brut).read_text(encoding="utf-8")
    cas("les octets conservés sont CE QUE L'OUTIL A RENDU (stdout, pas la re-construction du cœur)",
        copie.strip() == (res.texte_brut or "").strip() and copie.strip() != "",
        f"{len(copie)} octets")
cas("un provider qui n'a rien rendu ne produit pas de brut fantôme",
    A.conserver_brut(sbx, sbx.dossier, types.SimpleNamespace(
        fichier="", donnees=None, code_retour=1, texte_brut=""), "radon_cc") is None, "")
cas("extension déduite du format DÉCLARÉ (jsonl/sarif/csv/xml), pas d'une inspection du contenu",
    A.extension_de("jsonl") == "jsonl" and A.extension_de("sarif") == "json"
    and A.extension_de("xml") == "xml", "")
try:
    A.extension_de("yaml")
    cas("format inconnu côté cœur : refus explicite, pas de `.json` par défaut", False, "aucun refus")
except A.ManifestRefus as e:
    cas("format inconnu côté cœur : refus explicite, pas de `.json` par défaut", True, str(e))
except Exception as e:                                  # noqa: BLE001
    cas("format inconnu côté cœur : refus de type ManifestRefus", False, f"{type(e).__name__}: {e}")

# ═════════════════════════════ 6 · conditions : l'outil réseau est refusé, lisiblement
print("═══ 6 · conditions — un plugin ne s'auto-autorise pas à sortir ═══")
pa = reg.provider("pip_audit")
sans_egress = COND.manquantes(pa, egress=False, racine_db=None)
avec_egress = COND.manquantes(pa, egress=True, racine_db=None)
def sans_accent(s):
    import unicodedata
    return "".join(c for c in unicodedata.normalize("NFD", str(s))
                   if unicodedata.category(c) != "Mn").lower()


cas("pip-audit est refusé tant que l'export n'est pas autorisé, et la raison est une phrase",
    bool(sans_egress) and any(("reseau" in sans_accent(x) or "egress" in sans_accent(x))
                              for x in sans_egress) and len(sans_egress[0]) > 40, sans_egress)
cas("le même provider devient exécutable dès que l'export est accordé : la déclaration suffisait",
    not any("reseau" in sans_accent(x) for x in avec_egress),
    avec_egress)
cas("radon n'est jamais retenu pour son réseau (reseau: false lu, pas deviné)",
    not any("reseau" in sans_accent(x) for x in COND.manquantes(prov, egress=False,
                                                                racine_db=None)),
    COND.manquantes(prov, egress=False, racine_db=None))
cas("aucune condition résiduelle quand l'export est accordé (le plugin ne demande rien d'autre)",
    avec_egress == [], avec_egress)
# `fichiers_requis` passe par l'applicabilité du cœur (`applicable_globs`), PAS par
# `base_fichiers` — qui désigne une base côté machine. La confusion a été trouvée en déclarant
# pip-audit : elle faisait refuser le provider pour une raison qui n'existe pas.
import plan as PLN
for pid, cible, attendu in (("pip_audit", RACINE / "testrepo", True),
                            ("pip_audit", RACINE / "testrepo_iac", False),
                            ("radon_cc", RACINE / "testrepo", True)):
    elig, exclus = PLN.filtrer_applicabilite([pid], reg, cible)
    cas(f"applicabilité déclarée : {pid} {'reste' if attendu else 'est écarté'} sur "
        f"{cible.name} (glob lu, pas deviné)", (pid in elig) is attendu,
        {"eligibles": elig, "exclus": list(exclus)})
cas("le timeout déclaré par un plugin ne peut qu'ABAISSER le plafond du cœur",
    COND.timeout_effectif(pa, 1800)[0] <= 900 and COND.timeout_effectif(prov, 1800)[0] <= 600,
    (COND.timeout_effectif(pa, 1800), COND.timeout_effectif(prov, 1800)))
cas("un plugin qui demanderait 10 jours hérite du plafond, pas de son chiffre",
    COND.timeout_effectif(reg.provider("radon_cc"), 30)[0] <= 30, COND.timeout_effectif(prov, 30))

# ═════════════════════════════ 7 · les touches réelles du LOT 2
print("═══ 7 · ce que le lot a touché, et seulement ça ═══")
# Défaut TROUVÉ dans cette section et corrigé ici (31/08/2026) : les trois cas ci-dessous
# lisaient `git status --porcelain`. Ils n'étaient donc vrais QUE tant que le lot restait
# non commité — le commit de LOT 2 les a fait passer en échec sans que rien ne soit cassé.
# Un test qui rougit au moment où l'on committe est un test qui finit par être supprimé, et
# c'est exactement comment une promesse d'extension meurt. Les promesses sont réécrites sur
# leurs faits propres :
#   · « le cœur a été touché » → l'ensemble des fichiers modifiés DEPUIS LE POINT DE
#     BRANCHEMENT (`git merge-base HEAD main`), commits inclus — c'est la définition de
#     « ce que le lot a touché », et elle ne dépend pas du moment où l'on appuie sur commit ;
#   · « aucun parser écrit à la main » → le CONTENU des parsers du slice : aucun ne doit
#     connaître radon ni pip-audit ;
#   · « aucune capacité ajoutée à la main » → le CONTENU de capabilities.yaml : sept
#     capacités, et ni CODE_METRICS ni radon n'y figurent.
# Si le point de branchement est introuvable et l'arbre propre, RIEN n'est mesuré : le cas est
# déclaré en échec avec sa cause, jamais passé par défaut.
GIT = ["git", "-C", str(RACINE.parent)]


def _git(*args: str) -> str:
    return subprocess.run(GIT + list(args), capture_output=True, text=True).stdout


BASE = _git("merge-base", "HEAD", "main").strip() or None
sur_base = _git("diff", "--name-only", f"{BASE}...HEAD").split() if BASE else []
# `--porcelain` se lit LIGNE par ligne : les deux premiers caractères sont l'état, le reste
# est le chemin. Découper la sortie sur les blancs — ce que faisait le LOT 2 — ajoutait "M"
# et "??" à l'ensemble des chemins, et un cas « rien hors de PHASE3 » échouait sur une lettre
# de statut (mesuré le 31/08/2026, en réécrivant cette section).
sur_arbre = [l[3:].strip() for l in _git("status", "--porcelain").splitlines() if l.strip()]
TOUCHES = sorted({x for x in sur_base + sur_arbre})
NOMS = {Path(x).name for x in TOUCHES}
MESURE = bool(BASE) or bool(sur_arbre)
HORS_PHASE3 = [x for x in TOUCHES if not x.startswith("PHASE3/")]
DOCS_RACINE = {"README_USAGE.md", "PROJET_ETAT.md", "CONTEXTE_PROJET.md",
               "PATCHES_A_PORTER.md", ".gitattributes"}
for attend in ("plugins.py", "registre.py", "intent.py", "adapters.py", "extraction.py",
               "provider_manifest.py", "pipeline.py", "analyser.py"):
    cas(f"{attend} porte le changement (et le diff reste borné)",
        MESURE and attend in NOMS,
        "aucune base de comparaison (merge-base HEAD main introuvable et arbre propre) : "
        "rien n'est mesuré" if not MESURE else NOMS and sorted(NOMS)[:16])
cas("le lot ne touche rien hors de PHASE3, sauf les docs de la racine",
    MESURE and set(HORS_PHASE3) <= DOCS_RACINE, HORS_PHASE3)
PARSERS = sorted(x for x in (RACINE / "slice").glob("parsers_*.py"))
conrus = [f_.name for f_ in PARSERS
          if any(m in f_.read_text(encoding="utf-8") for m in ("radon", "pip_audit", "pip-audit"))]
cas("aucun parsers_*.py n'a été écrit pour intégrer les deux outils",
    not conrus and bool(PARSERS),
    {"parsers_existant": len(PARSERS), "connaissent_les_deux_outils": conrus})
cas("aucune capacité n'a été ajoutée à la main dans capabilities.yaml",
    "CODE_METRICS" not in (RACINE / "slice" / "capabilities.yaml").read_text(encoding="utf-8")
    and "radon" not in (RACINE / "slice" / "capabilities.yaml").read_text(encoding="utf-8").lower(),
    sorted(NOMS)[:16])
cas("capabilities.yaml déclare toujours ses sept capacités (rien n'y a été greffé)",
    (RACINE / "slice" / "capabilities.yaml").read_text(encoding="utf-8").count("\n  - id: ") == 7,
    (RACINE / "slice" / "capabilities.yaml").read_text(encoding="utf-8").count("\n  - id: "))
cas("le dossier chargé est exactement `plugins/*.yaml` — `propositions/` n'y est jamais",
    set(PL.fichiers()) == set((RACINE / "plugins").glob("*.yaml"))
    and not any("propositions" in str(f) for f in PL.fichiers()),
    sorted(f.name for f in PL.fichiers()))

# ═════════════════════════════ 7bis · ce que la console d'opération en dit
print("═══ 7bis · l'interface voit l'extension ═══")
sys.path.insert(0, str(RACINE / "interface"))
try:
    import api as API                                    # noqa: E402
    payload = API._capacites()
except Exception as e:                                  # noqa: BLE001
    payload, API = {"registre_erreur": f"{type(e).__name__}: {e}"}, None
cas("/api/capacites propose la capacité créée par le plugin (le menu se lit dans le registre)",
    any(c["id"] == "CODE_METRICS" for c in payload.get("capacites") or []),
    payload.get("registre_erreur") or [c["id"] for c in payload.get("capacites") or []])
cas("/api/capacites cite les providers des plugins parmi ceux des capacités publiées",
    {"radon_cc", "pip_audit"} <= set(payload.get("providers") or []), payload.get("providers"))
pla = payload.get("plugins") or {}
cas("/api/capacites dit QUELS fichiers de plugin sont chargés (l'opérateur doit pouvoir "
    "distinguer la plateforme de cette machine)",
    sorted(pla.get("fichiers") or []) == sorted(f.name for f in PL.fichiers())
    and len(pla.get("empreinte") or "") == 12, pla)

print("═══ 8 · ce qui reste à démontrer ailleurs ═══")
non_evalue("exécution sous bubblewrap du provider radon_cc",
           "bwrap refuse de créer les user namespaces sur cette machine "
           "(kernel.apparmor_restrict_unprivileged_userns) : `SablageReel` lance la commande "
           "sans montages. `test_bwrap.sh` (77 cas) couvre l'isolateur pour tout outil confondu, "
           "et un plugin n'a aucun pouvoir dessus — `sandbox: false` est refusé au chargement "
           "(cas 2).")
non_evalue("décision OPA sur les providers de plugin",
           "binaire opa introuvable : openpolicyagent.org répond 000 et release-assets."
           "githubusercontent.com échoue en TLS (mesuré le 30/08/2026, même cause qui empêche "
           "d'installer nmap/tfsec). `analyser.py` refuse donc la mission complète avec "
           "`PolicyError` AVANT d'en arriver aux conditions ; le chemin intégral d'une mission "
           "radon (plan → décision → exécution → rapport → ledger) est attendu sur une machine "
           "où bootstrap.sh a pu télécharger opa. Le refus observé est lisible et nomme la cause.")
non_evalue("modèles lignes_json et xml sur des octets d'outil réels",
           "aucun outil installable ici ne les rend : nmap/nikto/ffuf passent par des releases "
           "GitHub injoignables, et `pip-audit -f csv` n'existe pas dans 2.10.1 (mesuré : "
           "invalid OutputFormatChoice value: 'csv' — la documentation externe qui le promet est "
           "fausse pour cette version). Les modèles sont exercés sur leur forme documentée (cas 4) ; "
           "le jour où nmap est présent, le plugin se borne à déclarer `format: xml`.")
non_evalue("rendu navigateur des findings d'un plugin",
           "`interface/_domtest.mjs` tourne sur des artefacts figés du cœur. Un finding sans "
           "sévérité (radon rend un rang, pas une sévérité) doit rester lisible à l'écran : à "
           "vérifier sur une mission jouée avec opa, puis à épingler dans le harnais DOM.")
# La vue dérivée ne doit pas devenir un second endroit où l'on écrit ce que le registre est.
pool = (RACINE / "pool.yaml").read_text(encoding="utf-8")
import re as _re
cas("pool.yaml ne pinne aucune empreinte de registre (la vue suit le registre, elle ne le "
    "précède pas)", not [m for m in _re.findall(r"\b[0-9a-f]{12}\b", pool)
                         if m != reg.empreinte()[:12]] or reg.empreinte()[:12] in pool,
    _re.findall(r"\b[0-9a-f]{12}\b", pool)[:4])

# ══════════════════════════════════════════════════════════════════════════ bilan
nb = len(CAS)
ok = sum(1 for _, c, _ in CAS if c)
print(f"\n{ok}/{nb} attendus vérifiés")
for nom, cond, detail in CAS:
    if not cond:
        print(f"  ÉCHEC · {nom}\n        {detail}")
for nom, raison in NON_EVALUE:
    print(f"  NON ÉVALUÉ · {nom} — {raison}")
shutil.rmtree(ATELIER, ignore_errors=True)
sys.exit(1 if ECHECS else 0)
