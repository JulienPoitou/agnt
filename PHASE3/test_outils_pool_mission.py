#!/usr/bin/env python3
"""
Batterie « étape 2 » — objet Tool, pool dérivé, mission minimale (2026-08-29).

Invariants vérifiés (architecture gelée) :
- TOOL : version/sha/licence conservés ; binaire ⊆ whitelist ; un tool partagé
  par plusieurs providers n'a qu'UNE entrée d'installation ; tool_id inconnu ou
  incohérent = manifest refusé au chargement ; compatibilité ascendante (manifest
  sans tool_id reste valide).
- POOL : vue DÉRIVÉE (jamais source de vérité runtime) ; régénération
  déterministe ; cohérence à sens unique (tout provider intégré figure au pool) ;
  le runtime IGNORE le pool (aucune lecture,篡改 sans effet).
- MISSION : dossier append-only (préfixe du journal jamais réécrit, seq
  consécutif) ; digest cible + empreintes de contexte présents ; le pipeline
  journalise ouverture → contexte → plan → exécutions → clôture.

Usage: python3 PHASE3/test_outils_pool_mission.py
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

CAS = []
ECHECS = []


def cas(nom: str, cond: bool, detail: str = ""):
    CAS.append((nom, cond, detail))
    if not cond:
        ECHECS.append(nom)


def main() -> int:
    import outils
    import provider_manifest as PM
    from registre import Registry

    # ------------------------------------------------------------ 1. objet Tool
    regs = outils.registre()
    cas("1a. registre des tools chargé depuis manifeste_dependances.yaml",
        {"trivy", "gitleaks", "opa", "bandit", "checkov", "semgrep"} <= set(regs),
        f"tools={sorted(regs)}")
    cas("1b. chaque tool porte version, source ET licence",
        all(t.version and t.source and t.licence for t in regs.values()),
        str({k: (t.version, bool(t.licence)) for k, t in regs.items()}))
    binaire_tools = [t for t in regs.values() if t.installation == "binaire"]
    pip_tools = [t for t in regs.values() if t.installation == "pip"]
    cas("1c. tools binaires = sha256 ; tools pip = hash distribution (honnête)",
        all(t.sha256 for t in binaire_tools)
        and all(t.distribution_hash or t.note for t in pip_tools)
        and len(binaire_tools) + len(pip_tools) == len(regs),
        f"binaires={[t.id for t in binaire_tools]} pip={[t.id for t in pip_tools]}")
    cas("1d. tout tool de rôle 'outil' a son binaire dans la whitelist",
        all(t.id in PM.BINAIRES_AUTORISES for t in regs.values() if t.role == "outil")
        and any(t.role == "moteur" for t in regs.values()),
        f"whitelist={PM.BINAIRES_AUTORISES}")

    r = Registry()
    tool_par_provider = {}
    for p in r.providers():
        if p.manifest is not None:
            tool_par_provider[p.id] = p.manifest.tool_id
    cas("1e. providers à manifest référencent un tool_id connu",
        all(t in regs for t in tool_par_provider.values())
        and all(tool_par_provider.values()),
        f"{tool_par_provider}")
    cas("1f. un tool partagé = UNE installation (bandit×2, semgrep×2)",
        tool_par_provider.get("bandit") == tool_par_provider.get("bandit_custom") == "bandit"
        and tool_par_provider.get("semgrep_go") == "semgrep"
        and sum(1 for t in regs if t == "bandit") == 1,
        f"{tool_par_provider}")

    # 2. validation des tool_id au chargement
    doc_base = None
    doc_yaml = yaml.safe_load((RACINE / "slice" / "capabilities.yaml").read_text(encoding="utf-8"))
    for c in doc_yaml["capabilities"]:
        for p in c["providers"]:
            if p.get("id") == "checkov":
                doc_base = p["manifest"]
    import copy
    mauvais_tool = copy.deepcopy(doc_base)
    mauvais_tool["tool_id"] = "inconnu"
    try:
        PM.valider(mauvais_tool, "IAC_SCAN")
        cas("2a. tool_id inconnu refusé", False, "accepté")
    except PM.ManifestError as e:
        cas("2a. tool_id inconnu refusé", "tool_id" in str(e), str(e)[:70])
    incoherent = copy.deepcopy(doc_base)
    incoherent["tool_id"] = "trivy"   # ≠ binaire checkov
    try:
        PM.valider(incoherent, "IAC_SCAN")
        cas("2b. tool_id ≠ binaire refusé", False, "accepté")
    except PM.ManifestError as e:
        cas("2b. tool_id ≠ binaire refusé", "binaire" in str(e), str(e)[:70])
    sans_tool = copy.deepcopy(doc_base)
    sans_tool.pop("tool_id", None)
    try:
        PM.valider(sans_tool, "IAC_SCAN")
        ok = True
    except PM.ManifestError as e:
        ok = False
    cas("2c. compatibilité ascendante : manifest SANS tool_id reste valide", ok)

    # ------------------------------------------------------------ 3. pool dérivé
    pool_path = RACINE / "pool.yaml"
    if not pool_path.is_file():
        cas("3a. pool.yaml existe", False, "manquant — lancer genere_pool.py")
        return _fin()
    pool_txt = pool_path.read_text(encoding="utf-8")
    pool = yaml.safe_load(pool_txt)
    cas("3a. pool.yaml existe et se déclare VUE DÉRIVÉE",
        "VUE DÉRIVÉE" in pool_txt and "ne jamais éditer" in pool_txt.lower())
    avant = pool_txt
    subprocess.run([sys.executable, str(RACINE / "genere_pool.py")],
                   capture_output=True, check=True)
    cas("3b. régénération déterministe (octet pour octet)",
        pool_path.read_text(encoding="utf-8") == avant)

    entrees = {e["source"]: e for e in pool["entrees"]}
    integres_attendus = {"aquasecurity/trivy", "semgrep/semgrep", "gitleaks/gitleaks",
                         "PyCQA/bandit", "bridgecrewio/checkov", "open-policy-agent/opa"}
    trouves = {s for s, e in entrees.items()
               if e["statut_operationnel"] == "integrated"}
    cas("3c. cohérence à sens UNIQUE : tout provider intégré figure au pool",
        integres_attendus <= trouves,
        f"manquants={integres_attendus - trouves}")
    provs_pool = {p for e in entrees.values() for p in e.get("providers") or []}
    manquants_prov = {p.id for p in r.providers()} - provs_pool
    cas("3d. chaque provider du registre est rattaché à son tool au pool",
        not manquants_prov, f"manquants={sorted(manquants_prov)}")
    # Le runtime ignore le pool : aucune référence dans le cœur + falsification
    refs = subprocess.run(
        f"grep -l 'pool' {RACINE}/slice/*.py 2>/dev/null || true",
        shell=True, capture_output=True, text=True).stdout.strip()
    empreinte_avant = Registry().empreinte()
    pool_path.write_text("entrees: []\n# falsifié pour le test\n", encoding="utf-8")
    try:
        empreinte_apres = Registry().empreinte()
    finally:
        pool_path.write_text(avant, encoding="utf-8")
    cas("3e. le runtime IGNORE le pool (aucune lecture ; falsification sans effet)",
        refs == "" and empreinte_avant == empreinte_apres, f"références={refs!r}")
    cas("3f. lignes catalogue sans owner_repo exclues et comptées",
        pool.get("lignes_exclues_sans_owner_repo", 0) == 15,
        f"{pool.get('lignes_exclues_sans_owner_repo')}")

    # ------------------------------------------------------------ 4. mission
    import mission as MS
    import run as RUN
    m = MS.ouvrir("test batterie", "test batterie", RACINE / "testrepo_go")
    entete = json.loads((m.chemin / "mission.json").read_text(encoding="utf-8"))
    cas("4a. ouverture : mission.json + journal, entête complet",
        entete["mission_id"] == m.id and entete["requete"] == "test batterie"
        and entete["cible"]["type"] == "repertoire"
        and (m.chemin / "journal.jsonl").is_file())
    MS.consigner(m, "test", n=1)
    octets_1 = (m.chemin / "journal.jsonl").read_bytes()
    MS.consigner(m, "test", n=2)
    octets_2 = (m.chemin / "journal.jsonl").read_bytes()
    lignes = [json.loads(l) for l in octets_2.decode().splitlines() if l]
    cas("4b. append-only : préfixe jamais réécrit, seq consécutif",
        octets_2.startswith(octets_1) and len(octets_2) > len(octets_1)
        and [l["seq"] for l in lignes] == list(range(1, len(lignes) + 1)))
    m2 = MS.relire(m.id)
    MS.consigner(m2, "reprise")
    lignes2 = MS.journal(m2)
    cas("4c. relecture : l'append continue la séquence",
        lignes2[-1]["type"] == "reprise" and lignes2[-1]["seq"] == len(lignes) + 1)

    # 4d. intégration pipeline (réelle, sur testrepo_go — ~2 min)
    import pipeline
    e = pipeline.executer("Analyse la sécurité de mon dépôt", RACINE / "testrepo_go", cible_autorisee=True)
    types = [l["type"] for l in MS.journal(MS.relire(e.mission))]
    ctx_l = [l for l in MS.journal(MS.relire(e.mission)) if l["type"] == "contexte"]
    digest_attendu = RUN.digest_cible(RACINE / "testrepo_go")[0]
    cas("4d. pipeline : mission journalisée de bout en bout",
        e.mission != ""
        and types[0] == "ouverture" and "contexte" in types and "plan" in types
        and types.count("execution") == len(e.plan["steps"]) and types[-1] == "cloture"
        and ctx_l and ctx_l[0]["input_digest"] == digest_attendu,
        f"mission={e.mission} types={types}")

    return _fin()


def _fin() -> int:
    for nom, ok, detail in CAS:
        print(f"  [{'OK' if ok else 'ECHEC'}] {nom}" + (f"  — {detail}" if detail and not ok else ""))
    print(f"\ntest_outils_pool_mission : {len(CAS) - len(ECHECS)}/{len(CAS)} cas passés")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
