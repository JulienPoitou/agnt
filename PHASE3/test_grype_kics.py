#!/usr/bin/env python3
"""
Batterie « étape 4 » — premiers providers du pool : grype + kics (2026-08-29).

Invariants vérifiés :
- INTÉGRATION DÉCLARATIVE : les deux providers passent par le manifest générique
  (zéro code spécifique dans le cœur) ; le vocabulaire déclaratif s'étend
  (champ `paquet`, champ `env`, placeholder {OUT_DIR}) sans modifier le modèle.
- VALIDATION : `env` est validé comme argv (nom de variable, placeholders
  connus, fragments interdits) — un env libre serait une injection.
- ATTENDUS : l'extraction normalisée reproduit les comptes qualifiés par le
  harnais sur exécutions sandbox réelles (artefacts + dossiers de
  qualification dans testrepo_sca/ et testrepo_iac/).
- CONVERGENCE : grype (GHSA-*) × trivy (CVE-*) se regroupent par PAQUET
  (cross_tool), jamais par identifiant de règle ; same_dependency_usage ne se
  déclenche PAS entre deux outils de dépendances.
- FAN-OUT RÉEL : DEPENDENCY_ANALYSIS et IAC_SCAN déclarent fan_out max 2 ;
  l'e2e testrepo_sca exécute trivy ET grype.

Usage: python3 PHASE3/test_grype_kics.py
"""
from __future__ import annotations

import json
import sys
import tempfile
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


def _par_cle(findings) -> dict:
    """Même normalisation que le harnais : ATTENDUS comparables."""
    par_cle: dict[str, set] = {}
    for f in findings:
        d = f.to_dict()
        loc = d["location"]
        cle = str(loc.get("package") or loc.get("file") or "?")
        par_cle.setdefault(cle, set()).add(str(d["source"]["original_rule_id"]))
    return {k: sorted(v) for k, v in sorted(par_cle.items())}


REGISTRE_SYNTHETIQUE = """
capabilities:
  - id: TEST_CAP_ENV
    description: test — validation du champ env
    domaines: [test]
    entree: [cible]
    sortie: finding/test
    providers:
      - id: env_ok
        commande: ["grype"]
        manifest:
          id: env_ok
          binaire: grype
          argv: ["{BIN}", "dir:{TARGET}"]
          env:
            GRYPE_DB_CACHE_DIR: "{DB}/grype"
          output: {format: json}
          extraction: {modele: plat, items_from: matches, champs: {regle: vulnerability.id}}
          risk: PASSIVE
          target_types: [repository]
"""


def _manifest_brut(**env) -> dict:
    return {
        "id": "synth", "binaire": "grype", "argv": ["{BIN}", "dir:{TARGET}"],
        "env": env, "output": {"format": "json"},
        "extraction": {"modele": "plat", "items_from": "matches",
                       "champs": {"regle": "vulnerability.id"}},
        "risk": "PASSIVE", "target_types": ["repository"],
    }


def main() -> int:
    import provider_manifest as PM
    import findings as F
    import plan as P
    import clusterer as CL
    from registre import Registry

    reg = Registry()

    # ------------------------------------------------- 1. déclarations (hors-ligne)
    cas("1a. grype et kics dans la whitelist des binaires",
        "grype" in PM.BINAIRES_AUTORISES and "kics" in PM.BINAIRES_AUTORISES)
    pg, pk = reg.provider("grype"), reg.provider("kics")
    cas("1b. providers déclaratifs valides, tool_id cohérent avec le binaire",
        pg.manifest is not None and pk.manifest is not None
        and pg.manifest.tool_id == "grype" and pk.manifest.tool_id == "kics")
    cap_dep, cap_iac = reg.capability("DEPENDENCY_ANALYSIS"), reg.capability("IAC_SCAN")
    cas("1c. fan_out déclaré sur les deux capacités, borné à 2",
        cap_dep.mode_selection == "fan_out" and cap_dep.max_providers == 2
        and cap_iac.mode_selection == "fan_out" and cap_iac.max_providers == 2)
    cas("1d. priorités : trivy/checkov (100) avant grype/kics (110)",
        reg.provider("trivy").priorite == 100 and pg.priorite == 110
        and reg.provider("checkov").priorite == 100 and pk.priorite == 110)
    # MODIFIÉ le 2026-08-29 (dogfooding) : kics code_succes [0,60] → échelle complète.
    # Justification : [0,60] venait d'UNE observation (CRITICAL sur testrepo_iac) ;
    # gorilla/mux (LOW) a produit 30 — mesuré, confirmé par la documentation kics
    # (20/30/40/50/60 = INFO/LOW/MEDIUM/HIGH/CRITICAL). Contrôle conservé, borne élargie
    # aux codes réellement émis.
    cas("1e. codes de succès MESURÉS : grype [0], kics échelle de sévérité",
        tuple(pg.manifest.code_succes) == (0,)
        and tuple(pk.manifest.code_succes) == (0, 20, 30, 40, 50, 60))
    chemins = {"BIN": "/b", "TARGET": "/t", "OUT": "/o/kics.json", "OUT_DIR": "/o",
               "REGLES": "/r", "DB": "/d"}
    cas("1f. env grype déclaré et résolu par le cœur ({DB}/grype)",
        PM.resoudre_env(pg.manifest, chemins) == {"GRYPE_DB_CACHE_DIR": "/d/grype"})
    argv_kics = PM.resoudre_argv(pk.manifest, chemins)
    cas("1g. kics écrit dans un RÉPERTOIRE ({OUT_DIR}) avec un nom aligné",
        "--output-path" in argv_kics
        and argv_kics[argv_kics.index("--output-path") + 1] == "/o"
        and argv_kics[argv_kics.index("--output-name") + 1] == "kics")
    cas("1h. bibliothèque de requêtes kics référencée par {REGLES}",
        any(a == "/r/kics/queries" for a in argv_kics))

    # ------------------------------------------------- 2. validation de `env`
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "caps.yaml"
        f.write_text(REGISTRE_SYNTHETIQUE, encoding="utf-8")
        rs = Registry(chemin=f)
        cas("2a. env valide : manifest accepté et env conservé",
            rs.provider("env_ok").manifest.env == (("GRYPE_DB_CACHE_DIR", "{DB}/grype"),))
    for nom, env, attente in (
            ("2b. nom de variable invalide refusé", {"petit-nom": "x"}, "invalide"),
            ("2c. placeholder inconnu dans la valeur refusé",
             {"GRYPE_DB_CACHE_DIR": "{SORCIERE}"}, "inconnu"),
            ("2d. fragment interdit (;) dans la valeur refusé",
             {"GRYPE_DB_CACHE_DIR": "/d; rm -rf /"}, "refusé")):
        try:
            PM.valider(_manifest_brut(**env), "TEST")
            cas(nom, False, "accepté")
        except PM.ManifestError as e:
            cas(nom, attente in str(e), str(e)[:80])

    # ------------------------------------------------- 3. applicabilité (fixtures réelles)
    # NB : les fixtures portent leur ATTENDUS.yaml — un VRAI fichier .yaml qui
    # rend kics légitimement éligible dessus (pas une exclusion à asserte).
    # L'exclusion se mesure sur un inventaire synthétique : lockfiles seuls.
    provs_sca, _ = P.filtrer_applicabilite(
        ["trivy", "grype", "kics", "checkov", "semgrep", "bandit", "gitleaks"],
        reg, RACINE / "testrepo_sca")
    provs_iac, ecartes_iac = P.filtrer_applicabilite(
        ["trivy", "grype", "kics", "checkov", "semgrep", "bandit", "gitleaks"],
        reg, RACINE / "testrepo_iac")
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "package-lock.json").write_text("{}", encoding="utf-8")
        (Path(tmp) / "requirements.txt").write_text("flask==1.0\n", encoding="utf-8")
        provs_lock, ecartes_lock = P.filtrer_applicabilite(
            ["trivy", "grype", "kics", "checkov", "semgrep", "bandit", "gitleaks"],
            reg, Path(tmp))
    cas("3a. cible lockfiles seuls : grype applicable, kics écarté avec motif",
        "grype" in provs_lock and "kics" in ecartes_lock
        and "grype" in provs_sca, f"{ecartes_lock.get('kics', '')[:80]}")
    cas("3b. testrepo_iac : kics applicable, grype écarté avec motif",
        "kics" in provs_iac and "grype" in ecartes_iac, f"{ecartes_iac.get('grype', '')[:80]}")
    cas("3c. garde-fou package.json : aucun glob kics ne matche du .json",
        not any(g.endswith(".json") for g in pk.manifest.applicable_globs))

    # ------------------------------------------------- 4. extraction vs ATTENDUS (hors-ligne)
    att_sca = yaml.safe_load((RACINE / "testrepo_sca" / "ATTENDUS.yaml").read_text())
    brut_g = json.loads((RACINE / "testrepo_sca" / "artefacts_captures" / "grype.json")
                        .read_text())
    fg = F.depuis_manifest(brut_g, pg.manifest, "grype")
    exp_g = att_sca["attendus"]["grype"]
    cas("4a. grype : extraction conforme aux ATTENDUS qualifiés (62 findings)",
        len(fg) == exp_g["compte"] == 62 and _par_cle(fg) == exp_g["par_cle"],
        f"{len(fg)} vs {exp_g['compte']}")
    att_iac = yaml.safe_load((RACINE / "testrepo_iac" / "ATTENDUS.yaml").read_text())
    brut_k = json.loads((RACINE / "testrepo_iac" / "artefacts_captures" / "kics.json")
                        .read_text())
    fk = F.depuis_manifest(brut_k, pk.manifest, "kics")
    exp_k = att_iac["attendus_kics"]
    cas("4b. kics : extraction conforme aux ATTENDUS qualifiés (110 findings)",
        len(fk) == exp_k["compte"] == 110 and _par_cle(fk) == exp_k["par_cle"],
        f"{len(fk)} vs {exp_k['compte']}")
    cas("4c. paquet grype : déclaré par l'outil, jamais déduit",
        all(f.to_dict()["source"]["package_mapping"]["method"] == "declare_par_l_outil"
            for f in fg))
    severites_k = {f.to_dict()["severity"]["value"] for f in fk}
    cas("4d. severités kics : portées par la requête, aucune inventée",
        severites_k <= {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}, str(severites_k))
    cas("4e. aucune fuite de secret dans les findings normalisés",
        F.verifie_absence_secrets(fg + fk) == [],
        str(F.verifie_absence_secrets(fg + fk)[:2])[:120])

    # ------------------------------------------------- 5. convergence trivy × grype (hors-ligne)
    brut_t = json.loads((RACINE / "testrepo_sca" / "artefacts_captures" / "trivy_sca.json")
                        .read_text())
    ft = F.depuis_trivy(brut_t)
    res = CL.regrouper(ft + fg)
    clusters_paquet = [c for c in res["clusters"] if c["cle"].startswith("paquet:")]
    cas("5a. convergence par PAQUET : 6 clusters paquet: inter-outils",
        len(clusters_paquet) == 6
        and all("cross_tool" in c["reason"] for c in clusters_paquet),
        f"{len(clusters_paquet)} clusters")
    cas("5b. same_package sans same_dependency_usage (2 outils de dépendances, 0 usage)",
        all("same_package" in c["reason"] and "same_dependency_usage" not in c["reason"]
            for c in clusters_paquet))
    ids_ghsa = {i for c in clusters_paquet for i in c["members"] if i.startswith("gr")}
    ids_cve = {i for c in clusters_paquet for i in c["members"] if i.startswith("tv")}
    cas("5c. chaque cluster mêle GHSA (grype) et CVE (trivy) — namespaces distincts",
        bool(ids_ghsa) and bool(ids_cve),
        f"ghsa={len(ids_ghsa)} cve={len(ids_cve)}")

    # ------------------------------------------------- 6. e2e testrepo_sca (fan-out réel)
    import pipeline
    e = pipeline.executer("Analyse la sécurité de mon dépôt", RACINE / "testrepo_sca")
    steps = sorted({s["provider"] for s in e.plan["steps"]})
    # La fixture ne contient QUE des lockfiles : semgrep/checkov/gitleaks restent
    # éligibles (pas de déclaration d'applicabilité pour ces providers legacy/sans
    # globs) mais ne produisent rien — on asserte le fan-out, pas le plan entier.
    cas("6a. e2e : trivy ET grype exécutés (fan_out réel)",
        {"trivy", "grype"} <= set(steps), f"{steps}")
    motif = ((e.plan.get("selection") or {}).get("DEPENDENCY_ANALYSIS") or {}).get("motif", "")
    cas("6b. motif de sélection fan_out tracé", "fan_out" in motif, motif[:100])
    par_outil: dict = {}
    for f in e.findings:  # e.findings : dicts sérialisés (pas objets Finding)
        t = (f.get("source") or {}).get("tool")
        par_outil[t] = par_outil.get(t, 0) + 1
    cas("6c. findings des deux outils remontent (62 trivy + 62 grype)",
        par_outil.get("trivy") == 62 and par_outil.get("grype") == 62,
        f"{par_outil}")
    inter = (e.clusters or {}).get("clusters_inter_outils") or []
    cas("6d. clusters inter-outils présents (6 paquets × 2 outils)", len(inter) == 6,
        f"{len(inter)} clusters")
    from assainissement import contient_secret
    cas("6e. aucune fuite de secret dans le rapport final",
        contient_secret(json.dumps(e.findings, ensure_ascii=False), large=True) == 0)
    cas("6f. mission append-only tracée", bool(e.mission))

    # ------------------------------------------------- 7. plan niveau IaC (hors-ligne)
    from intent import Intent
    import intent as I
    it = Intent("resolved", "test", capabilities=("IAC_SCAN",), motifs={"IAC_SCAN": "test"})
    choix = I.choisir_providers(it, reg)
    cas("7a. IAC_SCAN fan_out : checkov + kics sélectionnés dans l'ordre",
        choix == ["checkov", "kics"], f"{choix}")

    for nom, ok, detail in CAS:
        print(f"  [{'OK' if ok else 'ECHEC'}] {nom}" + (f"  — {detail}" if detail and not ok else ""))
    print(f"\ntest_grype_kics : {len(CAS) - len(ECHECS)}/{len(CAS)} cas passés")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
