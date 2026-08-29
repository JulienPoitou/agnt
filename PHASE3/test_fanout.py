#!/usr/bin/env python3
"""
Batterie « étape 3 » — applicabilité, fan-out, montages par exécution (2026-08-29).

Invariants vérifiés (architecture gelée) :
- APPLICABILITÉ : déclarative (globs au manifest), déterministe (inventaire
  trié), PRÉ-exécution ; un provider écarté l'est avec motif tracé ; un provider
  sans déclaration reste toujours éligible (pas d'exclusion devinée) ; une
  fausse exclusion est pire qu'un not_scanned honnête.
- FAN-OUT : mode par capacité déclaré au registre (un_seul par DÉFAUT =
  comportement historique inchangé) ; fan_out borné par max_providers ; ordre de
  priorité ; budget global d'exécutions ; motifs tracés (choisis ET écartés).
- MONTAGES : défauts strictement identiques à l'existant ; une instance peut
  porter des montages distincts (pré-requis du parallélisme, non construit ici).

Usage: python3 PHASE3/test_fanout.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

CAS = []
ECHECS = []


def cas(nom: str, cond: bool, detail: str = ""):
    CAS.append((nom, cond, detail))
    if not cond:
        ECHECS.append(nom)


REGISTRE_SYNTHETIQUE = """
capabilities:
  - id: TEST_CAP_UN
    description: test — mode par défaut
    domaines: [test]
    entree: [cible]
    sortie: finding/test
    providers:
      - {id: alpha, commande: ["echo"], priorite: 10}
      - {id: beta, commande: ["echo"], priorite: 20}
  - id: TEST_CAP_FANOUT
    description: test — fan-out borné
    domaines: [test]
    entree: [cible]
    sortie: finding/test
    mode_selection: fan_out
    max_providers: 2
    providers:
      - {id: p1, commande: ["echo"], priorite: 30}
      - {id: p2, commande: ["echo"], priorite: 10}
      - {id: p3, commande: ["echo"], priorite: 20}
"""


def main() -> int:
    import intent as I
    import plan as P
    from intent import Intent
    from registre import Registry

    r = Registry()

    # ------------------------------------------------------------ 1. applicabilité
    m_go = r.provider("semgrep_go").manifest
    m_bandit = r.provider("bandit").manifest
    cas("1a. applicabilité DÉCLARÉE au manifest (semgrep_go *.go ; bandit *.py)",
        any("*.go" in g for g in m_go.applicable_globs)
        and any("*.py" in g for g in m_bandit.applicable_globs)
        and r.provider("checkov").manifest.applicable_globs == (),
        f"go={m_go.applicable_globs} bandit={m_bandit.applicable_globs}")

    inv_go = P.inventaire(RACINE / "testrepo_go")
    inv_py = P.inventaire(RACINE / "testrepo")
    cas("1b. inventaire déterministe, relatif, trié",
        inv_go == P.inventaire(RACINE / "testrepo_go")
        and all(not f.startswith("/") for f in inv_go)
        and inv_go == sorted(inv_go) and "main.go" in inv_go)

    provs = ["semgrep", "semgrep_go", "trivy", "gitleaks", "checkov"]
    elig_go, ex_go = P.filtrer_applicabilite(provs, r, RACINE / "testrepo_go")
    elig_py, ex_py = P.filtrer_applicabilite(provs, r, RACINE / "testrepo")
    cas("1c. dépôt Go : semgrep_go éligible ; dépôt Python : écarté AVEC motif",
        "semgrep_go" in elig_go and not ex_go.get("semgrep_go")
        and "semgrep_go" in ex_py and "applicable" in ex_py["semgrep_go"].lower(),
        f"ex_py={ex_py}")
    cas("1d. sans déclaration = toujours éligible (checkov même sans IaC)",
        "checkov" in elig_py and "checkov" in elig_go)

    # ------------------------------------------------------------ 2. fan-out
    with tempfile.TemporaryDirectory() as td:
        chemin = Path(td) / "caps.yaml"
        chemin.write_text(REGISTRE_SYNTHETIQUE, encoding="utf-8")
        rs = Registry(chemin=chemin)
        it_un = Intent("resolved", "test", capabilities=("TEST_CAP_UN",),
                       motifs={"TEST_CAP_UN": "test"})
        it_fo = Intent("resolved", "test", capabilities=("TEST_CAP_FANOUT",),
                       motifs={"TEST_CAP_FANOUT": "test"})
        choix_un = I.choisir_providers(it_un, rs)
        choix_fo = I.choisir_providers(it_fo, rs)
        cas("2a. défaut un_seul : 1 provider (comportement historique)",
            choix_un == ["alpha"], f"{choix_un}")
        cas("2b. fan_out borné : max_providers dans l'ordre de priorité",
            choix_fo == ["p2", "p3"], f"{choix_fo}")
        # motif tracé par construire
        plan_fo = P.construire("test", "/tmp", choix_fo, rs, "deterministe")
        motif = plan_fo.selection["TEST_CAP_FANOUT"]["motif"]
        cas("2c. motif de fan-out tracé (choisis + écartés nommés)",
            "fan_out" in motif and "p1" in motif, motif[:110])
        # 2d. budget global : trop d'étapes = refus bruyant
        try:
            P.verifier_budget(["x"] * (P.MAX_ETAPES + 1))
            cas("2d. budget global : dépassement refusé", False, "accepté")
        except P.PlanError as e:
            cas("2d. budget global : dépassement refusé", "budget" in str(e).lower(), str(e)[:70])

    # ------------------------------------------------------------ 3. montages
    import adapters
    from sandbox import Sandbox
    sbx_defaut = Sandbox()
    cas("3a. montages par défaut STRICTEMENT identiques à l'existant",
        sbx_defaut.M_SCAN == "/home/user/PHASE3/mt-scan"
        and sbx_defaut.M_OUT == "/home/user/PHASE3/mt-out"
        and adapters.IN_SCAN == sbx_defaut.M_SCAN)
    s1 = Sandbox(M_SCAN="/x/scan-1", M_OUT="/x/out-1")
    s2 = Sandbox(M_SCAN="/x/scan-2", M_OUT="/x/out-2")
    cmd1, cmd2 = s1.commande(["echo"]), s2.commande(["echo"])
    cas("3b. montages par instance : deux sandboxes indépendantes",
        "/x/scan-1" in cmd1 and "/x/out-1" in cmd1
        and "/x/scan-2" in cmd2 and "/x/scan-1" not in cmd2)

    # ------------------------------------------------------------ 4. e2e réels
    import pipeline
    e_go = pipeline.executer("Analyse la sécurité de mon dépôt", RACINE / "testrepo_go")
    steps_go = sorted({s["provider"] for s in e_go.plan["steps"]})
    e_py = pipeline.executer("Analyse la sécurité de mon dépôt", RACINE / "testrepo")
    steps_py = sorted({s["provider"] for s in e_py.plan["steps"]})
    sel_py = (e_py.plan.get("selection") or {}).get("applicabilite") or {}
    cas("4a. e2e dépôt Go : semgrep_go exécuté",
        "semgrep_go" in steps_go, f"{steps_go}")
    cas("4b. e2e dépôt Python : semgrep_go écarté AVANT exécution, motif tracé",
        "semgrep_go" not in steps_py and "semgrep_go" in sel_py,
        f"steps={steps_py} applicabilité={sel_py}")
    cas("4c. les deux missions restent complètes (findings > 0, mission tracée)",
        len(e_go.findings) > 0 and len(e_py.findings) > 0
        and e_go.mission and e_py.mission)

    for nom, ok, detail in CAS:
        print(f"  [{'OK' if ok else 'ECHEC'}] {nom}" + (f"  — {detail}" if detail and not ok else ""))
    print(f"\ntest_fanout : {len(CAS) - len(ECHECS)}/{len(CAS)} cas passés")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
