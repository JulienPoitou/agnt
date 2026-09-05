#!/usr/bin/env python3
"""Validation registre des plugins G1 (vague-web/g1) — étape 4 de la qualification.

Charge Registry() depuis le worktree, vérifie provider + cibles, puis résout un
argv complet via fournisseurs_web.planifier. AUCUNE exécution ici.
"""
import json
import sys

sys.path.insert(0, "/home/julie/agnt-g1/PHASE3/slice")

import fournisseurs_web as FW  # noqa: E402

REGLES = "/home/julie/agnt-g1/PHASE3/regles_web"
CIBLE = "http://127.0.0.1:8807"
OUTILS = ("whatweb", "webanalyze", "wafw00f", "nikto")

from registre import Registry  # noqa: E402

reg = Registry()
echecs = []
for outil in OUTILS:
    try:
        prov = reg.provider(outil)
        assert prov is not None, "provider absent"
        mani = prov.manifest
        assert "url" in tuple(mani.cibles), f"cibles={list(mani.cibles)}"
        plan = FW.planifier(outil, CIBLE, "/tmp/x", egress=True,
                            registre=reg, regles=REGLES)
        argv = plan["argv"]
        assert CIBLE in argv, "URL absente de l'argv"
        assert plan["timeout_s"] >= 300, f"timeout={plan['timeout_s']}"
        # sans egress → refus nommé
        try:
            FW.planifier(outil, CIBLE, "/tmp/x", egress=False,
                         registre=reg, regles=REGLES)
            echecs.append(f"{outil} : sans egress accepté (devrait refuser)")
            continue
        except FW.ErreurPlanification as e:
            assert "egress" in str(e), f"motif inattendu : {e}"
        print(f"OK {outil}  argv={json.dumps(argv, ensure_ascii=False)}")
        print(f"          sortie={plan['nom_sortie']} timeout={plan['timeout_s']}s "
              f"codes={plan['codes_succes']}")
    except Exception as e:  # noqa: BLE001
        echecs.append(f"{outil} : {type(e).__name__}: {e}")

if echecs:
    print("\nÉCHECS :")
    for e in echecs:
        print("  -", e)
    sys.exit(1)
print("\nVALIDATION REGISTRE OK (4/4 providers planifiables)")
