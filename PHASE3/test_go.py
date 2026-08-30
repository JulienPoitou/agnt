#!/usr/bin/env python3
"""
Batterie « capacité Go » — provider semgrep_go (2026-08-29, chantier largeur-Go).

Périmètre strict :
- AUCUN appel réseau, AUCUN outil exécuté : tout est lu depuis les artefacts
  capturés PHASE3/testrepo_go/artefacts_captures/ (semgrep_go, trivy, gitleaks).
- Le clustering et le modèle de findings ne sont PAS modifiés : la batterie vérifie
  la DÉCLARATION, l'extraction générique, le nettoyage canonique DÉCLARÉ des ids,
  l'intention (mot-clé « golang » — jamais « go » nu), et la CONVERGENCE attendue
  (gitleaks + semgrep_go sur le même fichier → regroupement inter-outils).

Usage: python3 PHASE3/test_go.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import clusterer  # noqa: E402
import extraction  # noqa: E402
import findings as F  # noqa: E402
import intent as I  # noqa: E402
import provider_manifest as PM  # noqa: E402
from registre import Registry  # noqa: E402

CAP = RACINE / "testrepo_go" / "artefacts_captures"
ATTENDUS = RACINE / "testrepo_go" / "ATTENDUS.yaml"

CAS = []
ECHECS = []


def cas(nom: str, cond: bool, detail: str = ""):
    CAS.append((nom, cond, detail))
    if not cond:
        ECHECS.append(nom)


def _canon_depuis(canon: str) -> str:
    """Partie stable de l'id, indépendante du chemin de montage : à partir de
    « go.lang. » — le marqueur canonique des règles du pack p/golang."""
    i = canon.find("go.lang.")
    return canon[i:] if i >= 0 else canon


def main() -> int:
    # 0. artefacts capturés
    if not all((CAP / n).is_file() for n in ("semgrep_go.json", "trivy.json", "gitleaks.json")):
        print(f"MANQUANT : artefacts dans {CAP}")
        return 2
    sg_brut = json.loads((CAP / "semgrep_go.json").read_text(encoding="utf-8"))
    tv_brut = json.loads((CAP / "trivy.json").read_text(encoding="utf-8"))
    gl_brut = json.loads((CAP / "gitleaks.json").read_text(encoding="utf-8"))
    att = yaml.safe_load(ATTENDUS.read_text(encoding="utf-8"))

    # 1. déclaration
    r = Registry()
    prov = r.provider("semgrep_go")
    m = prov.manifest
    cap = next(c for c in r.capabilities() if c.id == prov.capability)
    cas("1a. capacité GO publique (incluse dans les requêtes génériques)",
        prov.capability == "CODE_STATIC_ANALYSIS_GO" and not cap.interne,
        f"cap={prov.capability} interne={cap.interne}")
    cas("1b. binaire semgrep (zéro binaire nouveau), règles golang épinglées",
        m.binaire == "semgrep" and any("golang.yaml" in a for a in m.argv),
        f"argv={list(m.argv)}")
    cas("1c. nettoyage canonique DÉCLARÉ + champs texte masqués",
        m.extraction.nettoyage_regle == "semgrep" and m.extraction.masquer_large == ["message"],
        f"nettoyage={m.extraction.nettoyage_regle!r} masquer={m.extraction.masquer_large}")
    cas("1d. semgrep sort 1 quand il trouve : codes de succès [0, 1]",
        tuple(m.code_succes) == (0, 1), f"{tuple(m.code_succes)}")

    # 2. garde : un nom de nettoyage inconnu est refusé au chargement
    doc_ok = yaml.safe_load(r.chemin.read_text(encoding="utf-8"))
    doc_prov = next(p for c in doc_ok["capabilities"] for p in c["providers"]
                    if p.get("id") == "semgrep_go")
    import copy
    mauvais = copy.deepcopy(doc_prov["manifest"])
    mauvais["extraction"]["nettoyage_regle"] = "invente"
    try:
        PM.valider(mauvais, "CODE_STATIC_ANALYSIS_GO")
        cas("2a. nettoyage inconnu refusé", False, "accepté silencieusement")
    except PM.ManifestError as e:
        cas("2a. nettoyage inconnu refusé", "nettoyage_regle" in str(e), str(e)[:80])
    cas("2b. Extraction sans nettoyage déclaré = aucune normalisation implicite",
        extraction.Extraction(modele="plat").nettoyage_regle == "")

    # 3. extraction générique sur l'artefact réel
    items = extraction.extraire(sg_brut, m.extraction)
    champs = [extraction.champs(it, m.extraction) for it in items]
    cas("3a. extraction : compte = artefact",
        len(items) == len(sg_brut.get("results") or []), f"{len(items)} extraits")
    cas("3b. mapping complet (regle/fichier/ligne/message non vides, ligne entière)",
        all(c.get(k) not in (None, "", []) for c in champs for k in ("regle", "fichier", "ligne", "message"))
        and all(isinstance(c["ligne"], int) for c in champs))

    # 4. findings + nettoyage canonique appliqué (préfixe de montage retiré)
    fs_sg = F.depuis_manifest(sg_brut, m, "semgrep_go")
    canons = sorted(x.source["canonical_rule_id"] for x in fs_sg)
    cas("4a. canonical_rule_id canonique (aucun préfixe de chemin de montage)",
        all(c.startswith("semgrep_go:go.lang.") for c in canons), f"{canons}")
    # 4b — ATTENTE MOUVÉE LE 2026-08-30, avec sa raison écrite ici plutôt qu'un test supprimé.
    # L'intention du cas est intacte : un finding de la capacité Go doit rester RATTACHABLE à
    # `semgrep_go`, distinct de `semgrep`. Ce qui a changé est le CHAMP qui porte cette
    # distinction : `source["tool"]` nommait le provider, et le clusterer s'en servait pour
    # compter les OUTILS d'un cluster — `semgrep` et `semgrep_go` (même moteur, deux jeux de
    # règles) y comptaient donc comme deux outils indépendants, ce qui sur-évaluait une
    # convergence dans un rapport de sécurité. `tool` nomme désormais le moteur, `provider`
    # porte la trace demandée.
    cas("4b. trace distincte : provider = semgrep_go, outil = semgrep (le moteur)",
        all(x.source["provider"] == "semgrep_go" and x.source["tool"] == "semgrep"
            for x in fs_sg),
        str({(x.source.get("provider"), x.source.get("tool")) for x in fs_sg}))
    cas("4c. gravité = celle de l'outil, origine tracée",
        all(x.severity["origine"] == "semgrep_go" for x in fs_sg)
        and {x.severity["value"] for x in fs_sg} == {"WARNING"},
        f"{[x.severity['value'] for x in fs_sg]}")

    # 5. référentiel ATTENDUS (comparaison sur la partie stable de l'id)
    obtenu: dict[str, set] = {}
    for x in fs_sg:
        obtenu.setdefault(f'{x.location["file"]}:{x.location["line"]}', set()).add(
            _canon_depuis(x.source["canonical_rule_id"]))
    attendu = {k: {_canon_depuis(v2) for v2 in v}
               for k, v in att["attendus"]["semgrep_go"]["par_emplacement"].items()}
    cas("5. ATTENDUS.yaml respecté emplacement par emplacement",
        obtenu == attendu, f"obtenu={obtenu}\nattendu={attendu}")

    # 6. intention : « golang » oui, « go » nu NON (piège « django »), générique oui
    i1 = I.inferer("analyse le code golang de ce dépôt", r)
    i2 = I.inferer("scanne ce dépôt django", r)
    i3 = I.inferer("scan de sécurité complet du dépôt", r)
    cas("6a. « golang » → capacité GO sélectionnée",
        "CODE_STATIC_ANALYSIS_GO" in i1.capabilities, f"{i1.capabilities}")
    # Le piège : « go » en sous-chaîne matcherait « django ». Le seul mot-clé est
    # « golang ». Sur « scanne ce dépôt django », la capacité GO ne peut venir QUE de
    # l'extension générique (« scanne » ∈ GENERIC), jamais d'un mot-clé.
    mots_go = I.MOTIFS["CODE_STATIC_ANALYSIS_GO"]
    cas("6b. « django » ne déclenche PAS la capacité GO par mot-clé",
        mots_go == ("golang",) and all(mot not in "django" for mot in mots_go)
        and i2.motifs.get("CODE_STATIC_ANALYSIS_GO") in (None, "demande générique"),
        f"mots={mots_go} motif={i2.motifs.get('CODE_STATIC_ANALYSIS_GO')}")
    cas("6c. requête générique → capacité GO incluse (publique)",
        "CODE_STATIC_ANALYSIS_GO" in i3.capabilities, f"{i3.capabilities}")

    # 7. CONVERGENCE mesurée hors-ligne : les trois outils sur la même fixture
    fs_tv = F.depuis_trivy(tv_brut)
    fs_gl = F.depuis_gitleaks(gl_brut)
    outil_par_id = {x.id: x.source["tool"] for x in fs_sg + fs_tv + fs_gl}
    res = clusterer.regrouper(fs_sg + fs_tv + fs_gl)
    inter = res.get("clusters_inter_outils", [])
    outils_inter = {outil_par_id[mm] for cl in inter for mm in cl["members"]}
    # 7a — même déménagement (2026-08-30) : la convergence revendiquée est bien entre
    # DEUX MOTEURS distincts (gitleaks d'un côté, le moteur semgrep de l'autre). Ce que
    # l'attendait corrige : `semgrep_go` n'y apparaît plus comme outil, mais doit y
    # apparaître comme provider — sinon la correction aurait effacé la traçabilité au lieu
    # de la déplacer.
    cas("7a. cluster inter-outils sur main.go (gitleaks × moteur semgrep, même fichier)",
        len(inter) >= 1 and {"semgrep", "gitleaks"} <= outils_inter,
        f"inter={len(inter)} outils={sorted(outils_inter)}")
    par_id = {f.id: f for f in (fs_sg + fs_tv + fs_gl)}
    cas("7aa. …et le provider de ce cluster est bien nommé semgrep_go (traçabilité intacte)",
        any("semgrep_go" in {par_id[m].source.get("provider") for m in c["members"] if m in par_id}
            for c in inter),
        "aucun membre de cluster inter-outils ne vient de semgrep_go")
    cas("7b. les CVE trivy (go.mod) restent à part : fichier distinct, pas de collage",
        "trivy" not in outils_inter,
        f"outils inter-outils={sorted(outils_inter)}")
    cas("7c. trivy retrouve les 4 CVE du référentiel sur golang.org/x/text",
        len([x for x in fs_tv if x.source.get("package") == "golang.org/x/text"])
        == att["attendus"]["trivy"]["compte"],
        f"{len(fs_tv)} findings trivy")

    for nom, ok, detail in CAS:
        print(f"  [{'OK' if ok else 'ECHEC'}] {nom}" + (f"  — {detail}" if detail and not ok else ""))
    print(f"\ntest_go : {len(CAS) - len(ECHECS)}/{len(CAS)} cas passés")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
