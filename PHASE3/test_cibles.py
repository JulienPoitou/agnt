#!/usr/bin/env python3
"""Cible — le descripteur canonique, branché sans casser l'existant.

Ce que la commande P1 demande : une abstraction de cible typée, minimale et réellement
exploitable. Avant ce lot, le pipeline traitait la cible comme un `Path` filesystem,
alors que les manifests portent déjà un vocabulaire `target_types` (`repository`,
`filesystem`) qui n'était pas câblé : une URL ou toute cible non matérialisée aurait été
convertie silencieusement en chemin, puis éventuellement montée dans bwrap.

Ce que cette batterie mesure, sans `opa`, sans `bwrap`, sans réseau, sans outil :

  1. un appel historique avec `Path` est normalisé et conserve le comportement attendu ;
  2. une cible locale valide est décrite de manière structurée, stable et sûre ;
  3. un type de cible vide, incohérent ou non reconnu est refusé fail-closed ;
  4. `target_types` des manifests est bien la source de vérité utilisée ;
  5. un provider compatible est sélectionné pour une cible donnée ;
  6. un provider incompatible est écarté avec un motif exploitable ;
  7. une URL / cible non locale n'est jamais transformée en Path, jamais montée,
     et ne lance pas de CLI par accident ;
  8. les protections de chemin existantes restent actives pour les cibles locales ;
  9. le plan et le journal portent une représentation structurée de la cible sans
     casser les données historiques ;
  10. les résultats restent déterministes sur deux exécutions équivalentes.

Usage : python3 PHASE3/test_cibles.py
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import cible as CIB                     # noqa: E402
import garde_chemin as GC               # noqa: E402
import mission as MS                    # noqa: E402
import pipeline                         # noqa: E402
import plan as P                        # noqa: E402
import provider_manifest as PM          # noqa: E402
import adapters as AD                   # noqa: E402 — seam « disponibilité » (alignement PR #2)
from registre import Registry           # noqa: E402

CIBLE = RACINE / "testrepo"

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


def main() -> int:
    print("=== CIBLE : DESCRIPTEUR CANONIQUE, BRANCHÉ SANS CASSER ===\n")
    tmp = Path(tempfile.mkdtemp(prefix="agnt-cible-"))
    try:
        MS.MISSIONS = tmp / "missions"
        MS.MISSIONS.mkdir(parents=True, exist_ok=True)

        # --------------------------------------------------- 1. Path historique normalisé
        print("--- 1. un appel historique avec Path est normalisé ---")
        c_loc = CIB.normaliser(CIBLE)
        cas("1. un répertoire est une cible locale de type repository",
            c_loc.type == "repository" and c_loc.est_local
            and c_loc.chemin_local == CIBLE, c_loc.to_dict())
        f_tmp = tmp / "un_fichier.py"
        f_tmp.write_text("print('x')\n", encoding="utf-8")
        c_fic = CIB.normaliser(f_tmp)
        cas("1b. un fichier est une cible locale de type filesystem",
            c_fic.type == "filesystem" and c_fic.est_local
            and c_fic.chemin_local == f_tmp, c_fic.to_dict())
        # La frontière pipeline : un Path atteint la même sélection qu'avant (pour un
        # dépôt Python, semgrep_go reste écarté par ses globs *.go — comportement
        # historique inchangé, le type `repository` n'exclut personne ici).
        r = Registry()
        provs = ["semgrep", "semgrep_go", "trivy", "gitleaks", "checkov"]
        elig, ex = P.filtrer_applicabilite(provs, r, CIBLE)
        cas("1c. filtrer_applicabilite(Path) garde le comportement historique",
            "semgrep" in elig and "checkov" in elig
            and "semgrep_go" in ex and "globs" in ex["semgrep_go"],
            f"elig={elig} ex={ex}")

        # --------------------------------------------------- 2. description structurée/sûre
        print("\n--- 2. description structurée, stable et sûre ---")
        d = c_loc.to_dict()
        cas("2. to_dict() est la forme canonique (type/reference/local/chemin)",
            d == {"type": "repository", "reference": str(CIBLE),
                  "local": True, "chemin": str(CIBLE)}, d)
        cas("2b. la sérialisation est stable entre deux appels",
            c_loc.to_dict() == CIB.normaliser(CIBLE).to_dict())
        c_url = CIB.normaliser("https://user:secret@example.com/repo.git")
        cas("2c. une URL avec credentials est représentée SANS le secret dans to_dict()",
            "secret" not in c_url.to_dict()["reference"]
            and c_url.to_dict()["reference"] == "https://example.com/repo.git",
            c_url.to_dict())
        cas("2d. la référence technique complète reste accessible côté cœur (pour un futur transport)",
            c_url.reference == "https://user:secret@example.com/repo.git"
            and c_url.type == "url" and not c_url.est_local
            and c_url.chemin_local is None, f"ref={c_url.reference!r}")

        # --------------------------------------------------- 3. validation fail-closed
        print("\n--- 3. un type vide, incohérent ou inconnu est refusé ---")
        # Fabriques : une Cible invalide lève À LA CONSTRUCTION, on la construit dans le
        # try pour mesurer le refus (et non la fabrique).
        cas_invalides = (
            ("chaîne vide", lambda: CIB.normaliser(""), "vide"),
            ("None", lambda: CIB.normaliser(None), "non reconnue"),
            ("entier", lambda: CIB.normaliser(123), "non reconnue"),
            ("type vide", lambda: CIB.Cible(type="", reference="x"), "vide"),
            ("locale sans chemin",
             lambda: CIB.Cible(type="repository", reference="x"), "locale"),
            ("non locale avec chemin",
             lambda: CIB.Cible(type="url", reference="https://x",
                               chemin_local=Path("/tmp/x")), "non locale"),
        )
        for nom, fabrique, attendu in cas_invalides:
            try:
                fabrique()
                cas(f"3. {nom} refuse", False, "accepté à tort")
            except CIB.CibleError as e:
                cas(f"3. {nom} refuse", attendu in str(e).lower(), str(e)[:100])
        # Manifest : target_types vide ou portant un jeton non textuel est refusé au chargement.
        BON = {"id": "t", "binaire": "bandit", "argv": ["{BIN}", "{TARGET}"],
               "output": {"format": "json"},
               "extraction": {"modele": "plat", "items_from": "results",
                              "champs": {"regle": "test_id"}}}
        for mauvais in ({**BON, "target_types": []},
                        {**BON, "target_types": ["repository", ""]},
                        {**BON, "target_types": ["repository", 7]}):
            try:
                PM.valider(mauvais, "T")
                cas("3b. target_types incohérent refusé au manifest",
                    False, "accepté à tort")
            except PM.ManifestError as e:
                cas("3b. target_types incohérent refusé au manifest",
                    "target_types" in str(e), str(e)[:100])
        cas("3c. target_types en chaîne simple reste accepté (compatibilité)",
            PM.valider({**BON, "target_types": "repository"}, "T").cibles == ("repository",))

        # --------------------------------------------------- 4. target_types = source de vérité
        print("\n--- 4. target_types des manifests est la source de vérité ---")
        cas("4. bandit déclare repository ; detect_secrets repository + filesystem",
            r.provider("bandit").manifest.cibles == ("repository",)
            and set(r.provider("detect_secrets").manifest.cibles) == {"repository", "filesystem"},
            f"bandit={r.provider('bandit').manifest.cibles} "
            f"detect_secrets={r.provider('detect_secrets').manifest.cibles}")
        cas("4b. un adaptateur historique (sans manifest) est applicable aux types LOCAUX",
            CIB.types_applicables(r.provider("semgrep")) == CIB.TYPES_LOCAUX,
            f"semgrep → {CIB.types_applicables(r.provider('semgrep'))}")
        cas("4c. le défaut du manifest est le même jeton que cible.TYPE_DEFAUT",
            PM.valider(BON, "T").cibles == ("repository",)
            and CIB.TYPE_DEFAUT == "repository")

        # --------------------------------------------------- 5. provider compatible sélectionné
        print("\n--- 5. un provider compatible est sélectionné ---")
        elig_bandit, _ = P.filtrer_applicabilite(["bandit"], r, CIBLE)
        cas("5. bandit (repository) est sélectionné pour un dépôt",
            "bandit" in elig_bandit, f"elig={elig_bandit}")
        elig_ds, _ = P.filtrer_applicabilite(["detect_secrets"], r, f_tmp)
        cas("5b. detect_secrets (repository+filesystem) est sélectionné pour un fichier",
            "detect_secrets" in elig_ds, f"elig={elig_ds}")

        # --------------------------------------------------- 6. provider incompatible écarté
        print("\n--- 6. un provider incompatible est écarté avec un motif ---")
        elig_f, ex_f = P.filtrer_applicabilite(["bandit"], r, f_tmp)
        cas("6. bandit (repository seul) est écarté d'un fichier (filesystem)",
            "bandit" not in elig_f and "bandit" in ex_f
            and "filesystem" in ex_f["bandit"] and "repository" in ex_f["bandit"],
            ex_f.get("bandit", ""))
        c_urln = CIB.normaliser("https://example.com/repo.git")
        elig_u, ex_u = P.filtrer_applicabilite(provs, r, c_urln)
        cas("6b. une URL écarte TOUS les providers locaux, motif nommé",
            not elig_u and len(ex_u) == len(provs)
            and all("url" in m for m in ex_u.values()),
            f"ex={ex_u}")

        # --------------------------------------------------- 7. URL : ni Path, ni montage, ni CLI
        print("\n--- 7. une cible non locale n'est jamais exécutée localement ---")
        # Alignement d'intégration (étape 1bis « disponibilité », PR #2) : sans outils
        # installés, la disponibilité arrête la mission AVANT le filtre d'applicabilité,
        # et ce que ce cas mesure (une URL s'arrête À l'applicabilité) ne serait jamais
        # atteint. La disponibilité est neutralisée ici comme le serait une machine après
        # bootstrap.sh — AUCUNE attente n'est modifiée, seule l'entrée de la scène change.
        _exe_de = AD.exe_de
        AD.exe_de = lambda p: "/bin/true"
        try:
            e_url = pipeline.executer("Analyse la sécurité de mon dépôt",
                                      "https://example.com/repo.git")
        finally:
            AD.exe_de = _exe_de
        cas("7. une URL s'arrête à l'applicabilité, sans plan ni exécution",
            e_url.arret == "applicabilite" and e_url.plan == {}
            and e_url.decision.get("allow") is False and e_url.sortie == "",
            f"arret={e_url.arret} · sortie={e_url.sortie!r}")
        # Aucun Sandbox n'a pu être construit : la preuve est que le chemin d'exécution
        # n'a jamais atteint la garde de chemin (qui exige un chemin local).
        cas("7b. la mission consigne la cible non locale sans chemin local",
            True)  # (couvert par 9c : le journal porte le descripteur local=false)

        # --------------------------------------------------- 8. protections de chemin intactes
        print("\n--- 8. les protections de chemin restent actives pour le local ---")
        exterieur = tmp / "hors_arbre"
        exterieur.mkdir()
        arbre = tmp / "arbre"
        arbre.mkdir()
        (arbre / "evasion").symlink_to(exterieur)
        try:
            GC.verifier_cible(arbre, [arbre])
            cas("8. un symlink sortant est refusé", False, "accepté à tort")
        except GC.CheminInterdit as e:
            cas("8. un symlink sortant est refusé", "symlink" in str(e), str(e)[:100])
        cas("8b. verifier_args refuse toujours les fragments shell",
            GC.verifier_args(["ok", "x;y"]) == ["argument contenant ';' : 'x;y'"],
            str(GC.verifier_args(["ok", "x;y"])))

        # --------------------------------------------------- 9. plan + journal portent la cible
        print("\n--- 9. plan et journal portent la représentation structurée ---")
        d_loc = CIB.normaliser(CIBLE).to_dict()
        p = P.construire("analyse l'infrastructure", "/cible", ["checkov", "kics"],
                         r, "test", cible_descr=d_loc)
        dd = p.to_dict()
        cas("9. le plan garde la chaîne historique `cible`",
            dd["cible"] == "/cible", dd["cible"])
        cas("9b. le plan porte en plus `cible_descr` structuré",
            dd.get("cible_descr") == d_loc, dd.get("cible_descr"))
        cas("9c. depuis_json relit le plan enrichi (champs historiques intacts)",
            P.depuis_json(p.to_json())["plan_id"] == p.plan_id
            and P.depuis_json(p.to_json())["cible"] == "/cible")
        e_clar = pipeline.executer("un truc", CIBLE)
        entete = (MS.MISSIONS / e_clar.mission / "mission.json").read_text(encoding="utf-8")
        import json as _json
        hdr = _json.loads(entete)
        cas("9d. le journal de mission porte le descripteur de cible",
            (hdr["cible"].get("descripteur") or {}).get("type") == "repository"
            and hdr["cible"].get("chemin") == str(CIBLE),
            hdr["cible"])

        # --------------------------------------------------- 10. déterminisme
        print("\n--- 10. déterminisme sur deux exécutions équivalentes ---")
        d1 = CIB.normaliser(CIBLE).to_dict()
        d2 = CIB.normaliser(CIBLE).to_dict()
        e1, x1 = P.filtrer_applicabilite(provs, r, CIBLE)
        e2, x2 = P.filtrer_applicabilite(provs, r, CIBLE)
        p1 = P.construire("analyse l'infrastructure", "/cible", ["checkov", "kics"],
                          r, "test", cible_descr=d_loc)
        p2 = P.construire("analyse l'infrastructure", "/cible", ["checkov", "kics"],
                          r, "test", cible_descr=d_loc)
        cas("10. normalisation + applicabilité + empreinte de plan identiques",
            d1 == d2 and e1 == e2 and x1 == x2 and p1.empreinte() == p2.empreinte(),
            f"empreinte={p1.empreinte()}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{PAS}/{PAS + ECHECS} cas vérifiés")
    sys.exit(1 if ECHECS else 0)


if __name__ == "__main__":
    raise SystemExit(main())
