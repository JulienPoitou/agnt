#!/usr/bin/env python3
"""
Batterie « étape 6 » — chemin d'utilisation minimal (2026-08-29).

Invariants vérifiés :
- POINT D'ENTRÉE : `analyser.lancer(mission, cible)` exécute le pipeline, archive
  les artefacts SOUS la mission (append-only, jamais écrasés) et produit un
  RAPPORT.md par défaut. Deux missions = deux sorties distinctes.
- ARRÊTS : clarification et refus donnent un code de sortie distinct, une
  phrase lisible, et N'EXÉCUTENT rien (aucun RAPPORT.md, plan vide).
- F2 : les marqueurs de domaine l'emportent sur les mots génériques
  (« Analyse mon code Terraform » ne paie plus 5 capacités) ; une demande
  vraiment générique conserve toutes les capacités publiques.
- F3 : la clarification ne liste QUE des capacités publiques — les capacités
  internes (`interne: true`) ne fuient plus dans une phrase utilisateur.
- LLM PILOTE DANS LE CATALOGUE : branché via analyser, validé contre le
  registre ; un LLM qui invente, impose un outil, ou tombe → repli
  déterministe TRACÉ dans `moteur`. Aucun nom d'outil ne lui est transmis.
- CONFIANCE DE CIBLE : `--confiance controlled|untrusted` arrive jusqu'à
  `pipeline.executer()`, est enregistrée dans le journal de mission, et une valeur
  inconnue est une ERREUR immédiate — jamais un repli. Le refus réel (mémoire non
  bornée + cible non fiable) exige le binaire `opa` : sans lui, cas NON ÉVALUÉ.

Section G (`bloc_confiance`) exécutable seule :
    python3 -c "import sys; sys.path.insert(0,'PHASE3'); import test_utilisation as t; \
t.bloc_confiance(); raise SystemExit(1 if t.ECHECS else 0)"

Usage: python3 PHASE3/test_utilisation.py
"""
from __future__ import annotations

import sys
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

CAS = []
ECHECS = []


def cas(nom: str, cond: bool, detail: str = ""):
    CAS.append((nom, cond, detail))
    if not cond:
        ECHECS.append(nom)


# TROIS ÉTATS, JAMAIS MÉLANGÉS (convention reprise de test_correlation.py) :
#   succès · échec (exit 1) · non évalué (dépendance d'environnement absente).
# Un cas non évalué n'est JAMAIS compté comme un succès.
NON_EVALUES: list[tuple[str, str]] = []


def cas_non_evalue(nom: str, motif: str):
    NON_EVALUES.append((nom, motif))


def _faux_executer(capture: dict, arret: str = "policy",
                   motifs=("memoire_non_bornee_cible_non_fiable",)):
    """Remplace pipeline.executer pour observer ce que la CLI lui transmet.

    On ne rejoue pas la policy ici : on vérifie seulement que l'argument de sécurité
    ARRIVE jusqu'à la fonction qui l'appelle. L'effet réel est vérifié à part, avec opa.
    """
    import pipeline

    def faux(requete, cible, cible_autorisee=True, confiance_cible="controlled",
             avec_internes=False, escalade=True, egress=None):
        capture.clear()
        capture.update(requete=requete, cible=str(cible),
                       cible_autorisee=cible_autorisee,
                       confiance_cible=confiance_cible,
                       avec_internes=avec_internes,
                       escalade=escalade,
                       # `egress` est capturé comme les autres arguments de sécurité :
                       # ce n'est pas un réglage de confort mais une DÉLÉGATION, et ce
                       # fichier existe précisément pour vérifier que ce genre d'argument
                       # arrive jusqu'au pipeline.
                       egress=egress)
        return pipeline.Execution(
            plan={}, decision={"allow": False, "motifs": list(motifs)},
            intent={"moteur": "deterministe"}, arret=arret, mission="")

    # Le contrat RÉEL a été vérifié avant de toucher au double : `pipeline.executer`
    # expose bien `egress` (« l'autorisation de sortir pour CETTE mission », `None` =
    # le profil fait foi). C'est le DOUBLE qui avait dérivé — et comme `analyser.lancer`
    # transmet `egress` systématiquement, toute la batterie levait un TypeError pour une
    # raison étrangère à ce qu'elle mesure. On interdit désormais la dérive : un double
    # qui n'expose pas le contrat réel casse à la CONSTRUCTION, pas à l'usage.
    import inspect
    reel = inspect.signature(pipeline.executer).parameters
    double = inspect.signature(faux).parameters
    manquants = [p for p in reel if p not in double]
    if manquants:
        raise AssertionError(
            f"double `faux` périmé : paramètre(s) {manquants} absent(s) du double alors "
            f"que `pipeline.executer` les expose. Contrat réel : {list(reel)}.")
    return faux


def bloc_confiance():
    """Section G — la confiance de cible, du drapeau CLI jusqu'à la décision.

    Constat mesuré (2026-08-30) : `policy.rego:90-97` refuse une cible « untrusted »
    quand la mémoire n'est pas bornée, `profils.py` documente cette fermeture, et
    `test_intentions.py:126-133` le prouve à l'étage de la policy. Mais
    `analyser.py` appelait `pipeline.executer(requete, cible)` SANS `confiance_cible` :
    la valeur par défaut « controlled » était donc imposée par le point d'entrée.
    Autrement dit la garde existait et ne pouvait être armée par personne d'autre
    qu'un test. Ces cas verrouillent le câblage, pas la règle (la règle est déjà
    testée ailleurs).
    """
    import subprocess

    import analyser
    import mission as MS
    import pipeline

    cible = RACINE / "testrepo_sca"

    # ------------------------------------------------- G1-G4 parsing des options
    o, reste = analyser._options_depuis_argv(["depot", "--confiance=untrusted"])
    cas("G1. --confiance=untrusted : valeur lue, positionnels intacts",
        o.get("confiance") == "untrusted" and reste == ["depot"], f"{o} {reste}")
    o, reste = analyser._options_depuis_argv(["depot", "ma requête",
                                              "--confiance", "untrusted"])
    cas("G2. --confiance untrusted (forme espacée) : la requête n'avale pas la valeur",
        o.get("confiance") == "untrusted" and reste == ["depot", "ma requête"],
        f"{o} {reste}")
    o, reste = analyser._options_depuis_argv(["depot"])
    cas("G3. aucune option --confiance : défaut « controlled » (compatibilité appelants)",
        o.get("confiance") is None and reste == ["depot"], f"{o} {reste}")
    try:
        analyser._options_depuis_argv(["depot", "--confiance=tromperie"])
        cas("G4. valeur de confiance inconnue : ERREUR immédiate, aucun repli", False,
            "aucune exception levée")
    except ValueError as e:
        cas("G4. valeur de confiance inconnue : ERREUR immédiate, aucun repli",
            "controlled" not in str(e) or "untrusted" in str(e), str(e)[:90])
    try:
        analyser._options_depuis_argv(["depot", "--confiance"])
        cas("G5. --confiance sans valeur : ERREUR (pas de valeur par défaut muette)",
            False, "aucune exception levée")
    except ValueError as e:
        cas("G5. --confiance sans valeur : ERREUR (pas de valeur par défaut muette)",
            True, str(e)[:90])

    # --moteur : la forme espacée est documentée dans README_USAGE.md:14. Mesurée
    # fausse avant ce chantier : `--moteur deterministe` donnait moteur=llm ET
    # laissait « deterministe » comme requête. Corrigée par le même extracteur.
    o, reste = analyser._options_depuis_argv(["depot", "--moteur", "deterministe"])
    cas("G6. --moteur deterministe (forme espacée documentée) : valeur lue, requête propre",
        o.get("moteur") == "deterministe" and reste == ["depot"], f"{o} {reste}")
    o, _ = analyser._options_depuis_argv(["depot", "--moteur"])
    cas("G7. --moteur nu : « llm » conservé (comportement historique, non cassé)",
        o.get("moteur") == "llm", f"{o}")

    # ------------------------------------- G8-G9 le drapeau atteint le pipeline
    capture: dict = {}
    reel = pipeline.executer
    pipeline.executer = _faux_executer(capture)
    try:
        code, r = analyser.lancer("Analyse la sécurité de mon dépôt", cible,
                                  moteur="deterministe", confiance="untrusted")
        cas("G8. analyser.lancer(confiance='untrusted') transmet confiance_cible au pipeline",
            capture.get("confiance_cible") == "untrusted"
            and r.get("confiance_cible") == "untrusted" and code == 2,
            f"capture={capture.get('confiance_cible')} resume={r.get('confiance_cible')} code={code}")
        code = analyser.main(["analyser.py", str(cible), "Analyse les dépendances",
                             "--confiance=untrusted"])
        cas("G9. chemin CLI complet (main) : la valeur arrive au pipeline et le refus est rendu",
            capture.get("confiance_cible") == "untrusted"
            and code == 2, f"capture={capture} code={code}")
    finally:
        pipeline.executer = reel

    # ------------------------ G10 la valeur est enregistrée dans le dossier de mission
    n_avant = len(list(MS.MISSIONS.glob("m-*"))) if MS.MISSIONS.is_dir() else 0
    code = analyser.main(["analyser.py", str(cible), "--confiance=valeur_impossible"])
    n_apres = len(list(MS.MISSIONS.glob("m-*"))) if MS.MISSIONS.is_dir() else 0
    cas("G10. CLI + confiance invalide : code 1, AUCUN dossier de mission créé",
        code == 1 and n_apres == n_avant, f"code={code} missions {n_avant}→{n_apres}")

    # On ne cherche PAS « un journal qui contient untrusted » : le précédent run en
    # laisserait un, et le cas vert ne prouverait plus rien. On ne regarde que les
    # dossiers CRÉÉS par cet appel.
    avant = set(MS.MISSIONS.glob("m-*")) if MS.MISSIONS.is_dir() else set()
    try:
        pipeline.executer("Analyse la sécurité de mon dépôt", cible,
                          confiance_cible="untrusted")
    except Exception as e:                       # noqa: BLE001 — OPA/outil absent ici :
        erreur = e                                # la consigne précède la policy, elle passe.
    else:
        erreur = None
    nouveaux = sorted(set(MS.MISSIONS.glob("m-*")) - avant)
    trouve = next((ligne for d in nouveaux
                   for ligne in (d / "journal.jsonl").read_text(encoding="utf-8").splitlines()
                   if '"confiance"' in ligne and '"untrusted"' in ligne), None)
    cas("G11. le journal append-only de la mission enregistre la confiance appliquée",
        trouve is not None,
        f"{len(nouveaux)} nouveau(x) dossier(s) de mission · "
        f"erreur pendant l'exécution={type(erreur).__name__ if erreur else None}")

    # ------------------------------- G12 la bibliothèque refuse aussi, pas que la CLI
    try:
        pipeline.executer("Analyse la sécurité de mon dépôt", cible,
                          confiance_cible="probably-fine")
        cas("G12. pipeline.executer(confiance inconnue) lève — aucun repli silencieux",
            False, "aucune exception levée")
    except pipeline.PipelineError as e:
        cas("G12. pipeline.executer(confiance inconnue) lève — aucun repli silencieux",
            "controlled" in str(e) and "untrusted" in str(e), str(e)[:110])

    # ---------------- G12b les DEUX conditions du refus sont réunies dans l'entrée d'OPA
    # Sans le binaire `opa`, on ne peut pas rejouer la décision — mais on peut prouver
    # que le document soumis à OPA porte ce que la règle regarde : la confiance de la
    # cible ET le fait que la mémoire n'est pas bornée. C'est la moitié vérifiable
    # partout de G13 ; la règle elle-même est testée par test_intentions.py:126-133.
    import policy as PO

    capture_entree: dict = {}

    class MoteurEspion(PO.PolicyEngine):
        def __init__(self, *a, **kw):            # pas de binaire requis : espion
            pass

        def evaluer(self, plan, registre, cible_autorisee,
                    confiance_cible="controlled", profil=None):
            capture_entree["doc"] = PO.PolicyEngine.entree(
                plan, registre, cible_autorisee, confiance_cible, profil)
            # Refus volontaire : on veut lire le document soumis, pas lancer les outils.
            return PO.Decision(allow=False, motifs=("espion_entree_opa",))

    reel_moteur = PO.PolicyEngine
    PO.PolicyEngine = MoteurEspion
    try:
        analyser.main(["analyser.py", str(cible), "Analyse la sécurité de mon dépôt",
                       "--confiance=untrusted", "--moteur=deterministe"])
    except Exception:                            # noqa: BLE001 — sandbox/outil absent ici,
        pass                                     # et c'est APRÈS la policy dans ce cas.
    finally:
        PO.PolicyEngine = reel_moteur

    doc = capture_entree.get("doc") or {}
    cas("G12b. entrée soumise à OPA : confiance untrusted + mémoire non bornée (les deux conditions)",
        (doc.get("cible") or {}).get("confiance") == "untrusted"
        and doc.get("profil_sandbox", {}).get("memoire_bornee") is False,
        f"cible={doc.get('cible')} memoire_bornee={doc.get('profil_sandbox', {}).get('memoire_bornee')}")

    # ------------------------- G15 contrat de noms profils.py ↔ policy.rego (sans binaire)
    # Le jour où un seul des deux côtés change un nom, la garde cesse de lire ce qu'elle
    # croit lire — et côté OPA, un champ absent ne lève rien : `not <indéfini>` vaut vrai.
    # C'est exactement ce qui s'est passé (mesure 2026-08-30) : le profil émettait
    # `memory_bounded`, la politique lisait `memoire_bornee`. Ce cas rend la classe
    # d'erreur impossible, pour TOUS les champs lus, pas seulement ceux-là.
    import re as _re

    import profils
    rego = (RACINE / "policy" / "policy.rego").read_text(encoding="utf-8")
    champs_lus = set(_re.findall(r"input\.profil_sandbox\.([a-z_]+)", rego))
    champs_produits = set(profils.actif().to_dict())
    cas("G15. tout champ de profil lu par policy.rego est produit par profils.to_dict()",
        bool(champs_lus) and champs_lus <= champs_produits,
        f"lus={sorted(champs_lus)} · manquants={sorted(champs_lus - champs_produits)}")

    # ---------------------------- G13-G14 effet RÉEL sur la décision (exige opa)
    from sandbox import CACHE_BIN
    if not (CACHE_BIN / "opa").exists():
        cas_non_evalue("G13. cible untrusted + mémoire non bornée → REFUS réel (policy)",
                       f"binaire opa absent : {CACHE_BIN / 'opa'}")
        cas_non_evalue("G14. même plan en controlled → le motif mémoire n'apparaît pas",
                       "idem")
        return

    # Requête volontairement étroite (« secrets » → un provider) : le refus se joue à la
    # policy, donc une requête bon marché suffit — et G14, qui n'est PAS refusé, reste
    # rapide sur la machine source.
    code, r = analyser.lancer("Cherche des secrets exposés", cible,
                              moteur="deterministe", confiance="untrusted")
    cas("G13. cible untrusted + mémoire non bornée → REFUS réel (policy)",
        code == 2 and "memoire_non_bornee_cible_non_fiable" in (r.get("motif") or "")
        and not r.get("rapport"),
        f"code={code} motif={r.get('motif')}")

    # Contrôle : mêmes limites, confiance « controlled » → PAS de refus mémoire.
    # Sur une machine sans outils, l'exécution échoue plus loin (sandbox) : c'est la
    # preuve que la policy n'a pas refusé. Les deux issues sont donc satisfaisantes.
    r: dict = {}
    try:
        code, r = analyser.lancer("Cherche des secrets exposés", cible,
                                  moteur="deterministe", confiance="controlled")
        ok = not ("memoire_non_bornee_cible_non_fiable" in (r.get("motif") or "")
                  and r.get("statut") == "policy")
    except Exception as e:                       # noqa: BLE001 — exécution non disponible
        ok = "memoire_non_bornee" not in str(e)
    cas("G14. même plan en controlled → le motif mémoire n'apparaît pas", ok,
        f"statut={r.get('statut')}")


def main() -> int:
    import analyser
    import intent as I
    import mission as MS
    from registre import Registry

    reg = Registry()

    # ------------------------------------------- A. point d'entrée (e2e réel)
    code, r = analyser.lancer("Analyse la sécurité de mon dépôt",
                              RACINE / "testrepo_sca")
    sortie = Path(r.get("sortie") or "")
    # 124 = 62 trivy + 62 grype (fan-out SCA). La fixture porte aussi un
    # ATTENDUS.yaml : kics/checkov y contribuent légitimement (observation O3
    # du dogfooding) — d'où le seuil et non l'égalité stricte.
    cas("A1. mission complète : code 0, au moins 124 findings (62 trivy + 62 grype)",
        code == 0 and r.get("findings", 0) >= 124 and r.get("clusters_inter_outils") == 6,
        f"code={code} findings={r.get('findings')} inter={r.get('clusters_inter_outils')}")
    cas("A2. sortie archivée sous la mission (RAPPORT.md + plan + raw)",
        sortie.is_dir() and (sortie / "RAPPORT.md").exists()
        and (sortie / "plan.json").exists()
        and any(sortie.glob("raw_*.json")),
        str(sortie))
    cas("A3. la sortie est bien rattachée au dossier de mission append-only",
        sortie.parent == MS.MISSIONS / r.get("mission", "")
        and (MS.MISSIONS / r["mission"]).exists(), str(sortie))

    # ------------------------------------------- B. non-écrasement
    code2, r2 = analyser.lancer("Vérifie mes dépendances", RACINE / "testrepo_sca")
    s2 = Path(r2.get("sortie") or "")
    cas("B1. deux missions = deux sorties distinctes, aucune écrasée",
        code2 == 0 and s2 != sortie and (sortie / "RAPPORT.md").exists()
        and (s2 / "RAPPORT.md").exists(), f"{sortie} vs {s2}")

    # ------------------------------------------- C. arrêts (rien n'est exécuté)
    code3, r3 = analyser.lancer("Est-ce que ça marche ?", RACINE / "testrepo_sca")
    cas("C1. clarification : code 2, question lisible, aucune exécution",
        code3 == 2 and r3.get("statut") == "needs_clarification"
        and bool(r3.get("question")) and not r3.get("rapport"), f"{r3}")
    code4, r4 = analyser.lancer("Attaque 10.0.0.5", RACINE / "testrepo_sca")
    cas("C2. demande interdite : code 2, refus motivé, aucune exécution",
        code4 == 2 and r4.get("statut") == "rejected" and bool(r4.get("motif")),
        f"{r4}")

    # ------------------------------------------- D. F2 domaine > générique
    it_tf = I.inferer("Analyse mon code Terraform", reg)
    cas("D1. « Analyse mon code Terraform » : IaC + code, PAS les 5 capacités",
        set(it_tf.capabilities) == {"CODE_STATIC_ANALYSIS", "IAC_SCAN"},
        f"{sorted(it_tf.capabilities)}")
    it_gen = I.inferer("Analyse la sécurité de mon dépôt", reg)
    # « publiée » et « générique » sont deux attributs DISTINCTS, et ce test les
    # confondait : `publiques()` dit ce que l'interface PROPOSE, `generique` dit ce
    # qu'une demande qui ne nomme aucun domaine DÉCLENCHE. Un linter (CODE_LINT), une
    # métrique de complexité (CODE_METRICS) ou une analyse JS sont proposés à l'opérateur
    # mais ne partent pas sur « analyse mon dépôt » — c'est délibéré et déclaré par
    # capacité dans `capabilities.yaml`. Attendre l'égalité avec les capacités publiées
    # revenait à exiger qu'une analyse de sécurité lance un linter.
    # L'attendu est donc DÉRIVÉ du registre, jamais recopié.
    publiees = {p.id for p in reg.publiques()}
    attendu = {c.id for c in reg.capabilities()
               if c.id in publiees and getattr(c, "generique", False)}
    cas("D2. une demande générique déclenche les capacités déclarées génériques",
        set(it_gen.capabilities) == attendu,
        f"attendu={sorted(attendu)} obtenu={sorted(it_gen.capabilities)}")

    # ------------------------------------------- E. F3 clarification publique
    it_q = I.inferer("zzz phrase sans aucun mot clé zzz", reg)
    q = it_q.question or ""
    internes = {c.id for c in reg.capabilities() if c.interne}
    cas("E1. la clarification ne liste AUCUNE capacité interne",
        bool(q) and not any(i in q for i in internes), q[:120])
    it_qi = I.inferer("zzz phrase sans aucun mot clé zzz", reg, avec_internes=True)
    cas("E2. avec_internes=True (contrat des tests) : les internes restent listées",
        any(i in (it_qi.question or "") for i in internes))

    # ------------------------------------------- F. LLM pilote (hors-ligne, mock)
    from fournisseurs_llm import MockLLM
    mock = MockLLM("normal", nom="mock-test")
    code5, r5 = analyser.lancer("Analyse la sécurité de mon dépôt",
                                RACINE / "testrepo_sca",
                                moteur="llm", fournisseur=mock)
    # moteur est tracé « llm:<fournisseur> » (mesuré : llm:mock-test) — le suffixe
    # nomme le fournisseur, c'est une information, pas une déviation.
    cas("F1. LLM branché : moteur=llm tracé, mission complète",
        code5 == 0 and str(r5.get("moteur", "")).startswith("llm")
        and r5.get("findings", 0) >= 124,
        f"moteur={r5.get('moteur')} findings={r5.get('findings')}")
    descriptions = " ".join(a["description"] for a in mock.appels)
    # La liste des noms d'outils était écrite à la main (huit noms). Elle ne pouvait donc
    # rien attraper de ce qui n'y figurait pas — et « radon », « ruff », « eslint » et
    # « npm » fuyaient tranquillement dans les descriptions de capacités, en violation de
    # la règle que `intent_llm` énonce lui-même : « il ne voit QUE la description des
    # capacités — jamais un nom d'outil, un chemin, un argument ».
    # DÉFAUT RÉEL corrigé le 31/08/2026 : les descriptions de CODE_LINT, CODE_METRICS,
    # CODE_STATIC_ANALYSIS_JS et DEPENDENCY_ANALYSIS_JS nommaient leur outil.
    # La liste est désormais DÉRIVÉE du registre — provider, binaire déclaré, exécutable.
    noms_outils = set()
    for p in reg.providers():
        noms_outils.add(p.id)
        mani = getattr(p, "manifest", None)
        if mani is not None and getattr(mani, "binaire", ""):
            noms_outils.add(str(mani.binaire))
        if getattr(p, "commande", None):
            noms_outils.add(Path(str(p.commande[0])).name)
    noms_outils.discard("")
    marqueurs = {"/home/", "argv", "{TARGET}", "{BIN}", "CACHE"}
    fuites = sorted(n for n in (noms_outils | marqueurs)
                    if n and n.lower() in descriptions.lower())
    cas("F2. aucun nom d'outil ni chemin n'est transmis au LLM",
        not fuites, f"trouves : {fuites} · extrait : {descriptions[:120]}")
    for comportement in ("invente_capacite", "nomme_outil", "plante"):
        bad = MockLLM(comportement, nom=f"mock-{comportement}")
        codeX, rX = analyser.lancer("Vérifie mes dépendances",
                                    RACINE / "testrepo_sca",
                                    moteur="llm", fournisseur=bad)
        # L'invariant de ce cas est le REPLI TRACÉ : « le LLM a déraillé, le déterministe
        # a pris la main, et la mission le DIT » — c'est la seule chose qu'il mesure.
        # La santé de la mission (`code == 0`, `findings > 0`) dépend d'un fait machine :
        # « Vérifie mes dépendances » ne peut rien exécuter ici — trivy et grype sont
        # absents, pip-audit est écarté parce que la cage coupe la sortie. L'exiger
        # transformait une panne d'environnement en échec de la logique de repli.
        cas(f"F3. LLM {comportement} : repli déterministe TRACÉ, motif nommé",
            str(rX.get("moteur", "")).startswith("deterministe")
            and "repli" in str(rX.get("moteur", "")),
            f"moteur={rX.get('moteur')}")

    # Le pipeline ne doit pas rester en mode llm après les tests.
    import pipeline
    pipeline.MOTEUR_INTENT = "deterministe"
    pipeline.FOURNISSEUR_LLM = None

    bloc_confiance()

    for nom, ok, detail in CAS:
        print(f"  [{'OK' if ok else 'ECHEC'}] {nom}" + (f"  — {detail}" if detail and not ok else ""))
    for nom, motif in NON_EVALUES:
        print(f"  [NON EVALUE] {nom}  — {motif}")
    passes = len(CAS) - len(ECHECS)
    print(f"\ntest_utilisation : {passes}/{len(CAS)} cas passés"
          + (f" · {len(NON_EVALUES)} non évalués" if NON_EVALUES else "")
          + (f" · {len(ECHECS)} échec(s)" if ECHECS else ""))
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
