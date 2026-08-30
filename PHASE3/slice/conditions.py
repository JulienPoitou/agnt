"""Conditions d'exécution déclarées par l'outil, vérifiées AVANT le premier Popen.

Le défaut que ce module ferme est le plus grave qui reste au produit : un outil qui a
besoin de réseau (base de vulnérabilités à télécharger, hôte à interroger) exécuté dans
une cage qui coupe le réseau (`--unshare-net`, invariant du projet) ne dit pas « je n'ai
pas pu » — beaucoup de ces outils rendent alors un résultat VIDE avec le code 0. Le
rapport dirait « 0 vulnérabilité » sur la foi d'un scan qui n'a rien pu charger. Une
régression de détection se présente donc comme une amélioration.

Deux barrières, et c'est voulu qu'elles soient deux :

  1. au PLAN (ici) : le provider n'est même pas proposé, avec un motif qui finit dans
     `plan.json` et dans le ledger des six étapes (`statuts.py`) — « non applicable »,
     pas « 0 trouvé » ;
  2. à l'EXÉCUTION (`adapters._lance`) : la cage est jugée sur la commande RÉELLEMENT
     construite, pas sur la déclaration du profil. Un `--providers` passé en ligne de
     commande, un appel direct d'un adaptateur, ou un profil qui mentirait, tombent là.

Ce que le cœur ne fait pas : il ne devine aucune condition. Un provider sans manifest, ou
avec un manifest qui ne déclare rien, reste éligible — une fausse exclusion coûte plus
cher qu'un `not_scanned` honnête (même doctrine que `plan.filtrer_applicabilite`).
"""

from __future__ import annotations

from pathlib import Path

# Vocabulaire fermé : une condition mal orthographiée doit être REFUSÉE au chargement,
# jamais ignorée. `resau:` ou `reseaun:` annulerait la garde sans le moindre message.
CLES = ("reseau", "base_fichiers", "timeout_s", "privileges")

# `aucun` est la seule valeur admise en Phase 3 : AGNT ne s'élève jamais. Le dire ici
# vaut refus au chargement plutôt qu'échec à l'exécution.
PRIVILEGES = ("aucun",)

# Plafond dur d'un timeout déclaré, quel que soit le profil : un manifest ne peut pas
# demander une heure parce qu'un outil est mal écrit (démarrage lent, retry réseau).
PLAFOND_S = 1800


def valider(doc: dict) -> dict:
    """Contrôle la forme du bloc `conditions` et rend un dictionnaire normalisé.

    Levé par `provider_manifest.valider` : un manifest ambigu ne doit jamais atteindre
    l'exécution.
    """
    brut = doc.get("conditions")
    if brut is None:
        return {"reseau": False, "base_fichiers": (), "timeout_s": 0, "privileges": "aucun"}
    if not isinstance(brut, dict):
        raise ValueError(f"{doc.get('id')}: 'conditions' doit être un objet, pas {type(brut).__name__}")
    inconnues = [k for k in brut if k not in CLES]
    if inconnues:
        raise ValueError(
            f"{doc.get('id')}: conditions inconnues {inconnues} — admises : {list(CLES)}. "
            "Une condition mal orthographiée désarmerait la garde sans message : refusée.")
    reseau = brut.get("reseau", False)
    if not isinstance(reseau, bool):
        raise ValueError(f"{doc.get('id')}: 'reseau' doit être vrai ou faux")
    bases = brut.get("base_fichiers") or []
    if not isinstance(bases, (list, tuple)):
        raise ValueError(f"{doc.get('id')}: 'base_fichiers' doit être une liste de chemins relatifs")
    for b in bases:
        if not isinstance(b, str) or not b:
            raise ValueError(f"{doc.get('id')}: 'base_fichiers' porte {b!r} — chemins textuels requis")
        p = Path(b)
        if p.is_absolute() or ".." in p.parts or b.startswith("~"):
            raise ValueError(
                f"{doc.get('id')}: base déclarée {b!r} hors de la racine des bases "
                "(chemin relatif requis) — une base absolute serait un chemin d'hôte "
                "écrit dans un manifest non fiable")
    t = brut.get("timeout_s", 0)
    if isinstance(t, bool) or not isinstance(t, int) or t < 0 or t > PLAFOND_S:
        raise ValueError(
            f"{doc.get('id')}: 'timeout_s' doit être un entier entre 0 et {PLAFOND_S} "
            f"(0 = défaut du profil), pas {t!r}")
    priv = brut.get("privileges", "aucun")
    if priv not in PRIVILEGES:
        raise ValueError(
            f"{doc.get('id')}: privileges {priv!r} refusé — AGNT n'élève jamais de "
            f"privilège (admis : {list(PRIVILEGES)})")
    return {"reseau": reseau, "base_fichiers": tuple(bases), "timeout_s": int(t),
            "privileges": priv}


def declarees(prov) -> dict:
    """Les quatre conditions d'un provider, sous une forme unique.

    Deux origines, et il le fallait : un provider DÉCLARATIF porte ses conditions dans
    son `manifest` (validées au chargement par `provider_manifest`), un provider à
    ADAPTATEUR HISTORIQUE (semgrep, trivy, gitleaks — pas de manifest du tout) les porte
    au niveau du provider, validées ici par le registre. Sans cette seconde origine, la
    seule garde qui compte pour Trivy — sa base pré-peuplée — serait restée du texte
    mort dans le YAML. Mesuré le 2026-08-30 en écrivant le test : `prov.manifest` vaut
    None pour Trivy, donc un filtre qui ne lit que le manifest ne voyait rien.
    """
    m = getattr(prov, "manifest", None)
    if m is not None:
        return {"reseau": bool(getattr(m, "reseau", False)),
                "base_fichiers": tuple(getattr(m, "base_fichiers", ()) or ()),
                "timeout_s": int(getattr(m, "timeout_s", 0) or 0),
                "privileges": str(getattr(m, "privileges", "aucun") or "aucun")}
    d = dict(getattr(prov, "conditions", None) or {})
    return {"reseau": bool(d.get("reseau", False)),
            "base_fichiers": tuple(d.get("base_fichiers") or ()),
            "timeout_s": int(d.get("timeout_s", 0) or 0),
            "privileges": str(d.get("privileges", "aucun") or "aucun")}


def egress_de(sbx, argv: list[str]) -> bool:
    """Le réseau est-il réellement laissé à l'outil ? Jugé sur la commande construite.

    On ne lit pas `sbx.unshare_net` (attribut inexistant) ni la declaration du profil :
    on regarde ce qui sera passé à bwrap. Si `--unshare-net` disparaissait du
    `commande()`, la réponse basculerait — c'est ce qu'on veut, et c'est mesurable.
    """
    try:
        cmd = [str(x) for x in sbx.commande(list(argv))]
    except Exception:                                     # noqa: BLE001 - cage injoignable
        return False
    return "--unshare-net" not in cmd


def manquantes(prov, *, egress: bool, racine_db: Path | str, plafond_s: int = PLAFOND_S) -> list[str]:
    """Motifs, vides si le provider peut rendre un résultat FAISABLE dans ces conditions."""
    m = declarees(prov)
    motifs: list[str] = []
    if m["reseau"] and not egress:
        motifs.append(
            "réseau requis par l'outil, cage sans egress : l'outil rendrait un résultat "
            "vide avec le code 0 (refusé pour ne pas produire de faux « rien trouvé »)")
    racine = Path(racine_db) if racine_db else None
    for b in m["base_fichiers"]:
        # .exists() et non .is_file() : une base est tantôt un fichier (SQLite de
        # grype), tantôt un répertoire (trivy/db). Exiger l'un des deux rendrait la
        # déclaration fausse selon l'outil — et un faux négatif ici serait un scan vide.
        if racine is None or not (racine / b).exists():
            motifs.append(f"base déclarée absente : {racine_db}/{b} (lancer bootstrap.sh)")
    return motifs


def timeout_effectif(prov, plafond_s: int) -> tuple[int, str]:
    """(secondes à employer, note de limitation ou ""). Le plafond du profil GAGNE."""
    demande = declarees(prov)["timeout_s"]
    if demande <= 0:
        return int(plafond_s), ""
    if demande > plafond_s:
        return int(plafond_s), (
            f"timeout déclaré {demande}s ramené au plafond du profil {plafond_s}s "
            f"(un manifest ne relève pas le plafond; plafonné par `conditions.PLAFOND_S`={PLAFOND_S}s)")
    return demande, ""


def filtrer(providers: list[str], registre, *, egress: bool,
            racine_db: Path | str) -> tuple[list[str], dict[str, str]]:
    """Écarte avant le plan les providers dont les conditions ne sont pas remplies."""
    eligibles, exclus = [], {}
    for pid in providers:
        try:
            prov = registre.provider(pid)
        except Exception:                                 # noqa: BLE001 - inconnu : on ne tranche pas ici
            eligibles.append(pid)
            continue
        motifs = manquantes(prov, egress=egress, racine_db=racine_db)
        if motifs:
            exclus[pid] = " ; ".join(motifs)
        else:
            eligibles.append(pid)
    return eligibles, exclus
