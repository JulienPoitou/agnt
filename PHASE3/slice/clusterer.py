"""Clustering v0 — et non « corrélation ».

Le terme est volontairement modeste. Ce module ne prétend pas corréler des sources
hétérogènes : il regroupe des findings selon des règles EXPLICITES et dit quand il
ne sait pas.

Règle cardinale : ne jamais forcer un regroupement pour que la démo tombe juste.
Si 62 vulnérabilités distinctes sur 6 paquets donnent 6 groupes et 2 singletons,
alors c'est 6 groupes et 2 singletons — pas 3 parce que ce serait plus joli.

Chaque cluster expose ses raisons. Un regroupement inexplicable est un regroupement
faux.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

PROXIMITE_LIGNES = 3


@dataclass
class Cluster:
    cluster_id: str
    raison: list[str]
    membres: list[str]
    confiance: str
    cle: str = ""

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "confidence": self.confiance,
            "reason": self.raison,
            "members": self.membres,
            "cle": self.cle,
        }


def _regles(findings: list) -> list[tuple[str, list[str], str]]:
    """Retourne (clé de regroupement, raisons, confiance) par finding.

    Une règle s'applique ou non ; la première qui regroupe effectivement gagne.
    """
    par_paquet = defaultdict(list)
    for f in findings:
        pkg = (f.location or {}).get("package")
        if pkg:
            par_paquet[pkg].append(f.id)

    paquets_multiples = {p for p, ids in par_paquet.items() if len(ids) > 1}
    par_fichier = defaultdict(list)
    for f in findings:
        fic = (f.location or {}).get("file")
        if fic:
            par_fichier[fic].append(f)

    # 2. même fichier ET zone proche — union-find sur le voisinage de lignes.
    #    Une clé de type ligne//N scinderait des lignes réellement proches (9 et 12
    #    tombent dans des blocs différents pour N=3), et un ancrage « premier voisin »
    #    ne fusionnerait pas de façon transitive. D'où l'union-find.
    parent: dict[str, str] = {f.id: f.id for f in findings}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    for fic, groupe in par_fichier.items():
        for i in range(len(groupe)):
            for j in range(i + 1, len(groupe)):
                la = groupe[i].location.get("line")
                lb = groupe[j].location.get("line")
                if la is not None and lb is not None and abs(la - lb) <= PROXIMITE_LIGNES:
                    union(groupe[i].id, groupe[j].id)

    fichiers_multiples = {k for k, v in par_fichier.items() if len(v) > 1}

    # --------------------------------------------------------------------------
    # RÈGLE same_dependency_usage — le lien CVE ↔ usage.
    #
    # Deux familles, et le lien n'existe que si les DEUX sont présentes :
    #   · CVE sur un paquet              (déclarée par l'outil de dépendances)
    #   · usage dangereux de CE paquet   (déduit de la règle de l'outil de code,
    #                                     via le mapping extrait des métadonnées)
    #
    # Exigence explicite : « CVE sur paquet X + n'importe quel finding → cluster » est
    # INTERDIT. Un XSS de template n'a rien à voir avec une CVE Flask. C'est le mapping
    # qui décide, et une règle non mappée ne produit aucun lien.
    #
    # La comparaison de paquets est insensible à la casse : Trivy renvoie « Flask » tel
    # qu'écrit dans requirements.txt, le mapping renvoie « flask ».
    # --------------------------------------------------------------------------
    def _outil(f) -> str:
        return (f.source or {}).get("tool") or ""

    # Préfixes d'IDENTIFIANTS DE VULNÉRABILITÉ. Pas seulement CVE- : grype 0.118
    # identifie en GHSA-* (mesuré sur testrepo_sca — 62/62 findings GHSA, 0 CVE).
    # Sans GHSA- ici, les findings grype tombaient dans la famille « usage » et
    # déclenchaient un same_dependency_usage FAUX (deux outils de dépendances,
    # aucun usage de code). Élargir le prédicat corrige une mesure fausse.
    PREFIXES_VULN = ("CVE-", "GHSA-")

    cve_par_paquet: dict[str, list] = defaultdict(list)
    for f in findings:
        pkg = (f.location or {}).get("package")
        rid = ((f.source or {}).get("original_rule_id") or "").upper()
        if pkg and rid.startswith(PREFIXES_VULN):
            cve_par_paquet[str(pkg).lower()].append(f)

    usage_par_paquet: dict[str, list] = defaultdict(list)
    for f in findings:
        pkg = (f.location or {}).get("package")
        rid = ((f.source or {}).get("original_rule_id") or "").upper()
        if pkg and not rid.startswith(PREFIXES_VULN):
            usage_par_paquet[str(pkg).lower()].append(f)

    paquets_lies = set(cve_par_paquet) & set(usage_par_paquet)

    out = []
    for f in findings:
        loc = f.location or {}
        pkg = loc.get("package")
        fic = loc.get("file")
        rid = (f.source or {}).get("rule_id") or ""
        cle_pkg = str(pkg).lower() if pkg else ""
        # `rule_id` est None pour Semgrep comme pour Trivy : l'identifiant réel est dans
        # `original_rule_id`. Utiliser `rule_id` faisait tomber les CVE dans le mauvais
        # sous-cluster (libellé « usage » au lieu de « cve »).
        rid_orig = ((f.source or {}).get("original_rule_id") or "").upper()
        est_cve = rid_orig.startswith(PREFIXES_VULN)

        # 1. Dépendance liée : CVE + usage dangereux du MÊME paquet, dans UN seul cluster.
        #
        # Les séparer en « cve:X » et « usage:X » rendait le lien implicite et faisait
        # disparaître le marqueur cross_tool. Un seul cluster rend le lien explicite :
        # c'est exactement ce que la corrélation doit produire.
        if cle_pkg and cle_pkg in paquets_lies:
            out.append((f"dependance:{cle_pkg}",
                        ["same_dependency_usage", "related_dependency",
                         "same_package", "cross_tool"],
                        "high"))
            continue
        # 2. même paquet / dépendance — regroupement simple, sans lien CVE ↔ usage.
        if pkg and pkg in paquets_multiples:
            out.append((f"paquet:{pkg}", ["same_package", "related_dependency"], "high"))
            continue
        # 2. même fichier ET zone proche.
        if fic and fic in fichiers_multiples:
            racine = find(f.id)
            a_voisin = any(g.id != f.id and find(g.id) == racine for g in par_fichier[fic])
            if a_voisin:
                out.append((f"fichier:{fic}#zone:{racine}",
                            ["same_asset", "same_file", "ligne_proche"], "medium"))
                continue
            out.append((f"fichier:{fic}", ["same_asset", "same_file"], "medium"))
            continue
        # 3. même règle exacte.
        if rid:
            out.append((f"regle:{rid}", ["same_rule"], "low"))
            continue
        # 4. sinon : on ne regroupe pas.
        out.append((f"seul:{f.id}", [], "none"))
    return out


def _outils(membres: list[str], par_id: dict) -> set:
    return {par_id[m].source.get("tool") for m in membres if m in par_id}


def regrouper(findings: list) -> dict:
    """Regroupe les findings et RENDE COMPTE de ce qu'il n'a pas su regrouper."""
    groupes: dict[str, list[str]] = defaultdict(list)
    raisons: dict[str, list[str]] = {}
    confiance: dict[str, str] = {}

    for f, (cle, rs, conf) in zip(findings, _regles(findings)):
        groupes[cle].append(f.id)
        raisons[cle] = rs
        confiance[cle] = conf

    par_id = {f.id: f for f in findings}
    clusters = []
    non_regroupe = []
    n = 0
    for cle, ids in groupes.items():
        if len(ids) == 1 and cle.startswith("seul:"):
            non_regroupe.append(ids[0])
            continue
        n += 1
        rs = list(raisons[cle])
        outils = _outils(ids, par_id)
        # Un cluster qui mêle plusieurs outils est une corrélation INTER-OUTILS.
        # Ce n'est pas une « vulnérabilité confirmée » : c'est une relation entre
        # observations, produites par des outils différents, sur un même sujet.
        if len(outils) > 1:
            if "cross_tool" not in rs:
                rs = ["cross_tool"] + rs
            rs = rs + [f"tools:{'+'.join(sorted(outils))}"]
        # Déduplication en préservant l'ordre : une raison peut venir à la fois de la
        # règle de regroupement et de la détection multi-outils.
        rs = list(dict.fromkeys(rs))
        clusters.append(Cluster(
            cluster_id=f"CL-{n:03d}",
            raison=rs,
            membres=ids,
            confiance=confiance[cle],
            cle=cle,
        ))

    clusters.sort(key=lambda c: (-len(c.membres), c.cluster_id))
    for i, c in enumerate(clusters, 1):
        c.cluster_id = f"CL-{i:03d}"

    total = len(findings)
    inter = [c.to_dict() for c in clusters if "cross_tool" in c.raison]
    return {
        "clusters": [c.to_dict() for c in clusters],
        "clusters_inter_outils": inter,
        "non_regroupe": non_regroupe,
        "stats": {
            "findings_en_entree": total,
            "clusters": len(clusters),
            "findings_regroupes": total - len(non_regroupe),
            "findings_non_regroupes": len(non_regroupe),
            # Affiché explicitement : regrouper n'est pas réduire à tout prix.
            "reduction": f"{total} → {len(clusters) + len(non_regroupe)}",
        },
    }

