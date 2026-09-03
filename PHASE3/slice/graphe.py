"""Graphe de sécurité : modèle de données + relations (Stream H, fondation).

Pas de base distribuée : des nœuds typés en mémoire, des liens nommés, une
déduplication par empreinte. Règle centrale : deux outils qui observent le
même fait (même règle canonique + même coordonnée) partagent UN nœud finding
et gardent leurs sources — la convergence est un FAIT du graphe, pas un avis.

Types : target, asset, execution, provider, finding, evidence, verification,
remediation. Relations : observe, prouve, execute, fournit, verifie, corrige,
converge, expose.
"""
from __future__ import annotations

TYPES = ("target", "asset", "execution", "provider", "finding",
         "evidence", "verification", "remediation")


class ErreurGraphe(Exception):
    """Nœud ou lien invalide, nommés."""


class Graphe:
    def __init__(self) -> None:
        self.noeuds: dict[tuple[str, str], dict] = {}
        self.liens: list[dict] = []

    def ajouter_noeud(self, type: str, id: str, attrs: dict | None = None) -> dict:
        if type not in TYPES:
            raise ErreurGraphe(f"type inconnu : {type!r} — admis : {list(TYPES)}")
        if not id or not isinstance(id, str):
            raise ErreurGraphe("id de nœud vide")
        cle = (type, id)
        if cle in self.noeuds:
            existant = self.noeuds[cle]
            for k, v in (attrs or {}).items():
                if k not in existant["attrs"]:
                    existant["attrs"][k] = v
            return existant
        noeud = {"type": type, "id": id, "attrs": dict(attrs or {})}
        self.noeuds[cle] = noeud
        return noeud

    def ajouter_lien(self, de_type: str, de_id: str, relation: str,
                     vers_type: str, vers_id: str) -> dict:
        for t, i in ((de_type, de_id), (vers_type, vers_id)):
            if (t, i) not in self.noeuds:
                raise ErreurGraphe(f"lien vers nœud absent : {t}/{i}")
        if not relation or not isinstance(relation, str):
            raise ErreurGraphe("relation vide")
        lien = {"de": [de_type, de_id], "relation": relation,
                "vers": [vers_type, vers_id]}
        if lien not in self.liens:
            self.liens.append(lien)
        return lien

    def ajouter_finding(self, regle: str, coordonnee: tuple[str, str],
                        empreinte: str, sources: list[str],
                        attrs: dict | None = None) -> dict:
        """Un finding = (règle, coordonnée, empreinte). Même empreinte → même
        nœud, sources fusionnées (déduplication inter-outils)."""
        if not regle or not empreinte:
            raise ErreurGraphe("règle et empreinte exigées")
        noeud = self.ajouter_noeud("finding", empreinte,
                                   {"regle": regle, "asset": coordonnee[0],
                                    "valeur": coordonnee[1], **(attrs or {})})
        vues = set(noeud["attrs"].get("sources", [])) | set(sources)
        noeud["attrs"]["sources"] = sorted(vues)
        return noeud

    def relier_convergence(self) -> int:
        """Lie `converge` les findings partageant (règle, asset, valeur).
        Rend le nombre de liens créés."""
        crees = 0
        vus = list(self.noeuds.values())
        for i, a in enumerate(vus):
            if a["type"] != "finding":
                continue
            for b in vus[i + 1:]:
                if b["type"] != "finding" or a["id"] == b["id"]:
                    continue
                if (a["attrs"].get("regle") == b["attrs"].get("regle")
                        and a["attrs"].get("asset") == b["attrs"].get("asset")
                        and a["attrs"].get("valeur") == b["attrs"].get("valeur")):
                    self.ajouter_lien("finding", a["id"], "converge", "finding", b["id"])
                    crees += 1
        return crees

    def chemin_attaque(self, finding_id: str) -> list[dict]:
        """Chaîne finding → evidence → execution → provider + finding → target.
        Les maillons absents sont omis, jamais inventés."""
        if ("finding", finding_id) not in self.noeuds:
            raise ErreurGraphe(f"finding inconnu : {finding_id}")
        suivants: dict[str, list] = {}
        for l in self.liens:
            if l["de"] == ["finding", finding_id]:
                suivants.setdefault(l["relation"], []).append(l["vers"])
        ordre = ["prouve", "execute", "fournit", "expose", "corrige", "verifie"]
        chemin = [{"noeud": ["finding", finding_id]}]
        for rel in ordre:
            for vers in suivants.get(rel, []):
                if (vers[0], vers[1]) in self.noeuds:
                    chemin.append({"relation": rel, "noeud": vers})
        return chemin

    def to_dict(self) -> dict:
        return {"noeuds": sorted(
                    [{"type": t, "id": i, **n["attrs"]} for (t, i), n in self.noeuds.items()],
                    key=lambda n: (n["type"], n["id"])),
                "liens": self.liens}
