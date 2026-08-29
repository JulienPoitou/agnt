"""Normalisation des findings et identité canonique (décision D6).

Trois niveaux d'identité, et non un identifiant unique qui écraserait les autres :

    source_finding_id    trivy:CVE-2025-1234:/app/package-lock.json   (l'occurrence, par l'outil)
    canonical_rule_id    vulnerability:CVE-2025-1234                  (le problème logique)
    fingerprint          <empreinte stable>                           (l'occurrence concrète)

    Même problème logique  → même canonical_rule_id
    Même occurrence        → même fingerprint
    Outil différent        → source_finding_id différent

C'est ce qui permet à Semgrep, Trivy et Gitleaks de produire des résultats distincts
sans fabriquer artificiellement trois problèmes indépendants — ni, à l'inverse, de
fusionner des problèmes qui n'ont rien à voir.

Rappel vérifié : la même règle Semgrep a DEUX identifiants selon son origine
(préfixe `rules.` quand la règle vient d'un fichier local). Sans canonical_rule_id,
notre déduplication produirait des doublons.

Le RAW est conservé intégralement, SAUF la valeur d'un secret : décision actée,
elle n'entre jamais dans notre base.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

MAPPING_PATH = Path(__file__).parent / "mapping_regles.yaml"


def _charge_mapping() -> dict:
    if not MAPPING_PATH.exists():
        return {"version": 0, "regles": [], "defaut": {"paquet": None, "methode": "inconnu",
                                                      "confiance": "none"}}
    return yaml.safe_load(MAPPING_PATH.read_text(encoding="utf-8"))


MAPPING = _charge_mapping()

_MAPPING_GENERE = None


def _mapping_genere() -> dict:
    """Mapping EXTRAIT des métadonnées Semgrep — fichier généré, ne pas éditer."""
    global _MAPPING_GENERE
    if _MAPPING_GENERE is None:
        f = Path(__file__).parent / "mapping_regles_genere.yaml"
        try:
            _MAPPING_GENERE = (yaml.safe_load(f.read_text(encoding="utf-8")) or {}).get("regles") or {}
        except Exception:
            _MAPPING_GENERE = {}
    return _MAPPING_GENERE

SECRET = "<masqué>"


@dataclass
class Finding:
    id: str
    source: dict
    identity: dict
    location: dict
    severity: dict
    evidence: dict
    statut: str = "open"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "identity": self.identity,
            "location": self.location,
            "severity": self.severity,
            "evidence": self.evidence,
            "statut": self.statut,
            # Champs du cycle de vie que SARIF ne porte pas : c'est la raison pour
            # laquelle le modèle interne reste la source de vérité.
            "cycle": {"first_seen": None, "last_seen": None, "false_positive": False,
                      "reopened": False, "verified": False},
        }


def _fp(*parties: str) -> str:
    return hashlib.sha256("\x1f".join(parties).encode("utf-8")).hexdigest()[:32]


# Marqueurs de début d'identifiant de règle Semgrep. Le préfixe ajouté dépend du CHEMIN
# du fichier de règles, donc il varie : « rules. », « PHASE3.mt-regles. », etc.
# On ne peut pas le retirer par un motif fixe — il faut retrouver le début réel.
MARQUEURS_REGLE = ("python.lang.", "python.aws-lambda.", "python.django.", "python.flask.",
                   "python.requests.", "python.jwt.", "python.boto3.", "python.sqlalchemy.",
                   "generic.", "dockerfile.", "terraform.", "kubernetes.", "javascript.",
                   "java.", "go.", "ruby.", "c.", "php.")


def _nettoie_regle_semgrep(rid: str) -> str:
    """Ramène un identifiant Semgrep à sa forme canonique, quel que soit son préfixe.

    Observé par exécution, pour la MÊME règle :
        registre            -> python.lang.security.audit.subprocess-shell-true...
        fichier local       -> rules.python.lang.security.audit.subprocess-shell-true...
        autre chemin        -> PHASE3.mt-regles.python.lang.security.deserialization...
    Sans cette normalisation, la même règle produit plusieurs canonical_rule_id et
    notre déduplication fabrique des doublons.
    """
    rid = rid or ""
    for m in MARQUEURS_REGLE:
        i = rid.find(m)
        if i >= 0:
            return rid[i:]
    return rid.rsplit(".", 1)[-1] if rid else rid


def _paquet_concerne(rid: str) -> dict:
    """Retourne {paquet, methode, confiance} pour une règle.

    Ne devine JAMAIS : si aucune règle de mapping ne correspond, le paquet est null avec
    methode=inconnu. Un paquet inconnu empêche seulement le regroupement par paquet —
    il ne produit pas de lien faux.
    """
    # 1. Le mapping GÉNÉRÉ d'abord : extrait des métadonnées des règles Semgrep
    #    elles-mêmes (voir extraire_mapping.py). Bien plus large et plus fiable qu'une
    #    table écrite à la main — laquelle ne contenait qu'une ligne et rendait la
    #    corrélation aveugle au lien « Flask vulnérable + usage dangereux de Flask ».
    gen = _mapping_genere()
    for cle in (rid, rid.split(".")[-1]):
        if cle in gen:
            e = gen[cle]
            return {"paquet": e.get("paquet"),
                    "methode": e.get("methode", "metadata_semgrep"),
                    "confidence": e.get("confidence", "high")}
    # 2. Repli sur la table manuelle, pour les règles sans métadonnées de paquet.
    for entree in MAPPING.get("regles") or []:
        if entree.get("motif") and entree["motif"] in rid:
            return {"paquet": entree.get("paquet"),
                    "methode": entree.get("methode", "mapping_versionné"),
                    "confidence": entree.get("confiance", "low")}
    d = MAPPING.get("defaut") or {}
    return {"paquet": d.get("paquet"),
            "methode": d.get("methode", "inconnu"),
            "confidence": d.get("confiance", "none")}


def _replie(segs: list[str]) -> str | None:
    """Replie « . » et « .. » LEXICALEMENT. Renvoie None si ça remonte au-dessus du
    point d'ancrage : dans ce cas le chemin n'est PAS normalisable, et le refus est la
    réponse — l'aplatir (« ../x » → « x ») fabrique une identité de fichier qui créera
    un `same_file` entre deux fichiers distincts. Aucun accès au filesystem : la
    fonction reste déterministe et reproductible hors isolateur.
    """
    out: list[str] = []
    for s in segs:
        if s in ("", "."):
            continue
        if s == "..":
            if out and out[-1] != "..":
                out.pop()
                continue
            return None                      # remonte hors de la racine
        out.append(s)
    return "/".join(out)


def _segs(chemin: str) -> list[str]:
    return [s for s in chemin.replace("\\", "/").split("/") if s not in ("", ".")]


def normalise_chemin(fichier: str, racines=()) -> str:
    """Chemin relatif à la cible, indépendant de la machine (décision 2026-08-28,
    complétée le 2026-08-30).

    Les chemins émis par les outils ont plusieurs formes selon le contexte : absolus
    sous le montage de l'isolateur (/…/mt-scan/docs/x.js), relatifs à slash meneur
    (/main.tf — convention checkov), relatifs (docs/package-lock.json — trivy),
    « ./main.go » (style gosec), ou le dépôt nommé depuis le répertoire du run
    (/PHASE3/testrepo_iac/k8s.yaml — checkov hors isolateur, 20 findings mesurés sur
    la fixture iac). Les fingerprints et les clés de cluster sont calculés à partir du
    fichier : sans normalisation, les identités dépendent du point de montage, du cwd
    et du séparateur. Mesuré en dogfooding : 72 findings eslint en chemin absolu, 7 clés
    de cluster concernées ; et, à l'envers, un `./` non replié qui empêchait deux outils
    de parler du MÊME fichier.

    Règles — déterministes, SANS accès au filesystem :
      0. aucune marque de chemin (ni « / », ni « \\ », ni « ./ ») → RENDU TEL QUEL.
         Un finding peut porter un paquet, un asset, un dépôt : « golang.org/x/text »
         n'est pas un chemin et ne devient jamais un chemin local.
      1. séparateurs unifiés (Windows → POSIX), pour que l'identité ne dépende pas du
         séparateur. Inerte sous Linux, aucune occurrence observée.
      2. une racine connue (montage, cible — sous TOUTES ses formes, absolue ou
         relative) est retirée, puis les segments « . » et « .. » sont repliés ;
      3. un slash meneur résiduel est retiré : dans l'isolateur la cible est la seule
         arborescence visible, donc un chemin à slash meneur EST relatif à la cible
         (hypothèse documentée, testée dans test_chemins.py) ;
      4. si le repliement remonte AU-DESSUS de la racine (`../x`, `/..`), rien n'est
         aplati : le chemin est rendu tel quel. Il reste donc DISTINCT du fichier du
         même nom dans la cible — la prudence prime sur le regroupement ;
      5. tout autre chemin est rendu TEL QUEL — on ne fabrique pas de relativité.
    """
    if not fichier:
        return fichier or ""
    f = str(fichier)
    if "/" not in f and "\\" not in f and not f.startswith(("./", ".\\")):
        return f                                     # règle 0 : pas un chemin

    g = f.replace("\\", "/")                          # règle 1
    segs = _segs(g)
    for r in racines:                                # règle 2
        rs = _segs(str(r))
        if not rs or len(segs) < len(rs) or segs[:len(rs)] != rs:
            continue
        reste = _replie(segs[len(rs):])
        if reste is None:
            return f                                 # règle 4 : remontée → refus
        if reste:
            return reste
    if g.startswith("//"):
        return f                                     # « //… » : on n'y touche pas
    replie = _replie(segs)
    if replie is None:
        return f                                     # règle 4
    return replie



def depuis_semgrep(brut, racines=()) -> list[Finding]:
    if not isinstance(brut, dict):
        return []
    out = []
    for i, r in enumerate(brut.get("results") or [], 1):
        original = r.get("check_id", "")
        rid = _nettoie_regle_semgrep(original)
        carto = _paquet_concerne(rid)
        paquet = carto["paquet"]
        fichier = normalise_chemin(r.get("path") or "", racines)
        ligne = (r.get("start") or {}).get("line")
        meta = r.get("extra") or {}
        sev = (meta.get("severity") or "").upper()
        out.append(Finding(
            id=f"sg-{i:04d}",
            source={
                "tool": "semgrep",
                # L'identifiant ORIGINAL est toujours conservé : c'est la seule trace
                # fiable de ce que l'outil a réellement produit.
                "original_rule_id": original,
                "canonical_rule_id": f"semgrep:{rid}",
                "package": paquet,
                # Le paquet n'est pas deviné : méthode et confiance sont déclarées.
                "package_mapping": {"method": carto["methode"],
                                    "confidence": carto["confidence"]},
            },
            identity={"canonical_rule_id": f"semgrep:{rid}",
                      "fingerprint": _fp("semgrep", rid, fichier, str(ligne))},
            location={"asset": "repository", "file": fichier, "line": ligne,
                      "package": paquet},
            # Semgrep fournit une sévérité ; on la conserve avec sa provenance.
            severity={"value": sev or "UNKNOWN", "origine": "semgrep"},
            evidence={"message": (meta.get("message") or "")[:500],
                      "extrait": (meta.get("lines") or "")[:200]},
        ))
    return out


# ------------------------------------------------------------------ Trivy
def depuis_trivy(brut, racines=()) -> list[Finding]:
    if not isinstance(brut, dict):
        return []
    out = []
    n = 0
    for res in brut.get("Results") or []:
        cible = normalise_chemin(res.get("Target") or "", racines)
        for v in res.get("Vulnerabilities") or []:
            n += 1
            pkg = v.get("PkgName") or ""
            cve = v.get("VulnerabilityID") or ""
            out.append(Finding(
                id=f"tv-{n:04d}",
                source={
                    "tool": "trivy",
                    "original_rule_id": cve,
                    "canonical_rule_id": f"trivy:{cve}",
                    "package": pkg,
                    # Trivy déclare lui-même le paquet : c'est la méthode la plus fiable.
                    "package_mapping": {"method": "rule_metadata", "confidence": "high"},
                    "version_installee": v.get("InstalledVersion"),
                    "version_corrigee": v.get("FixedVersion"),
                },
                identity={"canonical_rule_id": f"trivy:{cve}",
                          "fingerprint": _fp("trivy", cve, pkg, cible)},
                location={"asset": "repository", "file": cible, "line": None,
                          "package": pkg},
                # Trivy fournit une sévérité ; provenance conservée.
                severity={"value": (v.get("Severity") or "UNKNOWN").upper(),
                          "origine": "trivy"},
                evidence={"titre": (v.get("Title") or "")[:300],
                          "cwe": v.get("CweIDs") or [],
                          "references": (v.get("References") or [])[:3]},
            ))
    return out


# ------------------------------------------------------------------ Gitleaks
def depuis_gitleaks(brut, racines=()) -> list[Finding]:
    if not isinstance(brut, list):
        return []
    out = []
    for i, f in enumerate(brut, 1):
        rid = f.get("RuleID") or ""
        # Le Fingerprint fourni par gitleaks (basé commit) est privilégié : la
        # normalisation du chemin ne déstabilise donc pas ces identités.
        fichier = normalise_chemin(f.get("File") or "", racines)
        # La valeur du secret est masquée ici aussi, par double précaution : l'outil
        # la masque déjà avec --redact, mais notre base ne doit jamais en contenir.
        out.append(Finding(
            id=f"gl-{i:04d}",
            source={
                "tool": "gitleaks",
                "original_rule_id": rid,
                "canonical_rule_id": f"gitleaks:{rid}",
                "package": None,
                "package_mapping": {"method": "inconnu", "confidence": "none"},
                "commit": f.get("Commit"), "auteur": f.get("Author"),
            },
            identity={"canonical_rule_id": f"gitleaks:{rid}",
                      "fingerprint": f.get("Fingerprint") or
                      _fp("gitleaks", rid, fichier, str(f.get("StartLine")))},
            location={"asset": "repository", "file": fichier,
                      "line": f.get("StartLine")},
            # Gitleaks ne fournit AUCUNE sévérité (vérifié : 18 champs, pas de Severity).
            # La sévérité est donc NOTRE responsabilité — décision documentée.
            severity={"value": "HIGH", "origine": "plateforme",
                      "justification": "exposition de credential : gravité attribuée par "
                                       "défaut, l'outil n'en fournit aucune"},
            evidence={"description": f.get("Description"),
                      "secret": SECRET,
                      "match": SECRET,
                      "entropy": f.get("Entropy")},
        ))
    return out


def depuis_manifest(brut, mani, outil: str, racines=()) -> list:
    """Normalise la sortie d'un provider déclaré par MANIFEST.

    Aucune connaissance de l'outil : tout vient de la spécification d'extraction.
    C'est ce qui permet d'ajouter un provider sans toucher à ce fichier.
    """
    import extraction as EX
    out = []
    for i, item in enumerate(EX.extraire(brut, mani.extraction), 1):
        c = EX.champs(item, mani.extraction)
        regle = str(c.get("regle") or "")
        # Nettoyage canonique des ids semgrep : hérité pour outil == "semgrep" (adapter
        # historique), et DÉCLARÉ par le manifest via extraction.nettoyage_regle pour
        # tout autre provider qui consomme une sortie semgrep (ex. semgrep_go). Le cœur
        # n'ajoute pas de nom d'outil : il applique ce que le manifest déclare.
        canon = _nettoie_regle_semgrep(regle) if (
            outil == "semgrep" or getattr(mani.extraction, "nettoyage_regle", "") == "semgrep"
        ) else regle
        fichier = normalise_chemin(c.get("fichier") or "", racines)
        ligne = c.get("ligne")
        # Paquet : le manifest peut DÉCLARER l'alias `paquet` dans extraction.champs
        # (étape 4). Occurrence observée : grype produit des matches au niveau PAQUET
        # (artifact.name) sans fichier, et ses ids GHSA-* n'existent dans aucun
        # mapping de règles — paquet=None cassait la convergence inter-outils avec
        # trivy (6/6 paquets communs mesurés sur testrepo_sca). L'outil nomme le
        # paquet lui-même : c'est une donnée, pas une déduction. Le repli mapping
        # reste inchangé pour les providers qui ne déclarent rien.
        paquet_declare = c.get("paquet")
        if paquet_declare:
            paquet = str(paquet_declare)
            paquet_methode, paquet_confiance = "declare_par_l_outil", "high"
        else:
            paquet = _paquet_concerne(canon)["paquet"] if regle else None
            paquet_methode = "mapping_versionné" if paquet else "inconnu"
            paquet_confiance = "medium" if paquet else "none"
        out.append(Finding(
            id=f"{outil[:2]}-{i:04d}",
            source={
                "tool": outil,
                "original_rule_id": regle,
                "canonical_rule_id": f"{outil}:{canon}",
                "package": paquet,
                "package_mapping": {"method": paquet_methode,
                                    "confidence": paquet_confiance},
                "nom_regle": c.get("nom_regle"),
                "declaratif": True,
            },
            identity={"canonical_rule_id": f"{outil}:{canon}",
                      "fingerprint": _fp(outil, canon, str(fichier), str(ligne))},
            location={"asset": "repository", "file": fichier, "line": ligne,
                      "package": paquet},
            severity={"value": str(c.get("severite") or "UNKNOWN").upper(),
                      "origine": outil},
            evidence={"message": c.get("message"),
                      "cwe": c.get("cwe"),
                      "reference": c.get("reference")},
        ))
    return out


NORMALISEURS = {
    "semgrep": depuis_semgrep,
    "trivy": depuis_trivy,
    "gitleaks": depuis_gitleaks,
}


def normaliser(provider: str, brut, mani=None, racines=()) -> list[Finding]:
    """Un provider avec manifest passe par la voie générique, sans code spécifique.

    `racines` : points d'ancrage connus (montage de l'isolateur, cible) pour
    relativiser les chemins AVANT le calcul des fingerprints — identité
    indépendante de la machine (décision 2026-08-28, test_chemins.py).
    """
    if mani is not None:
        return depuis_manifest(brut, mani, provider, racines)
    fn = NORMALISEURS.get(provider)
    if fn is None:
        raise KeyError(f"aucun normaliseur pour {provider!r} et aucun manifest déclaré")
    return fn(brut, racines)


def verifie_absence_secrets(findings: list[Finding]) -> list[str]:
    """Garde-fou : aucune valeur de secret ne doit subsister dans les findings.

    Teste la sortie réelle, pas l'intention. Un seul résultat suffit à faire échouer
    le pipeline : mieux vaut un échec bruyant qu'une fuite silencieuse.
    """
    # Garde-fou : jeu LARGE. Il ne masque rien, il bloque. On préfère un arrêt bruyant
    # à une clé qui passe — un faux positif ici coûte une investigation, pas une donnée.
    from assainissement import contient_secret
    problemes = []
    for f in findings:
        n = contient_secret(repr(f.to_dict()), large=True)
        if n:
            problemes.append(f"{f.id} contient {n} motif(s) de secret non masqué(s)")
    return problemes

