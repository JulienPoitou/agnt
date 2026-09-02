"""Moteur Oracle de vérification backend — AGNT.

Fait passer AGNT d'un modèle :
    scanner → finding
à un modèle fiable et traçable :
    observation → finding → vérification → preuve → verdict → proof_capsule

Principes architecturaux :
1. Une absence de preuve ne signifie PAS `false_positive` (refuted),
   mais `potential` / `not_verified`. Ne transforme jamais une incertitude en certitude.
2. Tout passe par les vérifications déterministes et les gardes existantes
   (Policy / Sandbox / Garde-chemin / Assainissement).
3. Les contradictions inter-observations sont conservées et tracées (état `contradictory`).
4. À observations identiques, le verdict et la preuve sont 100% déterministes.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from findings import Finding, vue_unifiee


class VerificationStatus(str, Enum):
    VERIFIABLE = "verifiable"
    NOT_VERIFIABLE = "not_verifiable"
    PENDING = "pending"
    ERROR = "error"


class VerdictStatus(str, Enum):
    CONFIRMED = "confirmed"          # Vrai positif confirmé par preuve explicite
    POTENTIAL = "potential"          # Observation possible mais sans preuve suffisante / non vérifiée
    REFUTED = "refuted"              # Faux positif prouvé par une observation incompatible
    CONTRADICTORY = "contradictory"  # Observations contradictoires conservées sans écrasement
    INCONCLUSIVE = "inconclusive"    # Erreur/Timeout/Interruption pendant la vérification


@dataclass
class ProofCapsule:
    """Représentation générique et structurée d'une preuve de vérification.

    Peut représenter :
    - localisation/AST dans le code ;
    - résolution/vérification de dépendance dans un lockfile ;
    - observation HTTP / réponse autorisée ;
    - sortie d'un outil / comparaison inter-outils ;
    - hash et empreinte de reproductibilité.
    """

    finding_id: str
    run_id: str
    timestamp: str
    observation_type: str  # "code_ast", "dependency_lockfile", "http_response", "tool_cross_check", "static_analysis"
    source: str
    details: dict[str, Any] = field(default_factory=dict)
    reproducibility_hash: str = ""

    def __post_init__(self) -> None:
        if not self.reproducibility_hash:
            # Calcul déterministe du hash de preuve
            payload = json.dumps({
                "finding_id": self.finding_id,
                "observation_type": self.observation_type,
                "source": self.source,
                "details": self.details,
            }, sort_keys=True, ensure_ascii=False, default=str)
            object.__setattr__(
                self, "reproducibility_hash",
                hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "observation_type": self.observation_type,
            "source": self.source,
            "details": self.details,
            "reproducibility_hash": self.reproducibility_hash,
        }


@dataclass
class VerificationResult:
    """Résultat complet du processus de vérification d'un finding."""

    finding_id: str
    verifiable: bool
    status: VerificationStatus
    verdict: VerdictStatus
    confidence: float  # 0.0 à 1.0
    justification: str
    proof_capsule: ProofCapsule | None = None
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "verifiable": self.verifiable,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "justification": self.justification,
            "proof_capsule": self.proof_capsule.to_dict() if self.proof_capsule else None,
            "contradictions": self.contradictions,
            "trace": self.trace,
        }


class OracleEngine:
    """Moteur Oracle principal pour la vérification des findings."""

    def __init__(self, target_dir: str | Path | None = None, run_id: str = "") -> None:
        self.target_dir = Path(target_dir).resolve() if target_dir else None
        self.run_id = run_id or "run-oracle-default"

    def evaluer_finding(
        self,
        finding: Finding | dict,
        autres_findings: list[Finding | dict] | None = None,
        context_override: dict | None = None,
    ) -> VerificationResult:
        """Évalue un finding et produit un verdict déterministe avec preuve et traçabilité."""
        trace: list[str] = []
        d = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding or {})
        fid = d.get("id") or "unknown-finding"
        trace.append(f"Réception du finding {fid}")

        # Protection contre entrées invalides ou corrompues
        if not isinstance(d, dict) or not d.get("id"):
            return VerificationResult(
                finding_id=fid,
                verifiable=False,
                status=VerificationStatus.ERROR,
                verdict=VerdictStatus.INCONCLUSIVE,
                confidence=0.0,
                justification="Finding malformé ou absent",
                trace=["Finding non valide"],
            )

        vue = vue_unifiee(d)
        outil = vue.get("outil") or ""
        regle = ((vue.get("regle") or {}).get("canonique") or "").lower()
        original_rule = ((vue.get("regle") or {}).get("originale") or "").lower()
        cible = vue.get("cible") or {}
        fichier = cible.get("chemin") or ""
        ligne = cible.get("ligne")
        paquet = cible.get("paquet")

        # 1. Analyse des contradictions inter-observations dans le cluster / context
        contradictions = self._detecter_contradictions(f_dict=d, vue=vue, autres=autres_findings or [])
        if contradictions:
            trace.append(f"Contradictions détectées ({len(contradictions)} conflit(s))")
            capsule = ProofCapsule(
                finding_id=fid,
                run_id=self.run_id,
                timestamp=self._now(),
                observation_type="tool_cross_check",
                source="oracle_cross_verification",
                details={"contradictions": contradictions},
            )
            return VerificationResult(
                finding_id=fid,
                verifiable=True,
                status=VerificationStatus.VERIFIABLE,
                verdict=VerdictStatus.CONTRADICTORY,
                confidence=0.5,
                justification="Observations contradictoires entre outils ou sources",
                proof_capsule=capsule,
                contradictions=contradictions,
                trace=trace,
            )

        # 2. Déterminer si le finding est vérifiable
        verifiable, motif_non_verif = self._est_verifiable(vue)
        if not verifiable:
            trace.append(f"Finding non vérifiable : {motif_non_verif}")
            # RÈGLE CRITIQUE : non vérifiable / absence de preuve => POTENTIAL / NOT_VERIFIED
            return VerificationResult(
                finding_id=fid,
                verifiable=False,
                status=VerificationStatus.NOT_VERIFIABLE,
                verdict=VerdictStatus.POTENTIAL,
                confidence=0.3,
                justification=f"Information insuffisante pour vérifier : {motif_non_verif}",
                trace=trace,
            )

        trace.append("Finding vérifiable. Analyse des preuves locales...")

        # 3. Vérification déterministe selon le type d'observation (SCA vs SAST vs Secret)

        # A. Verification de secrets (Gitleaks / detect-secrets)
        if "gitleaks" in outil or "secret" in regle or "credential" in regle:
            res_secret = self._verifier_secret(fid, vue, fichier, ligne)
            if res_secret:
                res_secret.trace = trace + res_secret.trace
                return res_secret

        # B. Verification SCA (Dépendances)
        if paquet or "trivy" in outil or "grype" in outil or "cve-" in regle or "ghsa-" in regle:
            res_sca = self._verifier_sca(fid, vue, fichier, paquet)
            if res_sca:
                res_sca.trace = trace + res_sca.trace
                return res_sca

        # C. Verification SAST (Code source / AST)
        if fichier and self.target_dir:
            res_sast = self._verifier_sast(fid, vue, fichier, ligne, regle, original_rule)
            if res_sast:
                res_sast.trace = trace + res_sast.trace
                return res_sast

        # 4. Repli si aucune preuve concluante ne peut être extraite
        trace.append("Aucune preuve formelle d'affirmation ou de réfutation directe trouvée")
        return VerificationResult(
            finding_id=fid,
            verifiable=True,
            status=VerificationStatus.VERIFIABLE,
            verdict=VerdictStatus.POTENTIAL,
            confidence=0.5,
            justification="Finding vérifiable mais preuve directe non concluante ; conservé comme potentiel",
            trace=trace,
        )

    # ------------------------------------------------------------------ Sub-methods
    def _est_verifiable(self, vue: dict[str, Any]) -> tuple[bool, str]:
        cible = vue.get("cible") or {}
        fichier = cible.get("chemin")
        paquet = cible.get("paquet")
        url = cible.get("url")
        hote = cible.get("hote")

        if not (fichier or paquet or url or hote):
            return False, "Aucune coordonnée de cible (fichier, paquet, url, hôte)"

        if fichier and self.target_dir:
            path_abs = (self.target_dir / fichier).resolve()
            # Sécurité garde-chemin : refuser les remontées de répertoire hors du target_dir
            try:
                path_abs.relative_to(self.target_dir)
            except ValueError:
                return False, f"Chemin de fichier hors cible autorisée : {fichier}"
            if not path_abs.exists():
                return False, f"Fichier local introuvable sur le disque : {fichier}"

        return True, ""

    def _detecter_contradictions(
        self, f_dict: dict, vue: dict, autres: list[Finding | dict]
    ) -> list[dict[str, Any]]:
        contradictions = []
        fid = f_dict.get("id")
        emp = vue.get("empreinte")
        loc = vue.get("cible") or {}
        fichier = loc.get("chemin")
        ligne = loc.get("ligne")
        paquet = loc.get("paquet")

        for autre in autres:
            a_dict = autre.to_dict() if hasattr(autre, "to_dict") else dict(autre or {})
            aid = a_dict.get("id")
            if aid == fid:
                continue
            avue = vue_unifiee(a_dict)
            aloc = avue.get("cible") or {}

            # Même paquet mais statut/version incompatible ou conclusion diamétralement opposée
            if paquet and aloc.get("paquet") == paquet:
                verdict_a = (a_dict.get("cycle") or {}).get("verdict")
                if verdict_a == VerdictStatus.REFUTED.value:
                    contradictions.append({
                        "autre_finding_id": aid,
                        "raison": f"Le finding {aid} pour le même paquet '{paquet}' est réfuté",
                        "outil_a": vue.get("outil"),
                        "outil_b": avue.get("outil"),
                    })

            # Même fichier & ligne mais sévérités ou règles contradictoires explicites
            if fichier and aloc.get("chemin") == fichier and ligne is not None and aloc.get("ligne") == ligne:
                sev_a = vue.get("severite")
                sev_b = avue.get("severite")
                # Exemple : l'un dit CRITICAL et l'autre dit INFO avec message de sécurité propre
                if (sev_a == "CRITICAL" and sev_b == "INFO") or (sev_a == "INFO" and sev_b == "CRITICAL"):
                    msg_b = avue.get("message") or ""
                    if "safe" in msg_b.lower() or "ok" in msg_b.lower() or "ignored" in msg_b.lower():
                        contradictions.append({
                            "autre_finding_id": aid,
                            "raison": f"Évaluation contradictoire de gravité entre {fid} ({sev_a}) et {aid} ({sev_b})",
                            "outil_a": vue.get("outil"),
                            "outil_b": avue.get("outil"),
                        })
        return contradictions

    def _verifier_sca(self, fid: str, vue: dict, fichier: str, paquet: str | None) -> VerificationResult | None:
        if not self.target_dir:
            return None

        # Chercher des fichiers manifestes / lockfiles dans le dépôt cible
        lockfiles = ["package-lock.json", "yarn.lock", "Pipfile.lock", "poetry.lock", "requirements.txt", "go.sum", "Cargo.lock"]
        trouves = []
        for lf in lockfiles:
            p = self.target_dir / lf
            if p.exists():
                trouves.append(p)

        if not trouves and not fichier:
            return None

        # Inspection de la présence du paquet dans le lockfile
        paquet_trouve = False
        version_detectee = None
        lockfile_source = ""

        if paquet:
            for lf_path in trouves:
                contenu = lf_path.read_text(encoding="utf-8", errors="ignore")
                if paquet.lower() in contenu.lower():
                    paquet_trouve = True
                    lockfile_source = lf_path.name
                    # Essayer d'extraire la version
                    m = re.search(rf'"{re.escape(paquet)}"\s*:\s*\{{\s*"version"\s*:\s*"([^"]+)"', contenu, re.IGNORECASE)
                    if not m:
                        m = re.search(rf"{re.escape(paquet)}==([0-9a-zA-Z\.\-]+)", contenu, re.IGNORECASE)
                    if m:
                        version_detectee = m.group(1)
                    break

        if paquet_trouve:
            capsule = ProofCapsule(
                finding_id=fid,
                run_id=self.run_id,
                timestamp=self._now(),
                observation_type="dependency_lockfile",
                source=f"lockfile:{lockfile_source}",
                details={
                    "package": paquet,
                    "lockfile": lockfile_source,
                    "version_found": version_detectee or "present_in_lockfile",
                },
            )
            return VerificationResult(
                finding_id=fid,
                verifiable=True,
                status=VerificationStatus.VERIFIABLE,
                verdict=VerdictStatus.CONFIRMED,
                confidence=0.9,
                justification=f"Dépendance '{paquet}' confirmée présente dans {lockfile_source}",
                proof_capsule=capsule,
                trace=[f"Dépendance '{paquet}' localisée dans {lockfile_source}"],
            )
        elif paquet and trouves:
            # Paquet absent des lockfiles alors que les lockfiles existent -> Refuté (faux positif)
            capsule = ProofCapsule(
                finding_id=fid,
                run_id=self.run_id,
                timestamp=self._now(),
                observation_type="dependency_lockfile",
                source="lockfile_inspection",
                details={"package": paquet, "checked_lockfiles": [l.name for l in trouves]},
            )
            return VerificationResult(
                finding_id=fid,
                verifiable=True,
                status=VerificationStatus.VERIFIABLE,
                verdict=VerdictStatus.REFUTED,
                confidence=0.85,
                justification=f"Dépendance '{paquet}' absente des fichiers de lock inspectés",
                proof_capsule=capsule,
                trace=[f"Dépendance '{paquet}' absente de {[l.name for l in trouves]}"],
            )
        return None

    def _verifier_sast(
        self, fid: str, vue: dict, fichier: str, ligne: int | None, regle: str, original_rule: str
    ) -> VerificationResult | None:
        if not self.target_dir:
            return None

        p_file = (self.target_dir / fichier).resolve()
        if not p_file.exists():
            return None

        lines = p_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        if ligne is not None and (ligne < 1 or ligne > len(lines)):
            # Ligne hors limites -> réfutation / inexistant
            capsule = ProofCapsule(
                finding_id=fid,
                run_id=self.run_id,
                timestamp=self._now(),
                observation_type="code_ast",
                source=f"file:{fichier}",
                details={"file": fichier, "requested_line": ligne, "total_lines": len(lines)},
            )
            return VerificationResult(
                finding_id=fid,
                verifiable=True,
                status=VerificationStatus.VERIFIABLE,
                verdict=VerdictStatus.REFUTED,
                confidence=0.9,
                justification=f"Numéro de ligne {ligne} hors des limites du fichier {fichier} ({len(lines)} lignes)",
                proof_capsule=capsule,
                trace=[f"Ligne {ligne} inexistante dans {fichier}"],
            )

        line_content = lines[ligne - 1] if (ligne and 1 <= ligne <= len(lines)) else ""

        # Test spécifique : pyyaml safe_load vs load
        if "yaml" in regle or "pyyaml" in original_rule:
            if "safe_load" in line_content:
                capsule = ProofCapsule(
                    finding_id=fid,
                    run_id=self.run_id,
                    timestamp=self._now(),
                    observation_type="code_ast",
                    source=f"file:{fichier}:{ligne}",
                    details={"file": fichier, "line": ligne, "code_snippet": line_content.strip()},
                )
                return VerificationResult(
                    finding_id=fid,
                    verifiable=True,
                    status=VerificationStatus.VERIFIABLE,
                    verdict=VerdictStatus.REFUTED,
                    confidence=0.95,
                    justification=f"Attaque de désérialisation réfutée : `yaml.safe_load` est utilisé à la ligne {ligne}",
                    proof_capsule=capsule,
                    trace=[f"Inspection ligne {ligne} : utilisation sécurisée de `safe_load`"],
                )
            elif "load(" in line_content and "safe_load" not in line_content:
                capsule = ProofCapsule(
                    finding_id=fid,
                    run_id=self.run_id,
                    timestamp=self._now(),
                    observation_type="code_ast",
                    source=f"file:{fichier}:{ligne}",
                    details={"file": fichier, "line": ligne, "code_snippet": line_content.strip()},
                )
                return VerificationResult(
                    finding_id=fid,
                    verifiable=True,
                    status=VerificationStatus.VERIFIABLE,
                    verdict=VerdictStatus.CONFIRMED,
                    confidence=0.95,
                    justification=f"Utilisation non sécurisée confirmée de `yaml.load` sans safe_load à la ligne {ligne}",
                    proof_capsule=capsule,
                    trace=[f"Inspection ligne {ligne} : `yaml.load` non sécurisé confirmé"],
                )

        # Preuve de présence par défaut pour le code source : POTENTIAL (car la ligne existe, mais pas de règle spécifique d'affirmation)
        if line_content:
            capsule = ProofCapsule(
                finding_id=fid,
                run_id=self.run_id,
                timestamp=self._now(),
                observation_type="code_ast",
                source=f"file:{fichier}:{ligne}",
                details={"file": fichier, "line": ligne, "snippet": line_content[:200]},
            )
            return VerificationResult(
                finding_id=fid,
                verifiable=True,
                status=VerificationStatus.VERIFIABLE,
                verdict=VerdictStatus.POTENTIAL,
                confidence=0.6,
                justification=f"Emplacement de code localisé à la ligne {ligne} de {fichier}, preuve spécifique manquante",
                proof_capsule=capsule,
                trace=[f"Code source localisé à {fichier}:{ligne}"],
            )

        return None

    def _verifier_secret(self, fid: str, vue: dict, fichier: str, ligne: int | None) -> VerificationResult | None:
        if not self.target_dir or not fichier:
            return None

        p_file = (self.target_dir / fichier).resolve()
        if not p_file.exists():
            return None

        lines = p_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        if ligne and 1 <= ligne <= len(lines):
            line_content = lines[ligne - 1]
            # Vérifier si la ligne est un commentaire ou un exemple fictif
            if line_content.strip().startswith("#") or "EXAMPLE" in line_content.upper() or "DUMMY" in line_content.upper() or "<masqué>" in line_content:
                capsule = ProofCapsule(
                    finding_id=fid,
                    run_id=self.run_id,
                    timestamp=self._now(),
                    observation_type="static_analysis",
                    source=f"file:{fichier}:{ligne}",
                    details={"file": fichier, "line": ligne, "reason": "comment_or_example"},
                )
                return VerificationResult(
                    finding_id=fid,
                    verifiable=True,
                    status=VerificationStatus.VERIFIABLE,
                    verdict=VerdictStatus.REFUTED,
                    confidence=0.85,
                    justification=f"Le secret détecté à la ligne {ligne} est un commentaire ou un exemple fictif non exploitable",
                    proof_capsule=capsule,
                    trace=[f"Secret identifié comme fictif/commentaire à la ligne {ligne}"],
                )
            else:
                capsule = ProofCapsule(
                    finding_id=fid,
                    run_id=self.run_id,
                    timestamp=self._now(),
                    observation_type="static_analysis",
                    source=f"file:{fichier}:{ligne}",
                    details={"file": fichier, "line": ligne, "found": True},
                )
                return VerificationResult(
                    finding_id=fid,
                    verifiable=True,
                    status=VerificationStatus.VERIFIABLE,
                    verdict=VerdictStatus.CONFIRMED,
                    confidence=0.9,
                    justification=f"Secret présent et actif dans le code à la ligne {ligne} de {fichier}",
                    proof_capsule=capsule,
                    trace=[f"Secret localisé à la ligne {ligne}"],
                )
        return None

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")
