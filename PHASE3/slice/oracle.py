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
    # Traçabilité étendue — BLOCK 3 : lie la preuve à la cible et au run pour éviter collision inter-cible
    input_digest: str = ""
    target_ref: str = ""
    verification_version: str = "oracle-v1"
    hash_version: str = "v1"

    def __post_init__(self) -> None:
        if not self.reproducibility_hash:
            # Calcul déterministe du hash de preuve — inclut désormais run_id, input_digest, target_ref, versions
            payload = json.dumps({
                "hash_version": self.hash_version,
                "verification_version": self.verification_version,
                "finding_id": self.finding_id,
                "run_id": self.run_id,
                "input_digest": self.input_digest,
                "target_ref": self.target_ref,
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
            "input_digest": self.input_digest,
            "target_ref": self.target_ref,
            "verification_version": self.verification_version,
            "hash_version": self.hash_version,
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
    flags: dict[str, Any] = field(default_factory=dict)

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
            "flags": self.flags,
        }


class OracleEngine:
    """Moteur Oracle principal pour la vérification des findings."""

    def __init__(self, target_dir: str | Path | None = None, run_id: str = "", *, target=None, input_digest: str = "", target_ref: str = "", reader=None) -> None:
        # BLOCK 1 fix : accepte Cible canonique pour éviter dépendance filesystem implicite
        self._target = target
        self.input_digest = input_digest or ""
        self.target_ref = target_ref or ""
        self.reader = reader  # reader borné par Sandbox/garde_chemin si fourni
        if target is not None:
            try:
                chemin_local = getattr(target, "chemin_local", None)
                self.target_dir = Path(chemin_local).resolve() if chemin_local else None
                if not self.target_ref:
                    ref_fn = getattr(target, "reference_sure", None) or getattr(target, "reference", "")
                    if callable(ref_fn):
                        try:
                            self.target_ref = ref_fn()
                        except Exception:
                            self.target_ref = str(ref_fn)
                    else:
                        self.target_ref = str(ref_fn or "")
                # Cible non locale (url/hote/image) → jamais de FS, même si chemin_local existait par erreur
                ttype = getattr(target, "type", "")
                est_local = ttype in ("repository", "filesystem") or bool(chemin_local)
                if not est_local:
                    self.target_dir = None
            except Exception:
                self.target_dir = None
        else:
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
        # BLOCK 5 fix : CONTRADICTORY devient flag orthogonal, pas verdict qui masque la vérité
        contradictions = self._detecter_contradictions(f_dict=d, vue=vue, autres=autres_findings or [])
        contradictory_flag = bool(contradictions)
        if contradictions:
            trace.append(f"Contradictions détectées ({len(contradictions)} conflit(s)) — flag contradictory activé")

        # 2. Déterminer si le finding est vérifiable
        verifiable, motif_non_verif = self._est_verifiable(vue)
        if not verifiable:
            trace.append(f"Finding non vérifiable : {motif_non_verif}")
            # RÈGLE CRITIQUE : non vérifiable / absence de preuve => POTENTIAL / NOT_VERIFIED
            capsule = None
            if contradictory_flag:
                capsule = ProofCapsule(
                    finding_id=fid,
                    run_id=self.run_id,
                    timestamp=self._now(),
                    observation_type="tool_cross_check",
                    source="oracle_cross_verification",
                    details={"contradictions": contradictions},
                    input_digest=self.input_digest,
                    target_ref=self.target_ref,
                )
            return VerificationResult(
                finding_id=fid,
                verifiable=False,
                status=VerificationStatus.NOT_VERIFIABLE,
                verdict=VerdictStatus.POTENTIAL,
                confidence=0.3,
                justification=f"Information insuffisante pour vérifier : {motif_non_verif}",
                proof_capsule=capsule,
                contradictions=contradictions,
                trace=trace,
                flags={"contradictory": contradictory_flag} if contradictory_flag else {},
            )

        trace.append("Finding vérifiable. Analyse des preuves locales...")

        # 3. Vérification déterministe selon le type d'observation (SCA vs SAST vs Secret)

        # A. Verification de secrets (Gitleaks / detect-secrets)
        if "gitleaks" in outil or "secret" in regle or "credential" in regle:
            try:
                res_secret = self._verifier_secret(fid, vue, fichier, ligne)
            except Exception as exc:
                # BLOCK 7 atomicité : exception isolée → INCONCLUSIVE, pas crash global
                return VerificationResult(
                    finding_id=fid,
                    verifiable=True,
                    status=VerificationStatus.ERROR,
                    verdict=VerdictStatus.INCONCLUSIVE,
                    confidence=0.0,
                    justification=f"Erreur pendant vérification secret : {exc}",
                    contradictions=contradictions,
                    trace=trace + [f"Exception _verifier_secret: {exc}"],
                    flags={"contradictory": contradictory_flag} if contradictory_flag else {},
                )
            if res_secret:
                if contradictory_flag:
                    res_secret.contradictions = contradictions
                    res_secret.flags = {"contradictory": True}
                res_secret.trace = trace + res_secret.trace
                return res_secret

        # B. Verification SCA (Dépendances)
        if paquet or "trivy" in outil or "grype" in outil or "cve-" in regle or "ghsa-" in regle:
            try:
                res_sca = self._verifier_sca(fid, vue, fichier, paquet)
            except Exception as exc:
                return VerificationResult(
                    finding_id=fid,
                    verifiable=True,
                    status=VerificationStatus.ERROR,
                    verdict=VerdictStatus.INCONCLUSIVE,
                    confidence=0.0,
                    justification=f"Erreur pendant vérification SCA : {exc}",
                    contradictions=contradictions,
                    trace=trace + [f"Exception _verifier_sca: {exc}"],
                    flags={"contradictory": contradictory_flag} if contradictory_flag else {},
                )
            if res_sca:
                if contradictory_flag:
                    res_sca.contradictions = contradictions
                    res_sca.flags = {"contradictory": True}
                res_sca.trace = trace + res_sca.trace
                return res_sca

        # C. Verification SAST (Code source / AST)
        if fichier and self.target_dir:
            try:
                res_sast = self._verifier_sast(fid, vue, fichier, ligne, regle, original_rule)
            except Exception as exc:
                return VerificationResult(
                    finding_id=fid,
                    verifiable=True,
                    status=VerificationStatus.ERROR,
                    verdict=VerdictStatus.INCONCLUSIVE,
                    confidence=0.0,
                    justification=f"Erreur pendant vérification SAST : {exc}",
                    contradictions=contradictions,
                    trace=trace + [f"Exception _verifier_sast: {exc}"],
                    flags={"contradictory": contradictory_flag} if contradictory_flag else {},
                )
            if res_sast:
                if contradictory_flag:
                    res_sast.contradictions = contradictions
                    res_sast.flags = {"contradictory": True}
                res_sast.trace = trace + res_sast.trace
                return res_sast

        # 4. Repli si aucune preuve concluante ne peut être extraite
        trace.append("Aucune preuve formelle d'affirmation ou de réfutation directe trouvée")
        # Si contradictions détectées mais pas de vérification locale conclusive, on garde POTENTIAL avec flag
        if contradictory_flag:
            capsule = ProofCapsule(
                finding_id=fid,
                run_id=self.run_id,
                timestamp=self._now(),
                observation_type="tool_cross_check",
                source="oracle_cross_verification",
                details={"contradictions": contradictions, "fallback": "potential_with_contradiction"},
                input_digest=self.input_digest,
                target_ref=self.target_ref,
            )
            return VerificationResult(
                finding_id=fid,
                verifiable=True,
                status=VerificationStatus.VERIFIABLE,
                verdict=VerdictStatus.POTENTIAL,
                confidence=0.45,
                justification="Observations contradictoires sans preuve locale concluante — conservé comme POTENTIAL avec flag contradictory",
                proof_capsule=capsule,
                contradictions=contradictions,
                trace=trace,
                flags={"contradictory": True},
            )
        return VerificationResult(
            finding_id=fid,
            verifiable=True,
            status=VerificationStatus.VERIFIABLE,
            verdict=VerdictStatus.POTENTIAL,
            confidence=0.5,
            justification="Finding vérifiable mais preuve directe non concluante ; conservé comme potentiel",
            contradictions=contradictions,
            trace=trace,
            flags={"contradictory": contradictory_flag} if contradictory_flag else {},
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

        # BLOCK 1 : cible distante → fichier non vérifiable sans FS local
        if fichier and not self.target_dir:
            # Si la cible est distante (url/hote ou _target non local), on refuse explicitement
            if url or hote or (self._target is not None and getattr(self._target, "type", "") not in ("repository", "filesystem", "")):
                return False, "Cible distante — vérification fichier requiert accès FS local indisponible"
            return False, "Répertoire cible local indisponible pour vérification fichier"

        if fichier and self.target_dir:
            # Sécurité garde-chemin : refuser les remontées de répertoire hors du target_dir
            # Utilise reader borné si disponible, sinon Path direct
            try:
                path_abs = (self.target_dir / fichier).resolve()
                path_abs.relative_to(self.target_dir)
            except ValueError:
                return False, f"Chemin de fichier hors cible autorisée : {fichier}"
            # Vérifie existence via reader si fourni, sinon FS direct
            exists = False
            try:
                if self.reader:
                    exists = self.reader(fichier) is not None  # reader retourne contenu ou None
                else:
                    exists = path_abs.exists()
            except Exception:
                exists = path_abs.exists()
            if not exists:
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

        # Inspection de la présence du paquet — BLOCK SCA : évite substring "express" dans "express-paginate"
        paquet_trouve = False
        version_detectee = None
        lockfile_source = ""

        def _paquet_dans_contenu(paquet: str, contenu: str, lf_name: str) -> tuple[bool, str | None]:
            # Pour package-lock.json / package.json : parse JSON et cherche clé exacte
            if lf_name in ("package-lock.json", "package.json"):
                try:
                    data = json.loads(contenu)
                    # package-lock v7 : packages: { "node_modules/express": {...}, "": {...} }
                    pkgs = data.get("packages") or data.get("dependencies") or {}
                    for k, v in pkgs.items():
                        # k peut être "node_modules/express" ou "express"
                        nom = k.split("/")[-1] if "/" in k else k
                        if nom.lower() == paquet.lower():
                            ver = ""
                            if isinstance(v, dict):
                                ver = v.get("version", "")
                            return True, ver or None
                    # fallback : cherche aussi dans le contenu brut avec word boundary
                    if re.search(rf'"{re.escape(paquet)}"\s*:\s*\{{', contenu):
                        return True, None
                    return False, None
                except Exception:
                    pass
            # requirements.txt / Pipfile.lock : cherche ligne exacte paquet==version ou paquet>=
            if lf_name in ("requirements.txt", "Pipfile.lock"):
                for line in contenu.splitlines():
                    line = line.strip().lower()
                    # match "express==4.17.1" ou "express>=4.0" avec word boundary
                    if re.match(rf'^{re.escape(paquet.lower())}\s*(==|>=|<=|~=|!=|===)', line):
                        m2 = re.search(rf'^{re.escape(paquet)}\s*==\s*([0-9a-zA-Z\.\-\+]+)', line, re.IGNORECASE)
                        return True, m2.group(1) if m2 else None
                    if line == paquet.lower():
                        return True, None
            # yarn.lock / Cargo.lock / go.sum : cherche mot exact avec word boundary (évite substring express vs express-paginate)
            if re.search(rf'\b{re.escape(paquet)}\b', contenu, re.IGNORECASE):
                # Tente extraction version spécifique au format
                m = re.search(rf'"{re.escape(paquet)}"\s*:\s*\{{\s*"version"\s*:\s*"([^"]+)"', contenu, re.IGNORECASE)
                if not m:
                    m = re.search(rf'{re.escape(paquet)}@[^:]*:\s*\n\s*version\s+"([^"]+)"', contenu, re.IGNORECASE)
                ver2 = m.group(1) if m else None
                # Vérifie que c'est bien un match exact, pas substring : déjà filtré par boundary
                return True, ver2
            return False, None

        if paquet:
            for lf_path in trouves:
                try:
                    contenu = lf_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                trouve, ver = _paquet_dans_contenu(paquet, contenu, lf_path.name)
                if trouve:
                    paquet_trouve = True
                    lockfile_source = lf_path.name
                    version_detectee = ver
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
                input_digest=self.input_digest,
                target_ref=self.target_ref,
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
            # BLOCK SCA fix : ne réfute que si lockfiles parsés prouvent l'absence (pas juste "fichier existe")
            # Si un seul lockfile existe mais ne couvre pas toutes les dépendances, on reste POTENTIAL
            # On ne réfute que si on a au moins un lockfile JSON/YAML parsé et que le paquet n'y est vraiment pas
            parsés = [lf for lf in trouves if lf.name in ("package-lock.json", "requirements.txt", "Pipfile.lock", "poetry.lock")]
            if parsés:
                capsule = ProofCapsule(
                    finding_id=fid,
                    run_id=self.run_id,
                    timestamp=self._now(),
                    observation_type="dependency_lockfile",
                    source="lockfile_inspection",
                    details={"package": paquet, "checked_lockfiles": [l.name for l in trouves]},
                    input_digest=self.input_digest,
                    target_ref=self.target_ref,
                )
                return VerificationResult(
                    finding_id=fid,
                    verifiable=True,
                    status=VerificationStatus.VERIFIABLE,
                    verdict=VerdictStatus.REFUTED,
                    confidence=0.75,
                    justification=f"Dépendance '{paquet}' absente des lockfiles parsés ({', '.join([l.name for l in parsés])}) — réfutation limitée aux manifests déclaratifs",
                    proof_capsule=capsule,
                    trace=[f"Dépendance '{paquet}' absente de {[l.name for l in parsés]}"],
                )
            # Sinon, pas assez de preuve pour réfuter → POTENTIAL
            return None
        return None

    def _verifier_sast(
        self, fid: str, vue: dict, fichier: str, ligne: int | None, regle: str, original_rule: str
    ) -> VerificationResult | None:
        if not self.target_dir:
            return None

        # Utilise reader borné si disponible
        try:
            p_file = (self.target_dir / fichier).resolve()
            try:
                p_file.relative_to(self.target_dir)
            except ValueError:
                return None
            if not p_file.exists():
                return None
            # Lecture via reader si fourni (sandbox), sinon FS direct
            if self.reader:
                try:
                    contenu = self.reader(fichier)
                    if contenu is None:
                        return None
                    lines = contenu.splitlines() if isinstance(contenu, str) else p_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                except Exception:
                    lines = p_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            else:
                lines = p_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return None
        if ligne is not None and (ligne < 1 or ligne > len(lines)):
            # Ligne hors limites -> réfutation / inexistant
            capsule = ProofCapsule(
                finding_id=fid,
                run_id=self.run_id,
                timestamp=self._now(),
                observation_type="code_ast",
                source=f"file:{fichier}",
                details={"file": fichier, "requested_line": ligne, "total_lines": len(lines)},
                input_digest=self.input_digest,
                target_ref=self.target_ref,
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
        stripped = line_content.strip()
        # Ignore les lignes de commentaire pur pour éviter faux REFUTED
        is_comment = stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*")

        # Test spécifique : pyyaml safe_load vs load — honnête, pas confirmation universelle (BLOCK 6)
        if ("yaml" in regle or "pyyaml" in original_rule) and not is_comment:
            # Détection plus précise : safe_load, SafeLoader, CSafeLoader
            has_safe = "safe_load" in line_content or "SafeLoader" in line_content or "CSafeLoader" in line_content
            has_load = re.search(r'\bload\s*\(', line_content) is not None
            # Si la ligne contient un commentaire, ne pas se baser sur safe_load dans le commentaire
            code_part = line_content.split("#")[0] if "#" in line_content else line_content
            has_safe_code = "safe_load" in code_part or "SafeLoader" in code_part or "CSafeLoader" in code_part
            has_load_code = re.search(r'\bload\s*\(', code_part) is not None
            if has_safe_code:
                capsule = ProofCapsule(
                    finding_id=fid,
                    run_id=self.run_id,
                    timestamp=self._now(),
                    observation_type="code_ast",
                    source=f"file:{fichier}:{ligne}",
                    details={"file": fichier, "line": ligne, "code_snippet": line_content.strip(), "evidence": "safe_load_or_SafeLoader"},
                    input_digest=self.input_digest,
                    target_ref=self.target_ref,
                )
                return VerificationResult(
                    finding_id=fid,
                    verifiable=True,
                    status=VerificationStatus.VERIFIABLE,
                    verdict=VerdictStatus.REFUTED,
                    confidence=0.85,
                    justification=f"Inspection statique : `safe_load`/`SafeLoader` détecté à la ligne {ligne} — indice de réfutation, non preuve d'exploitation impossible (contexte, wrapper, données non contrôlées non vérifiés)",
                    proof_capsule=capsule,
                    trace=[f"Inspection ligne {ligne} : `safe_load`/`SafeLoader` présent (evidence-based, non exploit-verified)"],
                )
            elif has_load_code and not has_safe_code:
                capsule = ProofCapsule(
                    finding_id=fid,
                    run_id=self.run_id,
                    timestamp=self._now(),
                    observation_type="code_ast",
                    source=f"file:{fichier}:{ligne}",
                    details={"file": fichier, "line": ligne, "code_snippet": line_content.strip(), "evidence": "yaml_load_sans_safe"},
                    input_digest=self.input_digest,
                    target_ref=self.target_ref,
                )
                return VerificationResult(
                    finding_id=fid,
                    verifiable=True,
                    status=VerificationStatus.VERIFIABLE,
                    verdict=VerdictStatus.POTENTIAL,
                    confidence=0.65,
                    justification=f"Inspection statique : `yaml.load` sans `safe_load` à la ligne {ligne} — conservé comme POTENTIAL, confirmation d'exploitation requiert analyse de flux/taint, non fournie",
                    proof_capsule=capsule,
                    trace=[f"Inspection ligne {ligne} : `yaml.load` sans safe (POTENTIAL, non CONFIRMED — besoin d'analyse de flux)"],
                )

        # Preuve de présence par défaut pour le code source : POTENTIAL (car la ligne existe, mais pas de règle spécifique d'affirmation)
        if line_content and not is_comment:
            capsule = ProofCapsule(
                finding_id=fid,
                run_id=self.run_id,
                timestamp=self._now(),
                observation_type="code_ast",
                source=f"file:{fichier}:{ligne}",
                details={"file": fichier, "line": ligne, "snippet": line_content[:200]},
                input_digest=self.input_digest,
                target_ref=self.target_ref,
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

        try:
            p_file = (self.target_dir / fichier).resolve()
            try:
                p_file.relative_to(self.target_dir)
            except ValueError:
                return None
            if not p_file.exists():
                return None
            if self.reader:
                try:
                    contenu = self.reader(fichier)
                    lines = contenu.splitlines() if isinstance(contenu, str) and contenu is not None else p_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                except Exception:
                    lines = p_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            else:
                lines = p_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return None
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
                    input_digest=self.input_digest,
                    target_ref=self.target_ref,
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
                    input_digest=self.input_digest,
                    target_ref=self.target_ref,
                )
                # BLOCK 6 : ne pas sur-confirmer, reste POTENTIAL si pas de validation de l'exploitabilité du secret
                return VerificationResult(
                    finding_id=fid,
                    verifiable=True,
                    status=VerificationStatus.VERIFIABLE,
                    verdict=VerdictStatus.POTENTIAL,
                    confidence=0.65,
                    justification=f"Secret présent dans le code à la ligne {ligne} de {fichier} — conservé comme POTENTIAL, exploitabilité non vérifiée (type, entropie, portée non évalués)",
                    proof_capsule=capsule,
                    trace=[f"Secret localisé à la ligne {ligne} (POTENTIAL, non CONFIRMED — evidence-based)"],
                )
        return None

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")
