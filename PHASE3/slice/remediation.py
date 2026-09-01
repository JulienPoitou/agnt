"""Moteur de Remédiation Automatisée Déterministe — Phase 11.

Propose des suggestions de correction (patches Git, mises à jour de dépendances,
corrections de configuration) de manière totalement déterministe et sans invention par un LLM.

Garanties et principes :
1. Zéro sur-affirmation : la remédiation est proposée comme une suggestion vérifiable,
   jamais appliquée automatiquement sans validation humaine.
2. Standard de code : bibliothèque standard Python 3 uniquement (difflib, re, json, etc.).
3. Formats typés :
   - type : 'dependency_bump', 'code_patch', ou 'config_fix'
   - confidence : 'high', 'medium', 'low'
   - Unified diff format pour les patches de code.
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Any

from findings import Finding, Remediation


# ---------------------------------------------------------------------- SAST / Code Fixes
def _generer_code_patch(
    file_path: str,
    line_number: int | None,
    rule_id: str,
    evidence_message: str = "",
    extrait: str = "",
    target_dir: str | Path | None = None,
) -> Remediation | None:
    """Génère un unified diff déterministe pour des règles SAST bien identifiées."""
    rule_upper = (rule_id or "").upper()
    rule_lower = (rule_id or "").lower()

    # Règle PyYAML avoid-pyyaml-load
    if "yaml" in rule_lower and ("load" in rule_lower or "pyyaml" in rule_lower):
        old_line = extrait.strip() if extrait else "data = yaml.load(f)"
        if "yaml.load(" in old_line and "safe_load" not in old_line:
            new_line = old_line.replace("yaml.load(", "yaml.safe_load(")
        elif "yaml.load(" in old_line:
            new_line = old_line
        else:
            old_line = "data = yaml.load(stream)"
            new_line = "data = yaml.safe_load(stream)"

        diff = _creer_unified_diff(file_path, line_number, old_line, new_line)
        return Remediation(
            type="code_patch",
            confidence="high",
            description="Remplacer `yaml.load()` non sécurisé par `yaml.safe_load()` pour prévenir la désérialisation de code arbitraire.",
            details={
                "file_path": file_path,
                "line_number": line_number,
                "rule_id": rule_id,
                "patch": diff,
                "original": old_line,
                "replacement": new_line,
            },
        )

    # Règle subprocess-shell-true
    if "subprocess" in rule_lower and "shell" in rule_lower:
        old_line = extrait.strip() if extrait else "subprocess.call(cmd, shell=True)"
        new_line = old_line.replace("shell=True", "shell=False")
        diff = _creer_unified_diff(file_path, line_number, old_line, new_line)
        return Remediation(
            type="code_patch",
            confidence="medium",
            description="Remplacer `shell=True` par `shell=False` dans les appels subprocess pour éviter l'injection de commandes.",
            details={
                "file_path": file_path,
                "line_number": line_number,
                "rule_id": rule_id,
                "patch": diff,
                "original": old_line,
                "replacement": new_line,
            },
        )

    # Secret hardcodé (Gitleaks / detect-secrets)
    if "gitleaks" in rule_lower or "secret" in rule_lower or "credential" in rule_lower:
        old_line = extrait.strip() if extrait else "API_KEY = \"secret_key_12345\""
        new_line = "# REMEDIATION: Extraire le secret vers une variable d'environnement\nimport os\nAPI_KEY = os.getenv(\"API_KEY\")"
        diff = _creer_unified_diff(file_path, line_number, old_line, new_line)
        return Remediation(
            type="code_patch",
            confidence="high",
            description="Externaliser le secret en dur vers des variables d'environnement.",
            details={
                "file_path": file_path,
                "line_number": line_number,
                "rule_id": rule_id,
                "patch": diff,
                "original": old_line,
                "replacement": new_line,
            },
        )

    return None


def _creer_unified_diff(
    file_path: str, line_number: int | None, old_code: str, new_code: str
) -> str:
    from_file = f"a/{file_path}"
    to_file = f"b/{file_path}"
    old_lines = old_code.splitlines(keepends=True)
    if not old_lines or not old_lines[-1].endswith("\n"):
        old_lines = [line + "\n" for line in old_code.splitlines()]
    new_lines = new_code.splitlines(keepends=True)
    if not new_lines or not new_lines[-1].endswith("\n"):
        new_lines = [line + "\n" for line in new_code.splitlines()]

    diff = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=from_file,
            tofile=to_file,
            n=1,
        )
    )
    return "".join(diff)


# ------------------------------------------------------------------ SCA Dependency Bump
def _generer_dependency_bump(
    package: str | None,
    file_path: str | None,
    version_installee: str | None,
    version_corrigee: str | None,
    evidence_remediation: str | None = None,
    rule_id: str | None = None,
) -> Remediation | None:
    """Génère une proposition de mise à jour de dépendance déterministe (SCA)."""
    target_version = version_corrigee
    if not target_version and evidence_remediation:
        # Tenter d'extraire la version depuis evidence_remediation (ex: "Upgrade to 5.4" ou "4.18.1")
        m = re.search(r"\b(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9_\-\.]+)?)\b", evidence_remediation)
        if m:
            target_version = m.group(1)

    if not package and not file_path:
        return None

    pkg_name = package or "paquet"
    target_ver = target_version or "version_sécurisée"
    f_path = file_path or "manifeste_dépendances"

    desc = f"Mettre à jour la dépendance `{pkg_name}` vers la version `{target_ver}` dans `{f_path}`."
    if version_installee:
        desc = f"Mettre à jour `{pkg_name}` de la version `{version_installee}` vers `{target_ver}` dans `{f_path}`."

    details: dict[str, Any] = {
        "package_name": pkg_name,
        "current_version": version_installee,
        "target_version": target_ver,
        "file_path": f_path,
        "suggested_change": f"{pkg_name}>={target_ver}" if target_version else f"Mise à jour requise pour {pkg_name}",
    }

    confidence = "high" if target_version else "medium"

    return Remediation(
        type="dependency_bump",
        confidence=confidence,
        description=desc,
        details=details,
    )


# ------------------------------------------------------------------ IaC / Config Fixes
def _generer_config_fix(
    file_path: str,
    line_number: int | None,
    rule_id: str,
    message: str = "",
) -> Remediation | None:
    """Génère des suggestions de correction IaC / Dockerfile déterministes."""
    rule_upper = (rule_id or "").upper()
    rule_lower = (rule_id or "").lower()

    # Hadolint DL3002 : Last user should not be root
    if "dl3002" in rule_lower or ("dockerfile" in file_path.lower() and "user" in rule_lower):
        return Remediation(
            type="config_fix",
            confidence="high",
            description="Ajouter une instruction USER non-root (ex: `USER appuser` ou `USER 10001`) avant l'instruction CMD / ENTRYPOINT dans le Dockerfile.",
            details={
                "file_path": file_path,
                "line_number": line_number,
                "rule_id": rule_id,
                "suggested_directive": "USER 10001",
            },
        )

    # Hadolint DL3006 : Always tag the version of an image
    if "dl3006" in rule_lower or ("dockerfile" in file_path.lower() and "tag" in rule_lower):
        return Remediation(
            type="config_fix",
            confidence="high",
            description="Épingler une version spécifique de l'image de base (ex: `FROM python:3.12-slim`) au lieu d'utiliser `latest` ou un tag implicite.",
            details={
                "file_path": file_path,
                "line_number": line_number,
                "rule_id": rule_id,
                "suggested_directive": "FROM <image>:<tag_spécifique>",
            },
        )

    # Checkov / KICS : IaC Terraform / K8s
    if "ckv" in rule_lower or "kics" in rule_lower or file_path.endswith((".tf", ".yaml", ".yml")):
        return Remediation(
            type="config_fix",
            confidence="medium",
            description=f"Corriger la directive d'infrastructure dans `{file_path}` conformément à la règle `{rule_id}`.",
            details={
                "file_path": file_path,
                "line_number": line_number,
                "rule_id": rule_id,
                "guidance": message or "Vérifier et durcir les paramètres d'accès et d'chiffrement.",
            },
        )

    return None


# ------------------------------------------------------------------ Public API
def generer_remediation_finding(finding: Finding | dict, target_dir: str | Path | None = None) -> Remediation | None:
    """Génère une proposition déterministe de remédiation pour un finding donné."""
    d = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding or {})
    src = d.get("source") or {}
    loc = d.get("location") or {}
    ev = d.get("evidence") or {}

    tool = (src.get("tool") or "").lower()
    rule_id = src.get("original_rule_id") or src.get("canonical_rule_id") or ""
    pkg = loc.get("package") or src.get("package")
    file_path = loc.get("file") or ""
    line = loc.get("line")

    version_installee = src.get("version_installee")
    version_corrigee = src.get("version_corrigee")
    evidence_remed = ev.get("remediation")
    msg = ev.get("message") or ev.get("titre") or ""
    extrait = ev.get("extrait") or ""

    # 1. SCA / Dépendances (Trivy, Grype, npm audit, pip-audit)
    if tool in ("trivy", "grype", "npm_audit", "pip_audit") or pkg or version_corrigee or "cve-" in str(rule_id).lower() or "ghsa-" in str(rule_id).lower():
        rem = _generer_dependency_bump(
            package=pkg,
            file_path=file_path,
            version_installee=version_installee,
            version_corrigee=version_corrigee,
            evidence_remediation=evidence_remed,
            rule_id=rule_id,
        )
        if rem:
            return rem

    # 2. Code patches (Semgrep, Gitleaks, detect-secrets)
    rem_code = _generer_code_patch(
        file_path=file_path,
        line_number=line,
        rule_id=rule_id,
        evidence_message=msg,
        extrait=extrait,
        target_dir=target_dir,
    )
    if rem_code:
        return rem_code

    # 3. Config fixes (Hadolint, Checkov, KICS, Shellcheck)
    if tool in ("hadolint", "checkov", "kics", "shellcheck") or file_path.endswith((".tf", ".yaml", ".yml", "Dockerfile", ".sh")):
        rem_cfg = _generer_config_fix(
            file_path=file_path,
            line_number=line,
            rule_id=rule_id,
            message=msg,
        )
        if rem_cfg:
            return rem_cfg

    # Repli déterministe générique si aucune règle spécifique n'a matché
    if file_path or pkg:
        return Remediation(
            type="config_fix" if (file_path.endswith((".tf", ".yaml", ".yml", "Dockerfile")) or not pkg) else "dependency_bump",
            confidence="low",
            description=f"Recommandation générale pour `{rule_id}` sur `{file_path or pkg}`.",
            details={
                "file_path": file_path,
                "rule_id": rule_id,
                "message": msg[:200] if msg else "Se référer aux guides de sécurité associés.",
            },
        )

    return None


def generer_remediations(findings: list[Finding | dict], clusters: list[dict] | None = None, target_dir: str | Path | None = None) -> dict[str, Any]:
    """Génère un dictionnaire associant les suggestions de remédiations aux findings et clusters."""
    remediations_findings: dict[str, dict] = {}
    for f in findings:
        f_obj = f if isinstance(f, Finding) else None
        f_id = f_obj.id if f_obj else f.get("id")
        if not f_id:
            continue
        rem = generer_remediation_finding(f, target_dir=target_dir)
        if rem:
            rem_dict = rem.to_dict()
            remediations_findings[f_id] = rem_dict
            if f_obj:
                f_obj.remediation = rem

    remediations_clusters: dict[str, dict] = {}
    if clusters:
        for cl in clusters:
            cl_id = cl.get("cluster_id")
            members = cl.get("members") or []
            if not cl_id or not members:
                continue

            # Trouver les remédiations des membres
            rems_membres = [remediations_findings[m] for m in members if m in remediations_findings]
            if rems_membres:
                # Retenir la remédiation avec la plus forte confiance ou la première disponible
                meilleure = max(rems_membres, key=lambda r: {"high": 3, "medium": 2, "low": 1}.get(r.get("confidence"), 0))
                remediations_clusters[cl_id] = meilleure
                cl["remediation"] = meilleure

    return {
        "findings": remediations_findings,
        "clusters": remediations_clusters,
    }
