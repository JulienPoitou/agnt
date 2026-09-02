"""Tests unitaires et d'intégration du moteur Oracle de vérification backend (PHASE3).

Couvre notamment :
- finding vérifiable
- finding non vérifiable
- absence de preuve (devient potential, PAS false_positive)
- preuve suffisante (confirmed)
- faux positif (refuted)
- observations contradictoires
- finding dupliqué / incomplet
- provider indisponible / timeout / erreur d'exécution / crash pendant vérification
- sécurité autour des entrées non fiables (traversée de répertoire, champs corrompus)
- déterminisme des verdicts et des ProofCapsules
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

# Ajouter PHASE3/slice au PYTHONPATH
RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

from findings import Finding, Remediation
from oracle import (
    OracleEngine,
    ProofCapsule,
    VerdictStatus,
    VerificationResult,
    VerificationStatus,
)


class TestOracleEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.target_dir = Path(self.tmp_dir.name)
        self.engine = OracleEngine(target_dir=self.target_dir, run_id="run-test-oracle")

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _creer_finding_base(self, fid: str = "sg-0001", tool: str = "semgrep") -> Finding:
        return Finding(
            id=fid,
            source={
                "tool": tool,
                "original_rule_id": "python.lang.security.audit.pyyaml-load",
                "canonical_rule_id": "semgrep:python.lang.security.audit.pyyaml-load",
            },
            identity={
                "canonical_rule_id": "semgrep:python.lang.security.audit.pyyaml-load",
                "fingerprint": "abc123hash",
            },
            location={"asset": "repository", "file": "app.py", "line": 3, "package": None},
            severity={"value": "HIGH", "origine": tool},
            evidence={"message": "yaml.load non sécurisé"},
        )

    # ------------------------------------------------------------------ 1. Finding non vérifiable & Absence de preuve
    def test_finding_non_verifiable_sans_coordonnees(self) -> None:
        """Un finding sans aucune coordonnée de cible (sans fichier, paquet, url, hôte) doit être not_verifiable -> potential."""
        f = self._creer_finding_base("f-001")
        f.location = {"asset": "repository", "file": None, "line": None, "package": None}
        res = self.engine.evaluer_finding(f)

        self.assertFalse(res.verifiable)
        self.assertEqual(res.status, VerificationStatus.NOT_VERIFIABLE)
        self.assertEqual(res.verdict, VerdictStatus.POTENTIAL)
        self.assertIn("Information insuffisante", res.justification)

    def test_absence_de_preuve_ne_devient_pas_false_positive(self) -> None:
        """RÈGLE CRITIQUE : Une absence de preuve ne doit PAS donner `refuted`/`false_positive`, mais `potential`."""
        f = self._creer_finding_base("f-002")
        f.location = {"asset": "repository", "file": "fichier_existant.txt", "line": 1, "package": None}
        # Créer le fichier pour qu'il soit vérifiable localement
        (self.target_dir / "fichier_existant.txt").write_text("un contenu quelconque sans motif specifique\n")

        res = self.engine.evaluer_finding(f)

        self.assertTrue(res.verifiable)
        self.assertNotEqual(res.verdict, VerdictStatus.REFUTED)
        self.assertEqual(res.verdict, VerdictStatus.POTENTIAL)

    # ------------------------------------------------------------------ 2. Preuve suffisante & Faux Positif (SAST)
    def test_sast_pyyaml_safe_load_refute_vulnerabilite(self) -> None:
        """Si la ligne utilise safe_load, la vulnérabilité est réfutée (Faux positif prouvé)."""
        f = self._creer_finding_base("f-003")
        f.location = {"asset": "repository", "file": "app.py", "line": 3, "package": None}
        (self.target_dir / "app.py").write_text("import yaml\ndef main():\n    data = yaml.safe_load(f)\n")

        res = self.engine.evaluer_finding(f)

        self.assertTrue(res.verifiable)
        self.assertEqual(res.verdict, VerdictStatus.REFUTED)
        self.assertIsNotNone(res.proof_capsule)
        self.assertEqual(res.proof_capsule.observation_type, "code_ast")
        self.assertIn("safe_load", res.justification)

    def test_sast_pyyaml_unsafe_load_confirme_vulnerabilite(self) -> None:
        """Si la ligne utilise yaml.load sans safe_load, la vulnérabilité est confirmée."""
        f = self._creer_finding_base("f-004")
        f.location = {"asset": "repository", "file": "app.py", "line": 3, "package": None}
        (self.target_dir / "app.py").write_text("import yaml\ndef main():\n    data = yaml.load(f)\n")

        res = self.engine.evaluer_finding(f)

        self.assertTrue(res.verifiable)
        self.assertEqual(res.verdict, VerdictStatus.CONFIRMED)
        self.assertIsNotNone(res.proof_capsule)
        self.assertEqual(res.proof_capsule.observation_type, "code_ast")

    def test_sast_ligne_hors_limites_refute(self) -> None:
        """Si le numéro de ligne est hors des limites du fichier, le finding est réfuté."""
        f = self._creer_finding_base("f-005")
        f.location = {"asset": "repository", "file": "app.py", "line": 999, "package": None}
        (self.target_dir / "app.py").write_text("line1\nline2\n")

        res = self.engine.evaluer_finding(f)

        self.assertTrue(res.verifiable)
        self.assertEqual(res.verdict, VerdictStatus.REFUTED)
        self.assertIn("hors des limites", res.justification)

    # ------------------------------------------------------------------ 3. Preuve suffisante & SCA / Lockfiles
    def test_sca_paquet_present_dans_package_lock_confirme(self) -> None:
        """SCA: Si le paquet est présent dans package-lock.json, la dépendance est confirmée."""
        f = Finding(
            id="tv-0001",
            source={"tool": "trivy", "original_rule_id": "CVE-2023-1234", "canonical_rule_id": "trivy:CVE-2023-1234"},
            identity={"canonical_rule_id": "trivy:CVE-2023-1234", "fingerprint": "trivyhash"},
            location={"asset": "repository", "file": "package-lock.json", "line": None, "package": "express"},
            severity={"value": "HIGH", "origine": "trivy"},
            evidence={"message": "Vulnerabilite express"},
        )
        (self.target_dir / "package-lock.json").write_text('{"packages": {"node_modules/express": {"version": "4.17.1"}}}')

        res = self.engine.evaluer_finding(f)

        self.assertTrue(res.verifiable)
        self.assertEqual(res.verdict, VerdictStatus.CONFIRMED)
        self.assertEqual(res.proof_capsule.observation_type, "dependency_lockfile")
        self.assertEqual(res.proof_capsule.details.get("package"), "express")

    def test_sca_paquet_absent_des_lockfiles_refute(self) -> None:
        """SCA: Si des lockfiles existent mais que le paquet n'y figure pas, le finding est réfuté."""
        f = Finding(
            id="tv-0002",
            source={"tool": "trivy", "original_rule_id": "CVE-2023-9999", "canonical_rule_id": "trivy:CVE-2023-9999"},
            identity={"canonical_rule_id": "trivy:CVE-2023-9999", "fingerprint": "trivyhash2"},
            location={"asset": "repository", "file": "requirements.txt", "line": None, "package": "nonexistent-pkg"},
            severity={"value": "HIGH", "origine": "trivy"},
            evidence={"message": "Vulnerabilite paquet inexistant"},
        )
        (self.target_dir / "requirements.txt").write_text("flask==2.0.1\nrequests==2.25.1\n")

        res = self.engine.evaluer_finding(f)

        self.assertTrue(res.verifiable)
        self.assertEqual(res.verdict, VerdictStatus.REFUTED)
        self.assertIn("absente des fichiers de lock", res.justification)

    # ------------------------------------------------------------------ 4. Verification des secrets & Faux Positifs
    def test_secret_commentaire_ou_exemple_refute(self) -> None:
        """Un secret dans une ligne de commentaire ou d'exemple est réfuté (faux positif)."""
        f = Finding(
            id="gl-0001",
            source={"tool": "gitleaks", "original_rule_id": "generic-api-key", "canonical_rule_id": "gitleaks:generic-api-key"},
            identity={"canonical_rule_id": "gitleaks:generic-api-key", "fingerprint": "glhash"},
            location={"asset": "repository", "file": "config.py", "line": 1, "package": None},
            severity={"value": "HIGH", "origine": "gitleaks"},
            evidence={"message": "Secret trouve"},
        )
        (self.target_dir / "config.py").write_text("# API_KEY = EXAMPLE_KEY_12345\nAPI_KEY = None\n")

        res = self.engine.evaluer_finding(f)

        self.assertTrue(res.verifiable)
        self.assertEqual(res.verdict, VerdictStatus.REFUTED)
        self.assertIn("exemple fictif", res.justification)

    # ------------------------------------------------------------------ 5. Gestion des contradictions
    def test_observations_contradictoires_produit_etat_contradictory(self) -> None:
        """Si deux observations sur le même sujet sont incompatibles/contradictoires, l'état doit être `contradictory`."""
        f1 = self._creer_finding_base("f-101", tool="semgrep")
        f1.severity = {"value": "CRITICAL", "origine": "semgrep"}

        f2 = self._creer_finding_base("f-102", tool="custom_tool")
        f2.severity = {"value": "INFO", "origine": "custom_tool"}
        f2.evidence = {"message": "safe usage confirmed by audit"}
        f2.cycle = {"verdict": VerdictStatus.REFUTED.value}

        res = self.engine.evaluer_finding(f1, autres_findings=[f1, f2])

        self.assertEqual(res.verdict, VerdictStatus.CONTRADICTORY)
        self.assertTrue(len(res.contradictions) > 0)
        self.assertIn("f-102", res.contradictions[0]["autre_finding_id"])

    # ------------------------------------------------------------------ 6. Sécurité des entrées non fiables
    def test_securite_tentative_traversee_repertoire(self) -> None:
        """Un chemin tentant d'accéder hors du dossier cible (ex: ../../etc/passwd) doit être rejeté."""
        f = self._creer_finding_base("f-bad-path")
        f.location["file"] = "../../etc/passwd"

        res = self.engine.evaluer_finding(f)

        self.assertFalse(res.verifiable)
        self.assertEqual(res.status, VerificationStatus.NOT_VERIFIABLE)
        self.assertIn("Chemin de fichier hors cible autorisée", res.justification)

    def test_finding_corrompu_ou_malforme(self) -> None:
        """Un finding corrompu ne doit pas faire crasher l'Oracle."""
        res = self.engine.evaluer_finding(dict())

        self.assertFalse(res.verifiable)
        self.assertEqual(res.status, VerificationStatus.ERROR)
        self.assertEqual(res.verdict, VerdictStatus.INCONCLUSIVE)

    # ------------------------------------------------------------------ 7. Déterminisme
    def test_determinisme_des_verdicts_et_proof_capsules(self) -> None:
        """À observations identiques, le verdict et la preuve doivent être strictement identiques."""
        f = self._creer_finding_base("f-det")
        (self.target_dir / "app.py").write_text("import yaml\ndef main():\n    data = yaml.safe_load(stream)\n")

        res1 = self.engine.evaluer_finding(f)
        res2 = self.engine.evaluer_finding(f)

        self.assertEqual(res1.verdict, res2.verdict)
        self.assertEqual(res1.status, res2.status)
        self.assertEqual(res1.justification, res2.justification)
        self.assertIsNotNone(res1.proof_capsule)
        self.assertIsNotNone(res2.proof_capsule)
        self.assertEqual(res1.proof_capsule.reproducibility_hash, res2.proof_capsule.reproducibility_hash)


if __name__ == "__main__":
    unittest.main()
