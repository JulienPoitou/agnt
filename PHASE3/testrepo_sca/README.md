# testrepo_sca — fixture de qualification SCA (étape 4)

Copie des manifestes de dépendances de testrepo (package-lock.json,
requirements.txt) — les CVE qu'ils portent sont connues des campagnes
précédentes. Sert à qualifier grype (2e provider DEPENDENCY_ANALYSIS) et à
mesurer la convergence grype × trivy sur les MÊMES vulnérabilités.
