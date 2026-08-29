# testrepo_iac — fixture IaC pour le provider checkov

Cible de test de la capacité `IAC_SCAN`. Tout y est **volontairement non conforme** :
bucket S3 public, volume EBS non chiffré, security group ouvert sur `0.0.0.0/0`,
pod Kubernetes privilégié, Dockerfile non épinglé.

- `ATTENDUS.yaml` : identifiants de checks attendus, **extraits d'une exécution réelle**
  de checkov (pas écrits à la main — règle du projet : le mapping s'extrait).
- La variable `mot_de_passe_admin` de `main.tf` contient un **faux secret** : sa valeur
  ne doit jamais apparaître dans une sortie, un finding ou un rapport (leçon #1).
