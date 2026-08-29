module example.com/vulngo

go 1.21

// Dépendance volontairement vulnérable : x/text < 0.3.7 → CVE-2022-32149.
// Trivy (go.mod) doit la signaler : c'est l'occasion de convergence gosec/trivy
// mesurée par le chantier largeur-Go (2026-08-29).
require golang.org/x/text v0.3.0
